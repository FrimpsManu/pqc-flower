"""Farm side (ClientApp): train on this farm's private crop data."""

from flwr.app import ArrayRecord, ConfigRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp

from pqcflower import signing, task

app = ClientApp()


def _farm_data(context: Context):
    return task.load_farm(
        int(context.node_config["partition-id"]),
        int(context.node_config["num-partitions"]),
        float(context.run_config["dirichlet-alpha"]),
    )


@app.train()
def train(msg: Message, context: Context) -> Message:
    (x, y), _ = _farm_data(context)
    model = msg.content["arrays"].to_numpy_ndarrays()
    model = task.train(
        model, x, y,
        epochs=int(context.run_config["local-epochs"]),
        lr=float(context.run_config["learning-rate"]),
    )
    loss, acc = task.evaluate(model, x, y)
    content = RecordDict({
        "arrays": ArrayRecord(model),
        "metrics": MetricRecord({"train_loss": loss, "train_acc": acc, "num-examples": len(y)}),
    })
    farm_id = int(context.node_config["partition-id"])
    auth = ConfigRecord({"farm-id": farm_id})
    if context.run_config["sign-updates"]:
        server_round = int(msg.content["config"]["server-round"])
        auth["signature"] = signing.sign_update(signing.load_private_key(farm_id), server_round, farm_id, model)
    content["auth"] = auth
    return Message(content=content, reply_to=msg)


@app.evaluate()
def evaluate(msg: Message, context: Context) -> Message:
    _, (x, y) = _farm_data(context)
    loss, acc = task.evaluate(msg.content["arrays"].to_numpy_ndarrays(), x, y)
    content = RecordDict({
        "metrics": MetricRecord({"eval_loss": loss, "eval_acc": acc, "num-examples": len(y)}),
    })
    return Message(content=content, reply_to=msg)
