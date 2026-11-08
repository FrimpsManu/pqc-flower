"""Farm side (ClientApp): train on this farm's private crop data."""

from flwr.app import ArrayRecord, ConfigRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp
from flwr.client.mod import secaggplus_mod
from flwr.common import Code, FitRes, Status, ndarrays_to_parameters, parameters_to_ndarrays
from flwr.common.secure_aggregation.secaggplus_constants import RECORD_KEY_CONFIGS
from flwr.compat.common import recorddict_compat as compat

from pqcflower import secagg_pq, signing, task


def secure_aggregation_mod(msg: Message, context: Context, call_next) -> Message:
    """Route SecAgg+ messages to Flower's mod ("ecdh") or the ML-KEM one ("mlkem")."""
    if RECORD_KEY_CONFIGS not in msg.content.config_records:
        return call_next(msg, context)
    mod = secagg_pq.pq_secaggplus_mod if context.run_config["secure-aggregation"] == "mlkem" else secaggplus_mod
    return mod(msg, context, call_next)


app = ClientApp(mods=[secure_aggregation_mod])


def _farm_data(context: Context):
    return task.load_farm(
        int(context.node_config["partition-id"]),
        int(context.node_config["num-partitions"]),
        float(context.run_config["dirichlet-alpha"]),
    )


def _train_legacy(msg: Message, context: Context) -> Message:
    """Training step inside SecAgg+, which still speaks Flower's legacy FitIns/FitRes format."""
    (x, y), _ = _farm_data(context)
    fitins = compat.recorddict_to_fitins(msg.content, keep_input=True)
    model = task.train(
        parameters_to_ndarrays(fitins.parameters), x, y,
        epochs=int(context.run_config["local-epochs"]),
        lr=float(context.run_config["learning-rate"]),
    )
    loss, acc = task.evaluate(model, x, y)
    fitres = FitRes(Status(Code.OK, ""), ndarrays_to_parameters(model), len(y), {"train_loss": loss, "train_acc": acc})
    return Message(content=compat.fitres_to_recorddict(fitres, keep_input=False), reply_to=msg)


@app.train()
def train(msg: Message, context: Context) -> Message:
    if "arrays" not in msg.content.array_records:
        return _train_legacy(msg, context)
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
        auth["signature"] = signing.sign_update(
            signing.load_private_key(farm_id), context.run_id, server_round, farm_id, model)
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
