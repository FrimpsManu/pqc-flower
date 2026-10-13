"""Server side (ServerApp): FedAvg across farms, plus accuracy on a held-out test set."""

import time

from flwr.app import ArrayRecord, Context, MetricRecord
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg

from pqcflower import task

app = ServerApp()


@app.main()
def main(grid: Grid, context: Context) -> None:
    num_farms = int(context.run_config["num-farms"])
    x_test, y_test = task.load_test()
    round_start = {"t": time.perf_counter()}

    def central_eval(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        loss, acc = task.evaluate(arrays.to_numpy_ndarrays(), x_test, y_test)
        now = time.perf_counter()
        elapsed, round_start["t"] = now - round_start["t"], now
        print(f"[round {server_round:>2}] test_acc={acc:.3f} test_loss={loss:.3f} round_time={elapsed:.2f}s")
        return MetricRecord({"test_acc": acc, "test_loss": loss, "round_time_s": elapsed})

    strategy = FedAvg(
        min_train_nodes=num_farms,
        min_evaluate_nodes=num_farms,
        min_available_nodes=num_farms,
    )
    result = strategy.start(
        grid=grid,
        initial_arrays=ArrayRecord(task.init_model()),
        num_rounds=int(context.run_config["num-server-rounds"]),
        evaluate_fn=central_eval,
    )
    print(result)
    print("PQCFLOWER_DONE")
