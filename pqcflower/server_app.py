"""Server side (ServerApp): FedAvg across farms, plus accuracy on a held-out test set."""

import time
from collections.abc import Iterable

from flwr.app import ArrayRecord, Context, Message, MetricRecord
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg

from pqcflower import attack, signing, task

app = ServerApp()


class SignedFedAvg(FedAvg):
    """FedAvg that only aggregates updates carrying a valid ML-DSA signature from their farm."""

    def __init__(self, *, sign_updates: bool, attack_farm: int, num_farms: int, **kwargs):
        super().__init__(**kwargs)
        self.sign_updates = sign_updates
        self.attack_farm = attack_farm  # -1: no attack
        self.public_keys = signing.load_public_keys(num_farms) if sign_updates else {}

    def aggregate_train(self, server_round: int, replies: Iterable[Message]):
        accepted = []
        for msg in replies:
            if msg.has_error():
                accepted.append(msg)  # FedAvg logs and skips error replies itself
                continue
            farm_id = int(msg.content["auth"]["farm-id"])
            tampered = farm_id == self.attack_farm
            if tampered:
                attack.tamper(msg)
            if not self.sign_updates:
                note = "  <- TAMPERED, accepted (no signature check)" if tampered else ""
                print(f"[round {server_round:>2}] farm {farm_id}: accepted, unsigned{note}")
                accepted.append(msg)
                continue
            signature = msg.content["auth"].get("signature")
            valid = signature is not None and signing.verify_update(
                self.public_keys[farm_id], signature, server_round, farm_id,
                msg.content["arrays"].to_numpy_ndarrays(),
            )
            if valid:
                print(f"[round {server_round:>2}] farm {farm_id}: ML-DSA signature valid, accepted")
                accepted.append(msg)
            else:
                print(f"[round {server_round:>2}] farm {farm_id}: ML-DSA signature INVALID, REJECTED")
        return super().aggregate_train(server_round, accepted)


@app.main()
def main(grid: Grid, context: Context) -> None:
    num_farms = int(context.run_config["num-farms"])
    sign_updates = bool(context.run_config["sign-updates"])
    attack_farm = int(context.run_config["attack-farm"])
    x_test, y_test = task.load_test()
    round_start = {"t": time.perf_counter()}
    print(f"[setup] farms={num_farms} sign-updates={sign_updates} "
          f"attack={'tamper farm ' + str(attack_farm) if attack_farm >= 0 else 'none'}")

    def central_eval(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        loss, acc = task.evaluate(arrays.to_numpy_ndarrays(), x_test, y_test)
        now = time.perf_counter()
        elapsed, round_start["t"] = now - round_start["t"], now
        print(f"[round {server_round:>2}] test_acc={acc:.3f} test_loss={loss:.3f} round_time={elapsed:.2f}s")
        return MetricRecord({"test_acc": acc, "test_loss": loss, "round_time_s": elapsed})

    strategy = SignedFedAvg(
        sign_updates=sign_updates,
        attack_farm=attack_farm,
        num_farms=num_farms,
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
