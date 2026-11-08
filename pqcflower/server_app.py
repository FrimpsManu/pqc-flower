"""Server side (ServerApp): FedAvg across farms, plus accuracy on a held-out test set.

With secure-aggregation = "ecdh" or "mlkem" the round runs Flower's SecAgg+ workflow instead, so the
server only ever sees the sum of the farms' updates: "ecdh" is Flower's own SecAgg+, "mlkem" our
post-quantum version (pqcflower/secagg_pq.py). SecAgg+ needs Flower's legacy strategy API.
"""

import time
from collections.abc import Iterable

from flwr.app import ArrayRecord, Context, Message, MetricRecord
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg

from pqcflower import attack, secagg_pq, signing, task

# SecAgg+ quantizes updates into [-CLIP, CLIP]; our weights reach about 15 after 15 rounds.
SECAGG_CLIPPING_RANGE = 64.0

app = ServerApp()


class SignedFedAvg(FedAvg):
    """FedAvg that only aggregates updates carrying a valid ML-DSA signature from their farm."""

    def __init__(self, *, sign_updates: bool, attack_farm: int, replay_farm: int, num_farms: int, run_id: int,
                 **kwargs):
        super().__init__(**kwargs)
        self.sign_updates = sign_updates
        self.attack_farm = attack_farm  # -1: no attack
        self.replay_farm = replay_farm  # -1: no attack
        self.run_id = run_id
        self.public_keys = signing.load_public_keys(num_farms) if sign_updates else {}

    def aggregate_train(self, server_round: int, replies: Iterable[Message]):
        accepted = []
        for msg in replies:
            if msg.has_error():
                accepted.append(msg)  # FedAvg logs and skips error replies itself
                continue
            farm_id = int(msg.content["auth"]["farm-id"])
            note = ""
            if farm_id == self.attack_farm:
                attack.tamper(msg)
                note = "  <- TAMPERED"
            if farm_id == self.replay_farm:
                source = attack.replay(msg, farm_id, server_round, self.run_id)
                note = f"  <- REPLAYED update {source}" if source else ""
            if not self.sign_updates:
                note = f"{note}, accepted (no signature check)" if note else ""
                print(f"[round {server_round:>2}] farm {farm_id}: accepted, unsigned{note}")
                accepted.append(msg)
                continue
            signature = msg.content["auth"].get("signature")
            valid = signature is not None and signing.verify_update(
                self.public_keys[farm_id], signature, self.run_id, server_round, farm_id,
                msg.content["arrays"].to_numpy_ndarrays(),
            )
            if valid:
                print(f"[round {server_round:>2}] farm {farm_id}: ML-DSA signature valid, accepted{note}")
                accepted.append(msg)
            else:
                print(f"[round {server_round:>2}] farm {farm_id}: ML-DSA signature INVALID, REJECTED{note}")
        return super().aggregate_train(server_round, accepted)


def run_secure_aggregation(grid: Grid, context: Context, mode: str, num_farms: int, x_test, y_test) -> None:
    """FedAvg where the server only learns the sum of the updates (SecAgg+, ECDH or ML-KEM)."""
    from flwr.common import ndarrays_to_parameters
    from flwr.server import LegacyContext, ServerConfig
    from flwr.server.strategy import FedAvg as LegacyFedAvg
    from flwr.server.workflow import DefaultWorkflow, SecAggPlusWorkflow

    round_start = {"t": time.perf_counter()}

    def central_eval(server_round, ndarrays, _config):
        loss, acc = task.evaluate(ndarrays, x_test, y_test)
        now = time.perf_counter()
        elapsed, round_start["t"] = now - round_start["t"], now
        if server_round > 0:
            print(f"[round {server_round:>2}] secure aggregation ({mode}): server saw only the sum "
                  f"of {num_farms} masked updates")
        print(f"[round {server_round:>2}] test_acc={acc:.3f} test_loss={loss:.3f} round_time={elapsed:.2f}s")
        return loss, {"test_acc": acc}

    strategy = LegacyFedAvg(
        fraction_fit=1.0, fraction_evaluate=0.0,  # all farms train; evaluation is central
        min_fit_clients=num_farms, min_available_clients=num_farms,
        initial_parameters=ndarrays_to_parameters(task.init_model()),
        evaluate_fn=central_eval,
        fit_metrics_aggregation_fn=lambda _: {},
    )
    legacy = LegacyContext(context=context, config=ServerConfig(
        num_rounds=int(context.run_config["num-server-rounds"])), strategy=strategy)
    workflow = secagg_pq.MLKEMSecAggPlusWorkflow if mode == "mlkem" else SecAggPlusWorkflow
    # Every farm shares its secrets with all others; any 2/3 of them can rebuild a dropped farm's masks.
    fit = workflow(num_shares=1.0, reconstruction_threshold=0.67, clipping_range=SECAGG_CLIPPING_RANGE)
    DefaultWorkflow(fit_workflow=fit)(grid, legacy)
    print("PQCFLOWER_DONE")


@app.main()
def main(grid: Grid, context: Context) -> None:
    num_farms = int(context.run_config["num-farms"])
    sign_updates = bool(context.run_config["sign-updates"])
    attack_farm = int(context.run_config["attack-farm"])
    replay_farm = int(context.run_config["replay-farm"])
    x_test, y_test = task.load_test()
    round_start = {"t": time.perf_counter()}
    attacks = ([f"tamper farm {attack_farm}"] if attack_farm >= 0 else []) \
        + ([f"replay farm {replay_farm}"] if replay_farm >= 0 else [])
    secure_aggregation = str(context.run_config["secure-aggregation"])
    print(f"[setup] run={context.run_id} farms={num_farms} sign-updates={sign_updates} "
          f"attack={', '.join(attacks) or 'none'} secure-aggregation={secure_aggregation}")
    if secure_aggregation in ("ecdh", "mlkem"):
        if sign_updates or attacks:
            print("[setup] note: with secure aggregation the server never sees single updates, "
                  "so update signatures and the update attacks are off")
        run_secure_aggregation(grid, context, secure_aggregation, num_farms, x_test, y_test)
        return

    def central_eval(server_round: int, arrays: ArrayRecord) -> MetricRecord:
        loss, acc = task.evaluate(arrays.to_numpy_ndarrays(), x_test, y_test)
        now = time.perf_counter()
        elapsed, round_start["t"] = now - round_start["t"], now
        print(f"[round {server_round:>2}] test_acc={acc:.3f} test_loss={loss:.3f} round_time={elapsed:.2f}s")
        return MetricRecord({"test_acc": acc, "test_loss": loss, "round_time_s": elapsed})

    strategy = SignedFedAvg(
        sign_updates=sign_updates,
        attack_farm=attack_farm,
        replay_farm=replay_farm,
        num_farms=num_farms,
        run_id=context.run_id,
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
