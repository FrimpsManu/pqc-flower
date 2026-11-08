"""Secure aggregation (SecAgg+): Flower's ECDH version vs our ML-KEM-768 version.

Runs the real SecAgg+ server workflow and farm code (Flower's, and pqcflower/secagg_pq.py) in one
process: a stand-in Grid hands each server message straight to the farm's ClientApp. No network,
so this measures the protocol itself:

  1. Correctness: the aggregate equals the plain weighted average of the farms' updates, with all
     farms and with one farm dropping out after sharing its keys (its masks must be rebuilt).
  2. Cost per farm per round: bytes the farm sends and receives in SecAgg+ messages (keys,
     ciphertexts, shares, masked vector), and time per stage, for 3, 5, 10 and 20 farms.
  3. The mask seed space: Flower's pseudo_rand_gen keeps 32 bits of the seed; ours keeps all of it.

Usage: python benchmarks/secagg_costs.py   writes results/secagg_costs_<date>.txt/.json
"""

import copy
import datetime
import json
import os
import statistics
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("PQC_DATA_DIR", str(ROOT / "data"))

from flwr.app import ConfigRecord, Context, RecordDict  # noqa: E402
from flwr.common import ndarrays_to_parameters, parameters_to_ndarrays  # noqa: E402
from flwr.common.secure_aggregation.secaggplus_constants import RECORD_KEY_CONFIGS, Key  # noqa: E402
from flwr.common.secure_aggregation.secaggplus_utils import pseudo_rand_gen  # noqa: E402
from flwr.compat.common import recorddict_compat as compat  # noqa: E402
from flwr.server import LegacyContext, ServerConfig  # noqa: E402
from flwr.server.compat.grid_client_proxy import GridClientProxy  # noqa: E402
from flwr.server.strategy import FedAvg as LegacyFedAvg  # noqa: E402
from flwr.server.workflow import SecAggPlusWorkflow  # noqa: E402
from flwr.server.workflow.constant import MAIN_CONFIGS_RECORD, MAIN_PARAMS_RECORD  # noqa: E402
from flwr.server.workflow.constant import Key as WorkflowKey  # noqa: E402
from flwr.supercore.task_identity import TaskIdentity  # noqa: E402

from pqcflower import client_app, secagg_pq, task  # noqa: E402
from pqcflower.server_app import SECAGG_CLIPPING_RANGE  # noqa: E402

RUN_ID = 1
results: dict = {"date": datetime.date.today().isoformat()}
lines: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)
    lines.append(text)


def _bytes_in(record_dict: RecordDict) -> int:
    """Bytes of protocol payload in a message: every bytes value in its SecAgg+ config record."""
    total = 0
    for record in record_dict.config_records.values():
        for value in record.values():
            values = value if isinstance(value, list) else [value]
            total += sum(len(v) for v in values if isinstance(v, bytes))
    return total


class InProcessGrid:
    """Delivers each message to the farm's ClientApp directly and records sizes and times."""

    def __init__(self, contexts: dict[int, Context], drop_after_share_keys: set[int]):
        self.contexts = contexts
        self.drop = drop_after_share_keys
        self.current: int | None = None  # node being called, so its update can be recorded
        self.stats: dict[str, dict[str, list[float]]] = {}

    def send_and_receive(self, messages, timeout=None):
        replies = []
        for msg in messages:
            msg = copy.deepcopy(msg)  # over the network every farm gets its own copy
            stage = str(msg.content.config_records[RECORD_KEY_CONFIGS][Key.STAGE])
            if stage == "collect_masked_vectors" and msg.metadata.dst_node_id in self.drop:
                continue  # the farm went offline after sharing its keys
            received = _bytes_in(msg.content)
            self.current = msg.metadata.dst_node_id
            t = time.perf_counter()
            reply = client_app.app(msg, self.contexts[msg.metadata.dst_node_id])
            elapsed = time.perf_counter() - t
            sent = _bytes_in(reply.content) + sum(
                len(b) for record in reply.content.array_records.values() for b in record.values())
            s = self.stats.setdefault(stage, {"received": [], "sent": [], "seconds": []})
            s["received"].append(received)
            s["sent"].append(sent)
            s["seconds"].append(elapsed)
            replies.append(reply)
        return replies


def one_round(mode: str, num_farms: int, drop: set[int] = frozenset()):
    """One SecAgg+ round; returns (aggregate, {node: (update, num_examples)}, surviving nodes, grid)."""
    TaskIdentity.run_id, TaskIdentity.node_id, TaskIdentity.task_id = RUN_ID, 0, 1  # we act as the server
    node_ids = [1000 + i for i in range(num_farms)]
    run_config = {"secure-aggregation": mode, "dirichlet-alpha": 0.5, "local-epochs": 20,
                  "learning-rate": 1.0, "sign-updates": False}
    contexts = {nid: Context(run_id=RUN_ID, node_id=nid, node_config={"partition-id": i, "num-partitions": num_farms},
                             state=RecordDict(), run_config=run_config) for i, nid in enumerate(node_ids)}
    grid = InProcessGrid(contexts, {node_ids[i] for i in drop})

    # Record each farm's real update so the expected average can be computed.
    updates: dict[int, tuple[list[np.ndarray], int]] = {}
    real_train = task.train

    def recording_train(model, x, y, **kw):
        out = real_train(model, x, y, **kw)
        updates[grid.current] = (out, len(y))
        return out

    task.train = recording_train
    try:
        strategy = LegacyFedAvg(fraction_fit=1.0, fraction_evaluate=0.0, min_fit_clients=num_farms,
                                min_available_clients=num_farms,
                                fit_metrics_aggregation_fn=lambda _: {})
        server_ctx = Context(run_id=RUN_ID, node_id=0, node_config={}, state=RecordDict(), run_config={})
        legacy = LegacyContext(context=server_ctx, config=ServerConfig(num_rounds=1), strategy=strategy)
        for nid in node_ids:
            legacy.client_manager.register(GridClientProxy(nid, grid, RUN_ID))
        legacy.state.config_records[MAIN_CONFIGS_RECORD] = ConfigRecord({WorkflowKey.CURRENT_ROUND: 1})
        legacy.state.array_records[MAIN_PARAMS_RECORD] = compat.parameters_to_arrayrecord(
            ndarrays_to_parameters(task.init_model()), True)
        workflow = secagg_pq.MLKEMSecAggPlusWorkflow if mode == "mlkem" else SecAggPlusWorkflow
        workflow(num_shares=1.0, reconstruction_threshold=0.67, clipping_range=SECAGG_CLIPPING_RANGE)(grid, legacy)
    finally:
        task.train = real_train

    aggregate = parameters_to_ndarrays(compat.arrayrecord_to_parameters(legacy.state.array_records[MAIN_PARAMS_RECORD],
                                                                        keep_input=True))
    survivors = set(node_ids) - grid.drop
    return aggregate, updates, survivors, grid


def check_correctness() -> None:
    say("1. Correctness: SecAgg+ aggregate vs plain weighted average (max absolute difference)")
    results["correctness"] = {}
    for mode in ("ecdh", "mlkem"):
        for drop in (set(), {1}):
            aggregate, updates, survivors, _ = one_round(mode, 5, drop)
            # A farm that dropped out never sent its masked update, so it is not in the average.
            kept = [updates[nid] for nid in survivors]
            total = sum(n for _, n in kept)
            expected = [sum(n * u[i] for u, n in kept) / total for i in range(len(aggregate))]
            best = max(float(np.abs(a - e).max()) for a, e in zip(aggregate, expected))
            label = f"{mode}, 5 farms, " + ("all present" if not drop else "1 farm drops after sharing keys")
            results["correctness"][label] = best
            say(f"   {label:<48} {best:.2e}  {'OK' if best < 1e-3 else 'MISMATCH'}")
    say()


def bench_costs(farm_counts=(3, 5, 10, 20)) -> None:
    say("2. Cost per farm per round (one in-process round; bytes of SecAgg+ payload, median farm)")
    say(f"   {'farms':>5}  {'mode':<6}{'sent KB':>9}{'received KB':>13}{'setup ms':>10}{'share keys ms':>15}"
        f"{'unmask ms':>11}")
    results["costs"] = {}
    for n in farm_counts:
        for mode in ("ecdh", "mlkem"):
            _, _, _, grid = one_round(mode, n)
            per_farm_sent = sum(statistics.median(s["sent"]) for s in grid.stats.values())
            per_farm_recv = sum(statistics.median(s["received"]) for s in grid.stats.values())
            ms = {stage: 1000 * statistics.median(s["seconds"]) for stage, s in grid.stats.items()}
            # The masked vector is the same size in both modes; report it separately.
            masked = statistics.median(grid.stats["collect_masked_vectors"]["sent"])
            r = {"sent_KB": per_farm_sent / 1024, "received_KB": per_farm_recv / 1024,
                 "masked_vector_KB": masked / 1024, "ms": ms}
            results["costs"][f"{mode}/{n}"] = r
            say(f"   {n:>5}  {mode:<6}{r['sent_KB']:>9.1f}{r['received_KB']:>13.1f}{ms['setup']:>10.1f}"
                f"{ms['share_keys']:>15.1f}{ms['unmask']:>11.1f}")
    say("   (sent includes the masked model update, the same size in both modes)")
    say()


def seed_space() -> None:
    say("3. Mask seed space")
    a, b = os.urandom(32), bytearray(os.urandom(32))
    # Flip bits that cancel in Flower's XOR-fold: two different seeds, the same 32-bit PRG seed.
    b[:] = a
    b[0] ^= 0xFF
    b[4] ^= 0xFF
    dims = [(7, 22)]
    flower_same = np.array_equal(pseudo_rand_gen(a, 2**32, dims)[0], pseudo_rand_gen(bytes(b), 2**32, dims)[0])
    ours_same = np.array_equal(secagg_pq.prg(a, 2**32, dims)[0], secagg_pq.prg(bytes(b), 2**32, dims)[0])
    results["seed_space"] = {"flower_bits": 32, "flower_collision": flower_same, "ours_collision": ours_same}
    say("   Flower pseudo_rand_gen: XOR-folds the 32-byte seed to 32 bits -> 2^32 possible masks")
    say(f"   two different seeds, same Flower mask: {flower_same};  same mask with prg(): {ours_same}")
    say()


def main() -> None:
    say(f"SecAgg+ benchmark: ECDH (Flower) vs ML-KEM-768 (ours), {results['date']} "
        f"({os.uname().machine}, Python {sys.version.split()[0]})")
    say()
    check_correctness()
    bench_costs()
    seed_space()
    out = ROOT / "results" / f"secagg_costs_{results['date']}"
    out.with_suffix(".txt").write_text("\n".join(lines) + "\n")
    out.with_suffix(".json").write_text(json.dumps(results, indent=2, default=str) + "\n")
    print(f"saved {out}.txt / .json")


if __name__ == "__main__":
    main()
