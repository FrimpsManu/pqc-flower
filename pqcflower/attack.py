"""Simulated attackers for the demos. Not part of the system being protected.

Attack 1 (tampered model update): an attacker on the path between a farm and the server alters
that farm's update before it reaches aggregation. Real-world equivalents are a compromised relay
or proxy, or TLS broken by a future quantum computer. We model it as a hook that runs on the
server just before the update is checked and aggregated.

Attack 3 (replayed model update): the same attacker records a farm's genuine signed update and sends
it again later, in a later round or a later training run. The signature is real, so only what it
covers (run id and round, see signing.py) can expose the replay.
"""

import os
from pathlib import Path

import numpy as np

from flwr.app import ArrayRecord, Message


def tamper(msg: Message, scale: float = -5.0) -> None:
    """Poison the update in place: flip and amplify the weights (a model-poisoning attack).

    The attacker cannot re-sign the altered update without the farm's private key.
    """
    poisoned = [scale * a for a in msg.content["arrays"].to_numpy_ndarrays()]
    msg.content["arrays"] = ArrayRecord([np.ascontiguousarray(a) for a in poisoned])


# --- Attack 3: replayed model update ----------------------------------------------------------------
# The attacker records a farm's signed updates as they pass and later sends one again, unchanged and
# with its genuine signature. Recordings outlive the run (files), so a later run can be targeted too.
CAPTURE_DIR = Path(os.environ.get("PQC_CAPTURE_DIR", Path(__file__).resolve().parent.parent / "logs" / "captured"))


def _capture_path(farm_id: int, server_round: int) -> Path:
    return CAPTURE_DIR / f"farm{farm_id}_round{server_round}.npz"


def _load_capture(farm_id: int, server_round: int):
    path = _capture_path(farm_id, server_round)
    if not path.exists():
        return None
    data = np.load(path)
    n = int(data["num_arrays"])
    return int(data["run_id"]), [data[f"a{i}"] for i in range(n)], data["signature"].tobytes()


def replay(msg: Message, farm_id: int, server_round: int, run_id: int) -> str | None:
    """Swap the farm's update for one recorded earlier; return where it came from (None: nothing yet).

    Prefers a recording of the same round from an earlier run, where the round number matches and
    only the run id tells it apart; otherwise this farm's update from the previous round.
    """
    arrays = msg.content["arrays"].to_numpy_ndarrays()
    signature = msg.content["auth"].get("signature") or b""
    captured = _load_capture(farm_id, server_round)
    source = None
    if captured and captured[0] != run_id:
        source = f"recorded in an earlier run (run {captured[0]}), same round"
    else:
        captured = _load_capture(farm_id, server_round - 1)
        if captured:
            source = f"recorded in round {server_round - 1}"

    # Record the genuine update for later replays.
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    np.savez(_capture_path(farm_id, server_round), run_id=run_id, num_arrays=len(arrays),
             signature=np.frombuffer(signature, dtype=np.uint8), **{f"a{i}": a for i, a in enumerate(arrays)})

    if source:
        _, old_arrays, old_signature = captured
        msg.content["arrays"] = ArrayRecord([np.ascontiguousarray(a) for a in old_arrays])
        if old_signature:
            msg.content["auth"]["signature"] = old_signature
    return source
