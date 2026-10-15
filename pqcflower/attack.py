"""Simulated attacker for the demos. Not part of the system being protected.

Attack 1 (tampered model update): an attacker on the path between a farm and the server alters
that farm's update before it reaches aggregation. Real-world equivalents are a compromised relay
or proxy, or TLS broken by a future quantum computer. We model it as a hook that runs on the
server just before the update is checked and aggregated.
"""

import numpy as np

from flwr.app import ArrayRecord, Message


def tamper(msg: Message, scale: float = -5.0) -> None:
    """Poison the update in place: flip and amplify the weights (a model-poisoning attack).

    The attacker cannot re-sign the altered update without the farm's private key.
    """
    poisoned = [scale * a for a in msg.content["arrays"].to_numpy_ndarrays()]
    msg.content["arrays"] = ArrayRecord([np.ascontiguousarray(a) for a in poisoned])
