"""Attack 2 (simulated quantum attacker): impersonate a farm by recovering its login key.

Shor's algorithm on a large quantum computer would recover an elliptic-curve private key from
its public key. No such machine exists, so we SIMULATE it with an oracle: for an ECDSA key it
hands back the farm's real private key (read from disk, and checked to match the public key);
for an ML-DSA key it fails, because no quantum algorithm is known to break ML-DSA (lattices).

The attacker then logs in to a live SuperLink as farm 0 over gRPC/TLS, exactly as a SuperNode
does: ActivateNode with farm 0's public key, signed with whatever key it has. The server only
checks that signature, so if it passes, the attacker *is* farm 0 to the server.

Usage: python -m pqcflower.attack2_quantum FARM0_PUBLIC_KEY FARM0_PRIVATE_KEY CA_CERT [ADDRESS]
(The private key path is what the oracle "computes"; the attacker never reads it directly.)
"""

import sys
from pathlib import Path

import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

from flwr.common.constant import PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from flwr.proto.fleet_pb2 import ActivateNodeRequest
from flwr.proto.fleet_pb2_grpc import FleetStub
from flwr.proto.heartbeat_pb2 import SendNodeHeartbeatRequest
from flwr.proto.node_pb2 import Node
from flwr.supercore.date import now
from flwr.supercore.primitives.asymmetric import public_key_to_bytes

from pqcflower.pqc_login import _load_private_key, _load_public_key, sign_message

B, R, G, Y, D, N = "\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[0m"


class KeyRecoveryFailed(Exception):
    pass


def simulated_quantum_key_recovery(public_key, private_key_path: Path):
    """SIMULATION of Shor's algorithm. Returns the private key for ECDSA; fails for ML-DSA."""
    if isinstance(public_key, mldsa.MLDSA65PublicKey):
        raise KeyRecoveryFailed("no known quantum algorithm breaks ML-DSA (lattice-based)")
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise KeyRecoveryFailed(f"unsupported key type {type(public_key).__name__}")
    recovered = _load_private_key(private_key_path)  # stands in for running Shor's algorithm
    assert recovered.public_key() == public_key, "oracle returned a key for a different farm"
    return recovered


def login_headers(signing_key, presented_public_key):
    timestamp = now().isoformat()
    return [
        (PUBLIC_KEY_HEADER, public_key_to_bytes(presented_public_key)),
        (TIMESTAMP_HEADER, timestamp),
        (SIGNATURE_HEADER, sign_message(signing_key, timestamp.encode("ascii"))),
    ]


def main() -> int:
    farm0_public = _load_public_key(Path(sys.argv[1]))
    farm0_private_path = Path(sys.argv[2])
    ca_cert = Path(sys.argv[3]).read_bytes()
    address = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1:9092"
    key_name = "ML-DSA-65" if isinstance(farm0_public, mldsa.MLDSA65PublicKey) else "ECDSA P-384"

    print(f"{D}[1]{N} Attacker copies farm 0's public login key (sent in every login): {B}{key_name}{N}")
    print(f"{D}[2]{N} Simulated quantum computer runs Shor's algorithm on it ...")
    try:
        signing_key = simulated_quantum_key_recovery(farm0_public, farm0_private_path)
        print(f"    {R}private key RECOVERED{N} {D}(simulated: Shor breaks elliptic-curve keys){N}")
    except KeyRecoveryFailed as err:
        signing_key = mldsa.MLDSA65PrivateKey.generate()
        print(f"    {G}key recovery FAILED{N}: {err}")
        print(f"    {D}attacker falls back to signing with a key of its own{N}")

    print(f"{D}[3]{N} Attacker logs in to the server as farm 0 ...")
    channel = grpc.secure_channel(
        address, grpc.ssl_channel_credentials(ca_cert), options=[("grpc.ssl_target_name_override", "localhost")]
    )
    stub = FleetStub(channel)
    try:
        response = stub.ActivateNode(
            ActivateNodeRequest(public_key=public_key_to_bytes(farm0_public), heartbeat_interval=30),
            metadata=login_headers(signing_key, farm0_public), timeout=10,
        )
        stub.SendNodeHeartbeat(
            SendNodeHeartbeatRequest(node=Node(node_id=response.node_id), heartbeat_interval=30),
            metadata=login_headers(signing_key, farm0_public), timeout=10,
        )
    except grpc.RpcError as err:
        print(f"    {G}{B}LOGIN REJECTED{N}: {err.code().name}: {err.details()}")
        print(f"{B}Result:{N} {G}impersonation blocked{N}; farm 0's identity is safe")
        return 0
    print(f"    {R}{B}LOGIN ACCEPTED{N}: server activated the attacker as farm 0 (node id {response.node_id})")
    print(f"{B}Result:{N} {R}impersonation succeeded{N}; the attacker would now receive farm 0's training")
    print("        tasks and the global model, and could submit model updates in farm 0's name")
    return 1


if __name__ == "__main__":
    sys.exit(main())
