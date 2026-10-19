"""Probe the SuperLink's farm-login check directly over gRPC, using forged login headers.

Sends a harmless SendNodeHeartbeat for a non-existent node with three kinds of login header:
  valid         farm 0's registered key, signed with farm 0's private key (control)
  forged        farm 0's registered public key, signed with an attacker's ML-DSA-65 key
  unregistered  an attacker's own ML-DSA-65 key pair
and prints the gRPC status the SuperLink answers with. Only a failed signature check returns
UNAUTHENTICATED "Invalid signature"; a valid signature gets past login and then fails on the
fake node id. No server state is changed.

Usage: login_forgery_probe.py FARM0_PRIVATE_PEM CA_CERT [ADDRESS]
"""

import sys
from pathlib import Path

import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from flwr.common.constant import PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from flwr.proto.fleet_pb2_grpc import FleetStub
from flwr.proto.heartbeat_pb2 import SendNodeHeartbeatRequest
from flwr.proto.node_pb2 import Node
from flwr.supercore.date import now
from flwr.supercore.primitives.asymmetric import public_key_to_bytes

farm0_key = serialization.load_pem_private_key(Path(sys.argv[1]).read_bytes(), None)
ca_cert = Path(sys.argv[2]).read_bytes()
address = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1:9092"
attacker = mldsa.MLDSA65PrivateKey.generate()

cases = {
    "valid": (farm0_key, farm0_key.public_key()),
    "forged": (attacker, farm0_key.public_key()),
    "unregistered": (attacker, attacker.public_key()),
}

channel = grpc.secure_channel(
    address, grpc.ssl_channel_credentials(ca_cert), options=[("grpc.ssl_target_name_override", "localhost")]
)
stub = FleetStub(channel)
for name, (signing_key, presented_key) in cases.items():
    timestamp = now().isoformat()
    metadata = [
        (PUBLIC_KEY_HEADER, public_key_to_bytes(presented_key)),
        (TIMESTAMP_HEADER, timestamp),
        (SIGNATURE_HEADER, signing_key.sign(timestamp.encode("ascii"))),
    ]
    size = sum(len(k) + len(v) for k, v in metadata)
    try:
        stub.SendNodeHeartbeat(
            SendNodeHeartbeatRequest(node=Node(node_id=1), heartbeat_interval=30), metadata=metadata, timeout=5
        )
        result = "OK"
    except grpc.RpcError as err:
        result = f"{err.code().name}: {err.details()}"
    print(f"{name:<13} login headers {size:>5} B -> {result}")
