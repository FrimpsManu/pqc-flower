"""Probe session-based login (pqcflower/session_login.py) on a live pqc-session SuperLink.

Logs in as farm 0 once with ML-DSA-65 (ActivateNode), takes the session the SuperLink issues,
then sends SendNodeHeartbeat with correct and tampered session headers and prints the answers:
  valid session          correct session ID and MAC                       -> OK
  wrong MAC              MAC computed with a different key                 -> rejected
  unknown session        random session ID                                 -> rejected
  MAC for another call   valid tag computed for a different RPC method     -> rejected
  old timestamp          valid MAC over a timestamp 10 minutes old         -> rejected
  other node ID          farm 0's valid session, request for another node  -> rejected
  forged full login      farm 0's public key, attacker's ML-DSA signature  -> rejected, no session

Usage: session_probe.py FARM0_PRIVATE_PEM CA_CERT [ADDRESS]
Start the server with: SERVER_ONLY=1 scripts/run_local.sh pqc-session 3 1
"""

import datetime
import secrets
import sys
from pathlib import Path

import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from flwr.common.constant import PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from flwr.proto.fleet_pb2 import ActivateNodeRequest
from flwr.proto.fleet_pb2_grpc import FleetStub
from flwr.proto.heartbeat_pb2 import SendNodeHeartbeatRequest
from flwr.proto.node_pb2 import Node
from flwr.supercore.date import now
from flwr.supercore.primitives.asymmetric import public_key_to_bytes

from pqcflower.session_login import SESSION_ID_HEADER, SESSION_KEY_HEADER, SESSION_MAC_HEADER, session_mac

HEARTBEAT = "/flwr.proto.Fleet/SendNodeHeartbeat"

farm0_key = serialization.load_pem_private_key(Path(sys.argv[1]).read_bytes(), None)
ca_cert = Path(sys.argv[2]).read_bytes()
address = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1:9092"
stub = FleetStub(grpc.secure_channel(
    address, grpc.ssl_channel_credentials(ca_cert), options=[("grpc.ssl_target_name_override", "localhost")]
))


def full_login(signing_key):
    timestamp = now().isoformat()
    return [
        (PUBLIC_KEY_HEADER, public_key_to_bytes(farm0_key.public_key())),
        (TIMESTAMP_HEADER, timestamp),
        (SIGNATURE_HEADER, signing_key.sign(timestamp.encode("ascii"))),
    ]


def call(name, metadata, request=None):
    size = sum(len(k) + len(v) for k, v in metadata)
    try:
        _, info = stub.SendNodeHeartbeat.with_call(
            request or SendNodeHeartbeatRequest(node=Node(node_id=node_id), heartbeat_interval=30),
            metadata=metadata, timeout=5,
        )
        result = "OK"
        if dict(info.trailing_metadata() or ()).get(SESSION_ID_HEADER):
            result += " (session issued)"
    except grpc.RpcError as err:
        result = f"{err.code().name}: {err.details()}"
    print(f"{name:<22} auth headers {size:>5} B -> {result}")


# 1. One full ML-DSA login; the SuperLink returns a session in the trailers.
response, info = stub.ActivateNode.with_call(
    ActivateNodeRequest(public_key=public_key_to_bytes(farm0_key.public_key()), heartbeat_interval=30),
    metadata=full_login(farm0_key), timeout=5,
)
node_id = response.node_id
trailers = dict(info.trailing_metadata())
session_id, key = trailers[SESSION_ID_HEADER], trailers[SESSION_KEY_HEADER]
print(f"ML-DSA login as farm 0 -> node {node_id}; session issued ({len(session_id)} B id, {len(key)} B key)")


def session_headers(sid=session_id, k=key, method=HEARTBEAT, timestamp=None):
    timestamp = timestamp or now().isoformat()
    return [(SESSION_ID_HEADER, sid), (TIMESTAMP_HEADER, timestamp),
            (SESSION_MAC_HEADER, session_mac(k, method, timestamp))]


old = (now() - datetime.timedelta(minutes=10)).isoformat()
call("valid session", session_headers())
call("wrong MAC", session_headers(k=secrets.token_bytes(32)))
call("unknown session", session_headers(sid=secrets.token_bytes(16)))
call("MAC for another call", session_headers(method="/flwr.proto.Fleet/PushMessages"))
call("old timestamp", session_headers(timestamp=old))
call("other node ID", session_headers(),
     SendNodeHeartbeatRequest(node=Node(node_id=node_id + 1), heartbeat_interval=30))
call("forged full login", full_login(mldsa.MLDSA65PrivateKey.generate()))
