"""Session-based farm login: one ML-DSA-65 signature per session instead of one per request.

Flower authenticates every SuperNode request with the farm's public key and a fresh signature.
With ML-DSA-65 that is ~8 KB of headers per request and ~297 KB per farm per round (see
benchmarks/pqc_costs.py). Here the farm logs in with ML-DSA once; the SuperLink then issues a
session and later requests carry only a session ID and a MAC:

  first request   public key + timestamp + ML-DSA signature   (Flower's login, ~8 KB)
                  <- trailers: session ID (16 B) + session key (32 B)
  later requests  session ID + timestamp + HMAC-SHA256(key, method | timestamp)   (~150 B)

Why this stays quantum-safe: the session key is random and travels only inside TLS 1.3, whose key
exchange is hybrid X25519 + ML-KEM-768; HMAC-SHA256 keeps 128-bit security against quantum
attackers (Grover only halves it). The session is bound to the public key that passed the ML-DSA
check, and Flower's node-ID check still runs on every request. The MAC covers the RPC method, so a
captured tag cannot be reused for a different call.

Sessions expire after SESSION_TTL seconds and do not survive a SuperLink restart; in both cases
the server answers UNAUTHENTICATED and the farm logs in again with ML-DSA, once.
"""

import datetime
import hashlib
import hmac
import os
import secrets
import threading
import time

import grpc

from flwr.client.grpc_rere_client.node_auth_client_interceptor import NodeAuthClientInterceptor
from flwr.common.constant import PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from flwr.server.superlink.fleet.grpc_rere.node_auth_server_interceptor import (
    MAX_TIMESTAMP_DIFF,
    MIN_TIMESTAMP_DIFF,
    NodeAuthServerInterceptor,
    _unary_unary_rpc_terminator,
)
from flwr.supercore.date import now
from flwr.supercore.utils import get_metadata_bytes, get_metadata_str

SESSION_ID_HEADER = "pqc-session-id-bin"
SESSION_KEY_HEADER = "pqc-session-key-bin"
SESSION_MAC_HEADER = "pqc-session-mac-bin"
SESSION_TTL = int(os.environ.get("PQC_SESSION_TTL", "600"))

# Benchmarks only: if set, each farm appends the auth-header bytes it sends, one line per request.
_BYTES_FILE = os.environ.get("PQC_LOGIN_BYTES_FILE")


def session_mac(key: bytes, method: str, timestamp: str) -> bytes:
    return hmac.new(key, f"{method}\n{timestamp}".encode("ascii"), hashlib.sha256).digest()


def _wire_bytes(metadata) -> int:
    """Size of the auth headers on the wire ("-bin" values are base64-encoded by gRPC)."""
    auth = {PUBLIC_KEY_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER, SESSION_ID_HEADER, SESSION_MAC_HEADER}
    total = 0
    for name, value in metadata:
        if name in auth:
            n = len(value)
            total += len(name) + (4 * ((n + 2) // 3) if name.endswith("-bin") else n)
    return total


def _record(metadata) -> None:
    if _BYTES_FILE:
        with open(_BYTES_FILE, "a") as f:
            f.write(f"{_wire_bytes(metadata)}\n")


# --- SuperNode (farm) side -----------------------------------------------------------------------

class SessionClientInterceptor(NodeAuthClientInterceptor):
    """Full ML-DSA login when there is no session; session ID + MAC afterwards."""

    def __init__(self, private_key, public_key):
        super().__init__(private_key, public_key)
        self._session: tuple[bytes, bytes, float] | None = None  # (id, key, expires at)
        self._lock = threading.Lock()

    def intercept_unary_unary(self, continuation, client_call_details, request):
        with self._lock:
            session = self._session if self._session and self._session[2] > time.monotonic() else None
        if session:
            session_id, key, _ = session
            timestamp = now().isoformat()
            metadata = list(client_call_details.metadata or []) + [
                (SESSION_ID_HEADER, session_id),
                (TIMESTAMP_HEADER, timestamp),
                (SESSION_MAC_HEADER, session_mac(key, client_call_details.method, timestamp)),
            ]
            _record(metadata)
            call = continuation(client_call_details._replace(metadata=metadata), request)
            if call.code() != grpc.StatusCode.UNAUTHENTICATED:
                return call
            with self._lock:  # expired or unknown to the server (e.g. it restarted): log in again
                self._session = None

        def recording_continuation(details, req):
            _record(details.metadata)
            return continuation(details, req)

        call = super().intercept_unary_unary(recording_continuation, client_call_details, request)
        trailers = dict(call.trailing_metadata() or ())
        if SESSION_ID_HEADER in trailers and SESSION_KEY_HEADER in trailers:
            with self._lock:
                # Renew a little before the server expires the session.
                self._session = (trailers[SESSION_ID_HEADER], trailers[SESSION_KEY_HEADER],
                                 time.monotonic() + SESSION_TTL - 30)
        return call


# --- SuperLink (server) side ---------------------------------------------------------------------

class SessionServerInterceptor(NodeAuthServerInterceptor):
    """Accepts Flower's full login (and then issues a session) or a valid session MAC."""

    def __init__(self, state_factory):
        super().__init__(state_factory)
        self._sessions: dict[bytes, tuple[bytes, bytes, float]] = {}  # id -> (key, public key, expiry)
        self._by_public_key: dict[bytes, bytes] = {}  # public key -> its current session id
        self._lock = threading.Lock()

    def intercept_service(self, continuation, handler_call_details):
        if not handler_call_details.method.startswith("/flwr.proto.Fleet/"):
            return continuation(handler_call_details)
        metadata = handler_call_details.invocation_metadata
        session_id = get_metadata_bytes(metadata, SESSION_ID_HEADER)
        if not session_id:
            # Flower's full login; on success it calls _wrap_method_handler, which issues a session.
            return super().intercept_service(continuation, handler_call_details)

        timestamp_iso = get_metadata_str(metadata, TIMESTAMP_HEADER)
        mac = get_metadata_bytes(metadata, SESSION_MAC_HEADER)
        if not timestamp_iso or not mac:
            return _unary_unary_rpc_terminator("Missing session metadata")
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session[2] <= time.monotonic():
                self._drop(session_id)
                session = None
        if session is None:
            return _unary_unary_rpc_terminator("Unknown or expired session")
        key, public_key_bytes, _ = session
        expected = session_mac(key, handler_call_details.method, timestamp_iso)
        if not hmac.compare_digest(mac, expected):
            return _unary_unary_rpc_terminator("Invalid session MAC")
        try:
            age = (now() - datetime.datetime.fromisoformat(timestamp_iso)).total_seconds()
        except ValueError:
            return _unary_unary_rpc_terminator("Invalid timestamp")
        if not MIN_TIMESTAMP_DIFF < age < MAX_TIMESTAMP_DIFF:
            return _unary_unary_rpc_terminator("Invalid timestamp")
        # Same node-ID check as a full login, against the public key the session was issued to.
        return super()._wrap_method_handler(continuation(handler_call_details), public_key_bytes)

    def _wrap_method_handler(self, method_handler, received_public_key):
        """Called by Flower's intercept_service after a valid full login: also issue a session."""
        inner = super()._wrap_method_handler(method_handler, received_public_key)

        def handler(request, context):
            session_id, key = self._new_session(received_public_key)
            context.set_trailing_metadata(((SESSION_ID_HEADER, session_id), (SESSION_KEY_HEADER, key)))
            return inner.unary_unary(request, context)

        return grpc.unary_unary_rpc_method_handler(
            handler,
            request_deserializer=inner.request_deserializer,
            response_serializer=inner.response_serializer,
        )

    def _new_session(self, public_key_bytes: bytes) -> tuple[bytes, bytes]:
        session_id, key = secrets.token_bytes(16), secrets.token_bytes(32)
        with self._lock:
            old = self._by_public_key.get(public_key_bytes)
            if old:
                self._drop(old)  # one live session per farm
            self._sessions[session_id] = (key, public_key_bytes, time.monotonic() + SESSION_TTL)
            self._by_public_key[public_key_bytes] = session_id
        return session_id, key

    def _drop(self, session_id: bytes) -> None:
        _, public_key_bytes, _ = self._sessions.pop(session_id)
        if self._by_public_key.get(public_key_bytes) == session_id:
            del self._by_public_key[public_key_bytes]


def install() -> None:
    """Swap Flower's node-auth interceptors for the session versions (call after pqc_login.install)."""
    import importlib

    connection = importlib.import_module("flwr.client.grpc_rere_client.connection")
    superlink = importlib.import_module("flwr.superlink.cli.flower_superlink")
    connection.NodeAuthClientInterceptor = SessionClientInterceptor
    superlink.NodeAuthServerInterceptor = SessionServerInterceptor
