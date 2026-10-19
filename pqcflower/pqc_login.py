"""ML-DSA-65 farm login (SuperNode authentication) for Flower 1.39.0.

Flower authenticates each SuperNode request with an ECDSA P-384 signature over a timestamp.
This module makes the login code accept ML-DSA-65 keys as well. ECDSA keys keep working, so
classical and post-quantum farms can be compared on the same SuperLink.

Only the login call sites are patched. Secure aggregation (SecAgg+) imports the same helpers
for ECDH key agreement, and it is deliberately left untouched.

`install()` must run before Flower starts; the pqc-flower-* entry points in cli.py do this.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

from flwr.supercore.primitives import asymmetric

KEY_DIR = Path(os.environ.get("PQC_LOGIN_KEY_DIR", Path(__file__).resolve().parent.parent / "credentials" / "farm-keys-mldsa"))

_original_sign = asymmetric.sign_message
_original_verify = asymmetric.verify_signature
_original_nist_check = asymmetric.uses_nist_ec_curve


# --- Helpers that accept both ECDSA and ML-DSA keys -------------------------------------------

def sign_message(private_key, message: bytes) -> bytes:
    if isinstance(private_key, mldsa.MLDSA65PrivateKey):
        return private_key.sign(message)
    return _original_sign(private_key, message)


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    if isinstance(public_key, mldsa.MLDSA65PublicKey):
        try:
            public_key.verify(signature, message)
            return True
        except Exception:  # cryptography raises InvalidSignature
            return False
    return _original_verify(public_key, message, signature)


def is_accepted_login_key(public_key) -> bool:
    """Flower accepts only NIST EC curves; we also accept ML-DSA-65."""
    if isinstance(public_key, mldsa.MLDSA65PublicKey):
        return True
    return _original_nist_check(public_key)


# --- Key files ----------------------------------------------------------------------------------

def generate_farm_keys(num_farms: int, key_dir: Path = KEY_DIR) -> None:
    """farmN.pem (private, PKCS#8) and farmN.pub.pem (public, SubjectPublicKeyInfo)."""
    key_dir.mkdir(parents=True, exist_ok=True)
    for i in range(num_farms):
        if (key_dir / f"farm{i}.pem").exists():
            continue
        key = mldsa.MLDSA65PrivateKey.generate()
        (key_dir / f"farm{i}.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (key_dir / f"farm{i}.pub.pem").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def _load_private_key(path: Path):
    """PEM ML-DSA keys from generate_farm_keys(), or Flower's usual SSH-format ECDSA keys."""
    data = path.expanduser().read_bytes()
    if data.startswith(b"-----BEGIN PRIVATE KEY-----"):
        return serialization.load_pem_private_key(data, None)
    return serialization.load_ssh_private_key(data, None)


def _load_public_key(path: Path):
    data = path.read_bytes()
    if data.startswith(b"-----BEGIN PUBLIC KEY-----"):
        return serialization.load_pem_public_key(data)
    return serialization.load_ssh_public_key(data)


# --- Patches --------------------------------------------------------------------------------------

def install() -> None:
    """Patch Flower's farm-login code paths to accept ML-DSA-65 keys."""
    import importlib

    import click

    # import_module, not "from package import name": flwr.cli.supernode.register and
    # flwr.supernode.cli.flower_supernode are also re-exported *functions* with the same names.
    register = importlib.import_module("flwr.cli.supernode.register")
    client_auth = importlib.import_module("flwr.client.grpc_rere_client.node_auth_client_interceptor")
    server_auth = importlib.import_module("flwr.server.superlink.fleet.grpc_rere.node_auth_server_interceptor")
    control_handlers = importlib.import_module("flwr.superlink.servicer.control.control_handlers")
    flower_supernode = importlib.import_module("flwr.supernode.cli.flower_supernode")

    # Farm signs each request; SuperLink verifies it.
    client_auth.sign_message = sign_message
    server_auth.verify_signature = verify_signature
    # SuperLink accepts ML-DSA keys at registration.
    control_handlers.uses_nist_ec_curve = is_accepted_login_key

    # `flwr supernode register` reads an ML-DSA public key file.
    def try_load_public_key(public_key_path: Path) -> bytes:
        if not public_key_path.exists():
            raise click.ClickException(f"Public key file '{public_key_path}' does not exist.")
        public_key = _load_public_key(public_key_path)
        if not isinstance(public_key, (mldsa.MLDSA65PublicKey, ec.EllipticCurvePublicKey)) \
                or not is_accepted_login_key(public_key):
            raise click.ClickException(f"Unsupported login key type: {type(public_key).__name__}")
        return asymmetric.public_key_to_bytes(public_key)

    register.try_load_public_key = try_load_public_key

    # `flower-supernode --auth-supernode-private-key` reads an ML-DSA private key file.
    def _try_setup_client_authentication(args):
        if not args.auth_supernode_private_key:
            return None
        private_key = _load_private_key(Path(args.auth_supernode_private_key))
        if not isinstance(private_key, (mldsa.MLDSA65PrivateKey, ec.EllipticCurvePrivateKey)):
            raise SystemExit(f"Unsupported login key type: {type(private_key).__name__}")
        return private_key, private_key.public_key()

    flower_supernode._try_setup_client_authentication = _try_setup_client_authentication


if __name__ == "__main__":
    import sys

    generate_farm_keys(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
    print(f"ML-DSA-65 login keys in {KEY_DIR}")
