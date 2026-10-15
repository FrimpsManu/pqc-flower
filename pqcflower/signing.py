"""ML-DSA-65 signatures on model updates (Topic 3: Trustworthy AI with PQC-based authentication).

Each farm signs (round, farm id, model weights) with its own ML-DSA-65 key. The server holds every
farm's public key and drops any update whose signature does not verify, so an update that was
altered in transit, or forged by someone without the farm's private key, never reaches aggregation.
"""

import os
import struct
from pathlib import Path

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

KEY_DIR = Path(os.environ.get("PQC_KEY_DIR", Path(__file__).resolve().parent.parent / "credentials" / "pqc-keys"))
DOMAIN = b"pqcflower/model-update/v1"


def generate_farm_keys(num_farms: int, key_dir: Path = KEY_DIR) -> None:
    """One ML-DSA-65 key pair per farm: farmN.seed (private, 32 B) and farmN.pub (public, 1952 B)."""
    key_dir.mkdir(parents=True, exist_ok=True)
    for farm_id in range(num_farms):
        if (key_dir / f"farm{farm_id}.seed").exists():
            continue
        key = mldsa.MLDSA65PrivateKey.generate()
        (key_dir / f"farm{farm_id}.seed").write_bytes(key.private_bytes_raw())
        (key_dir / f"farm{farm_id}.pub").write_bytes(key.public_key().public_bytes_raw())


def load_private_key(farm_id: int) -> mldsa.MLDSA65PrivateKey:
    return mldsa.MLDSA65PrivateKey.from_seed_bytes((KEY_DIR / f"farm{farm_id}.seed").read_bytes())


def load_public_keys(num_farms: int) -> dict[int, mldsa.MLDSA65PublicKey]:
    return {
        farm_id: mldsa.MLDSA65PublicKey.from_public_bytes((KEY_DIR / f"farm{farm_id}.pub").read_bytes())
        for farm_id in range(num_farms)
    }


def _signed_message(server_round: int, farm_id: int, arrays: list[np.ndarray]) -> bytes:
    """Everything the signature covers. Round and farm id stop replaying old or other farms' updates."""
    parts = [DOMAIN, struct.pack(">II", server_round, farm_id)]
    for a in arrays:
        a = np.ascontiguousarray(a)
        parts += [a.dtype.str.encode(), struct.pack(f">{a.ndim + 1}I", a.ndim, *a.shape), a.tobytes()]
    return b"".join(parts)


def sign_update(key: mldsa.MLDSA65PrivateKey, server_round: int, farm_id: int, arrays: list[np.ndarray]) -> bytes:
    return key.sign(_signed_message(server_round, farm_id, arrays))


def verify_update(
    key: mldsa.MLDSA65PublicKey, signature: bytes, server_round: int, farm_id: int, arrays: list[np.ndarray]
) -> bool:
    try:
        key.verify(signature, _signed_message(server_round, farm_id, arrays))
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    import sys

    generate_farm_keys(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
    print(f"ML-DSA-65 farm keys in {KEY_DIR}")
