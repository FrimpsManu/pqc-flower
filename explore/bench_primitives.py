"""Compare Flower's classical primitives with their PQC replacements (time + size)."""

import os
import timeit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem

RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw
MSG = os.urandom(1024 * 1024)  # ~1 MB, stand-in for a model update


def us(fn, n=200):
    return min(timeit.repeat(fn, number=n, repeat=5)) / n * 1e6


def row(name, keygen, op1, op2, pk, extra, extra_name):
    print(f"{name:<22}{keygen:>10.1f}{op1:>12.1f}{op2:>12.1f}{pk:>10}{extra:>10}  {extra_name}")


print(f"{'algorithm':<22}{'keygen us':>10}{'op1 us':>12}{'op2 us':>12}{'pk B':>10}{'out B':>10}")

# --- Signatures (node auth + our signed model updates) ---
sk = ec.generate_private_key(ec.SECP384R1())
pk = sk.public_key()
sig = sk.sign(MSG, ec.ECDSA(hashes.SHA256()))
pk_len = len(pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
row("ECDSA P-384 (Flower)", us(lambda: ec.generate_private_key(ec.SECP384R1())),
    us(lambda: sk.sign(MSG, ec.ECDSA(hashes.SHA256())), 20),
    us(lambda: pk.verify(sig, MSG, ec.ECDSA(hashes.SHA256())), 20),
    pk_len, len(sig), "sign / verify 1MB")

for cls in (mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey):
    k = cls.generate()
    p = k.public_key()
    s = k.sign(MSG)
    row(cls.__name__.replace("PrivateKey", ""), us(cls.generate),
        us(lambda: k.sign(MSG), 20), us(lambda: p.verify(s, MSG), 20),
        len(p.public_bytes(*RAW)), len(s), "sign / verify 1MB")

# --- Key agreement (SecAgg+ pairwise keys) ---
a = ec.generate_private_key(ec.SECP384R1())
b = ec.generate_private_key(ec.SECP384R1()).public_key()
row("ECDH P-384 (Flower)", us(lambda: ec.generate_private_key(ec.SECP384R1())),
    us(lambda: a.exchange(ec.ECDH(), b)), 0.0, pk_len, pk_len, "exchange / - ")

for cls in (mlkem.MLKEM768PrivateKey, mlkem.MLKEM1024PrivateKey):
    k = cls.generate()
    p = k.public_key()
    _, ct = p.encapsulate()
    row(cls.__name__.replace("PrivateKey", ""), us(cls.generate),
        us(p.encapsulate), us(lambda: k.decapsulate(ct)),
        len(p.public_bytes(*RAW)), len(ct), "encaps / decaps")
