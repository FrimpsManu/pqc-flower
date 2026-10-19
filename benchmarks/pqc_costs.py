"""What does post-quantum cryptography cost in our Flower system? (Deliverable D2)

  A. Farm login, per request: ECDSA P-384 vs ML-DSA-65 sign/verify time and login-header bytes
  B. Signed model updates: ML-DSA-65 sign/verify time and signature overhead on our real update
  C. TLS 1.3 handshake against a live SuperLink: classical X25519 vs hybrid X25519MLKEM768
  D. Login requests per farm per round, from a real pqc-mode training run, giving login bytes
     per farm per round

Usage: python benchmarks/pqc_costs.py [--skip-live]   (C and D start their own servers, ~3 min)
Writes results/pqc_costs_<date>.txt and .json.
"""

import datetime
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, mldsa

from flwr.supercore.primitives.asymmetric import public_key_to_bytes

from pqcflower import signing, task

ROOT = Path(__file__).resolve().parent.parent
OPENSSL = os.environ.get("OPENSSL", "/opt/homebrew/opt/openssl@3/bin/openssl")
TIMESTAMP = datetime.datetime.now(datetime.timezone.utc).isoformat().encode("ascii")
results: dict = {"date": datetime.date.today().isoformat(), "machine": os.uname().machine}
lines: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)
    lines.append(text)


def median_us(fn, n: int) -> float:
    times = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times) * 1e6


def wire(n: int) -> int:
    """gRPC "-bin" metadata is base64-encoded on the wire."""
    return 4 * ((n + 2) // 3)


# --- A. Farm login --------------------------------------------------------------------------------
def bench_login() -> None:
    say("A. Farm login, per request (signature over a timestamp; median of 2000)")
    say(f"   {'':<12}{'sign':>10}{'verify':>10}{'public key':>12}{'signature':>11}{'headers on wire':>17}")
    ecdsa = ec.generate_private_key(ec.SECP384R1())
    mldsa_key = mldsa.MLDSA65PrivateKey.generate()
    rows = {
        "ECDSA P-384": (
            lambda: ecdsa.sign(TIMESTAMP, ec.ECDSA(hashes.SHA256())),
            ecdsa.public_key(),
            lambda sig: ecdsa.public_key().verify(sig, TIMESTAMP, ec.ECDSA(hashes.SHA256())),
        ),
        "ML-DSA-65": (
            lambda: mldsa_key.sign(TIMESTAMP),
            mldsa_key.public_key(),
            lambda sig: mldsa_key.public_key().verify(sig, TIMESTAMP),
        ),
    }
    results["login"] = {}
    for name, (sign, public_key, verify) in rows.items():
        sig = sign()
        pk = public_key_to_bytes(public_key)
        on_wire = wire(len(pk)) + wire(len(sig)) + len(TIMESTAMP) + 60  # + header names
        r = {
            "sign_us": median_us(sign, 2000), "verify_us": median_us(lambda: verify(sig), 2000),
            "public_key_B": len(pk), "signature_B": len(sig), "headers_on_wire_B": on_wire,
        }
        results["login"][name] = r
        say(f"   {name:<12}{r['sign_us']:>8.0f}us{r['verify_us']:>8.0f}us{len(pk):>10} B{len(sig):>9} B{on_wire:>15} B")
    say()


# --- B. Signed model updates -----------------------------------------------------------------------
def bench_updates() -> None:
    say("B. Signed model updates, ML-DSA-65 (median of 500)")
    key = mldsa.MLDSA65PrivateKey.generate()
    pub = key.public_key()
    model = task.init_model()
    update_bytes = sum(a.nbytes for a in model)
    sig = signing.sign_update(key, 1, 0, model)
    sign_us = median_us(lambda: signing.sign_update(key, 1, 0, model), 500)
    verify_us = median_us(lambda: signing.verify_update(pub, sig, 1, 0, model), 500)
    results["updates"] = {
        "update_B": update_bytes, "signature_B": len(sig), "sign_us": sign_us, "verify_us": verify_us,
        "overhead_pct": 100 * len(sig) / update_bytes,
    }
    say(f"   our crop model update: {update_bytes} B; signature {len(sig)} B (+{100 * len(sig) / update_bytes:.0f}%)")
    say(f"   sign {sign_us:.0f} us per farm per round; verify {verify_us:.0f} us per update on the server")
    for mb in (1, 10):
        big = [task.np.zeros(mb * 1024 * 1024 // 8)]
        t_sign = median_us(lambda: signing.sign_update(key, 1, 0, big), 20)
        say(f"   for scale, a {mb} MB update: sign {t_sign / 1000:.1f} ms, signature still {len(sig)} B "
            f"(+{100 * len(sig) / (mb * 1024 * 1024):.2f}%)")
        results["updates"][f"sign_ms_{mb}MB"] = t_sign / 1000
    say()


# --- live server helpers ----------------------------------------------------------------------------
def start(cmd: list[str], env: dict, log: Path, ready: str, timeout: int = 90) -> subprocess.Popen:
    proc = subprocess.Popen(cmd, env=env, stdout=open(log, "w"), stderr=subprocess.STDOUT, cwd=ROOT)
    for _ in range(timeout):
        if ready in log.read_text():
            return proc
        if proc.poll() is not None:
            break
        time.sleep(1)
    stop(proc)
    raise RuntimeError(f"{' '.join(cmd)} did not become ready; see {log}")


def stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    subprocess.run([str(ROOT / "scripts/stop_all.sh"), "--quiet"])
    time.sleep(2)


# --- C. TLS handshake ------------------------------------------------------------------------------
def bench_tls() -> None:
    say("C. TLS 1.3 handshake with our SuperLink (openssl client, median of 100)")
    log = ROOT / "logs/bench_server.log"
    log.parent.mkdir(exist_ok=True)
    server = start([str(ROOT / "scripts/run_local.sh"), "classical", "3", "1"],
                   {**os.environ, "SERVER_ONLY": "1"}, log, "SERVER READY")
    results["tls"] = {}
    try:
        for group in ("X25519", "X25519MLKEM768"):
            times, read_b, written_b, negotiated = [], 0, 0, ""
            for _ in range(100):
                t = time.perf_counter()
                out = subprocess.run(
                    [OPENSSL, "s_client", "-connect", "127.0.0.1:9092", "-groups", group, "-alpn", "h2",
                     "-CAfile", str(ROOT / "credentials/certs/ca.crt"), "-servername", "localhost"],
                    input=b"", capture_output=True, timeout=10,
                ).stdout.decode()
                times.append(time.perf_counter() - t)
                m = re.search(r"SSL handshake has read (\d+) bytes and written (\d+) bytes", out)
                read_b, written_b = int(m.group(1)), int(m.group(2))
                negotiated = (re.search(r"Negotiated TLS1.3 group: (\S+)", out) or re.search(r"Peer Temp Key: (\S+?),", out)).group(1)
            ms = statistics.median(times) * 1000
            results["tls"][group] = {"median_ms": ms, "client_sent_B": written_b, "client_received_B": read_b,
                                     "negotiated": negotiated}
            say(f"   {group:<16} negotiated {negotiated:<16} {ms:6.1f} ms   client sent {written_b:>5} B, "
                f"received {read_b:>5} B")
    finally:
        stop(server)
    c, h = results["tls"]["X25519"], results["tls"]["X25519MLKEM768"]
    extra = (h["client_sent_B"] + h["client_received_B"]) - (c["client_sent_B"] + c["client_received_B"])
    say(f"   hybrid PQC adds {extra} B per handshake and {h['median_ms'] - c['median_ms']:+.1f} ms "
        f"(times include starting the openssl process, the same for both)")
    say()


# --- D. Requests per round --------------------------------------------------------------------------
def bench_requests(rounds: int = 5, farms: int = 3) -> None:
    say(f"D. Login requests per farm per round (pqc run: {farms} farms, {rounds} rounds)")
    count_file = ROOT / "logs/login_count.txt"
    count_file.unlink(missing_ok=True)
    env = {**os.environ, "PQC_LOGIN_COUNT_FILE": str(count_file)}
    t = time.perf_counter()
    subprocess.run([str(ROOT / "scripts/run_local.sh"), "pqc", str(farms), str(rounds)], env=env,
                   capture_output=True, check=True, cwd=ROOT)
    duration = time.perf_counter() - t
    requests = len(count_file.read_text().splitlines())
    per_farm_round = requests / farms / rounds
    results["requests"] = {"total": requests, "farms": farms, "rounds": rounds,
                           "per_farm_per_round": per_farm_round, "run_seconds": duration}
    say(f"   {requests} authenticated requests in {duration:.0f} s = {per_farm_round:.0f} per farm per round")
    for name, r in results.get("login", {}).items():
        kb = per_farm_round * r["headers_on_wire_B"] / 1024
        ms = per_farm_round * r["sign_us"] / 1000
        results["requests"][f"{name}_KB_per_farm_round"] = kb
        say(f"   {name:<12} login traffic {kb:7.1f} KB and {ms:5.1f} ms of signing per farm per round")
    say()


def main() -> None:
    say(f"PQC cost benchmark, {results['date']} ({results['machine']}, Python {sys.version.split()[0]})")
    say()
    bench_login()
    bench_updates()
    if "--skip-live" not in sys.argv:
        bench_tls()
        bench_requests()
    out = ROOT / "results" / f"pqc_costs_{results['date']}"
    out.with_suffix(".txt").write_text("\n".join(lines) + "\n")
    out.with_suffix(".json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"saved {out}.txt / .json")


if __name__ == "__main__":
    main()
