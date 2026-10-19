# Project Plan: Quantum-Safe Federated Learning for Smart Agriculture

Team: Augustine Manu-Frimpong, David Orisakwe, Kimora Mclemore

> **What we will deliver** (from our topic selection, Oct 8, 2026)
> By the end of the semester we will deliver a working Flower system, with several simulated farms, secured with post-quantum cryptography. We will compare it against the original classical version on speed and security, and demonstrate an attack that the new version stops.

That sentence makes three commitments:

- **D1.** A working Flower system with several simulated farms, secured with PQC
- **D2.** A comparison against the original classical version on **speed** and **security**
- **D3.** A demonstration of an **attack that the new version stops**

---

## D1: Working PQC-secured Flower system

### Farms (Topic 1: PQC for IoT and Smart Agriculture)
- 3–10 simulated farms, each holding its own private slice of crop/sensor data.
- Suggested data: a small tabular crop dataset (soil N/P/K, temperature, humidity, pH, rainfall → crop). Each farm gets a different mix of crops, so they need each other.
- A small model that trains in seconds, so experiments stay quick.

### Security layers (Topic 2: PQC-Enabled Federated Learning)

| Layer | Flower today | Our version |
|---|---|---|
| Farm ↔ server key exchange | TLS 1.3, **already hybrid X25519 + ML-KEM-768** with grpcio 1.84 (found Oct 13) | Keep, pin and measure it; compare with classical X25519 |
| Farm ↔ server certificates | ECDSA P-384 | ML-DSA certificates if gRPC supports them, else a documented limitation |
| Farm login (node authentication) | ECDSA P-384 | **ML-DSA-65** |
| Secure aggregation (SecAgg+) | ECDH P-384 | **ML-KEM-768** |

### New protection (Topic 3: Trustworthy AI with PQC-Based Authentication)
- Each farm signs its model update with **ML-DSA**. The server rejects any update whose signature doesn't verify.
- Flower doesn't do this today: its login signature covers only a timestamp, not the update.

**Done when:** classical and PQC versions both train the same model for N rounds with the same accuracy, switched by a single config setting.

---

## D2: Comparison against the classical version

### Speed, measured with 3, 5, 10 and 20 farms
- Time per training round
- TLS handshake time
- Key generation, sign/verify and encapsulate/decapsulate times (first numbers in `README.md`)
- Bytes sent per round, where bigger PQC keys and signatures show up
- Final model accuracy, to show security didn't cost accuracy

### Security: threat table

| Threat | Classical Flower | Our PQC Flower |
|---|---|---|
| Quantum computer recovers private keys (Shor's algorithm) | ❌ Broken | ✅ Resists |
| Harvest-now, decrypt-later of recorded traffic | ✅ with grpcio ≥ 1.84 (hybrid by default); ❌ with older grpcio | ✅ Protected, pinned |
| Forged farm identity | ❌ With a quantum computer | ✅ |
| Tampered / forged model update | ❌ No update signatures | ✅ Rejected |
| Replay of an old update | Partly (timestamp window) | ✅ If signature covers round + timestamp |

---

## D3: Attack demonstration

Each attack runs against both versions.

### Attack 1: Tampered / forged model update (a real gap today)
- An attacker injects or changes a farm's model update, for example a poisoned update that corrupts the shared model.
- **Classical:** accepted, because nothing checks the update content. We show model accuracy dropping.
- **PQC:** the ML-DSA signature fails, the update is rejected and accuracy holds.

### Attack 2: Simulated quantum adversary (the post-quantum point)
- We model a quantum computer as an "oracle" that gives the attacker a farm's ECDSA private key, which Shor's algorithm would do. We label this clearly as a simulation.
- **Classical:** the attacker impersonates the farm and the server accepts.
- **PQC:** no such oracle exists for ML-DSA / ML-KEM, so impersonation fails.

**Wording note:** Attack 1 is stopped by *signing* the updates. Attack 2 is what shows the *quantum-safe* part. We say this openly.

---

## Timeline

**Final due Nov 17. Our target: finished Nov 15**, keeping 2 days of buffer. That leaves about 4.5 weeks after the progress report, so the three roles run in parallel.

| Dates | Augustine (PQC integration) | David (signatures + attacks) | Kimora (farms + benchmarks) |
|---|---|---|---|
| Oct 13–14 | ✅ Repo, crypto map, PQC benchmarks | | Classical baseline started |
| **Oct 15** | **Progress report due (2 pages): all** | | |
| Oct 16–22 | ✅ Classical TLS + ECDSA login baseline (done Oct 13); TLS: classical vs hybrid comparison, PQC certificates check | ✅ Signed-update format (round + farm id + weights), done Oct 15 | ✅ Baseline done Oct 13; start benchmark harness |
| Oct 23–29 | ✅ ML-DSA farm login, done early Oct 18 | ✅ Signed model updates (Topic 3), done early Oct 15 (PR #1) | Benchmark harness (round time, bytes, handshake) |
| Oct 30–Nov 5 | ML-KEM in SecAgg+ *(stretch, see below)* | ✅ Attack 1 (tampered update), done early Oct 15; Attack 2 (simulated quantum) | Run classical benchmarks |
| Nov 6–10 | Integration: one config switch, classical ↔ PQC | Attack demo scripts polished | PQC benchmarks, charts, threat table |
| Nov 11–14 | **Final report + demo rehearsal: all** | | |
| **Nov 15** | **Done (our target)** | | |
| Nov 17 | Official deadline | | |

**Scope guard:** if we fall behind by Nov 5, ML-KEM in SecAgg+ is the first thing to cut. The deliverables still hold with PQC TLS + ML-DSA login + signed updates, and we would describe SecAgg+ as future work.

## Suggested split

- **Augustine:** PQC integration in Flower (TLS, login, SecAgg+)
- **David:** signed model updates + attack demos (D3)
- **Kimora:** farm simulation, dataset, benchmarks and charts (D1 baseline + D2)
