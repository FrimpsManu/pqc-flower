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
| Farm ↔ server connection | TLS 1.3, classical key exchange | TLS 1.3 with hybrid **X25519 + ML-KEM-768** |
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
| Harvest-now, decrypt-later of recorded traffic | ❌ Exposed | ✅ Protected |
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

| Dates | Milestone |
|---|---|
| Oct 13–14 | ✅ Repo, map of Flower's crypto, first PQC benchmarks. Classical baseline running if possible. |
| **Oct 15** | **Progress report due (2 pages)** |
| Oct 16–26 | Classical baseline complete: farms + dataset + Flower simulation |
| Oct 27–Nov 9 | PQC swaps: TLS hybrid, ML-DSA login, ML-KEM SecAgg+ |
| Nov 10–16 | Signed model updates (Topic 3) |
| Nov 17–23 | Attack demos 1 and 2 (D3) |
| Nov 24–Dec 1 | Benchmarks (D2), charts, threat table |
| Early Dec (date TBC) | Final report + live demo |

## Suggested split

- **Augustine:** PQC integration in Flower (TLS, login, SecAgg+)
- **David:** signed model updates + attack demos (D3)
- **Kimora:** farm simulation, dataset, benchmarks and charts (D1 baseline + D2)
