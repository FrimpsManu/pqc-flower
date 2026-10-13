# Quantum-Safe Federated Learning for Smart Agriculture

Group project: Augustine Manu-Frimpong, David Orisakwe, Kimora Mclemore

We take [Flower](https://github.com/flwrlabs/flower), an open-source federated learning framework, and replace its classical cryptography with post-quantum cryptography (PQC). Several simulated farms train one shared model without sharing their raw sensor data.

**Selected topics**
1. PQC for IoT and Smart Agriculture: the farms and their sensor data are the use case.
2. PQC-Enabled Federated Learning Systems: Flower's connections and authentication become quantum-safe.
3. Trustworthy AI with PQC-Based Authentication: model updates are signed, so forged or tampered updates are rejected.

**Network protocol:** gRPC over TLS 1.3

## Where Flower uses classical cryptography (Flower 1.39.0)

| Layer | Flower today | File | PQC replacement |
|---|---|---|---|
| Transport | gRPC over TLS 1.3 (BoringSSL inside grpcio) | `supercore/grpc.py` | Hybrid X25519MLKEM768 key exchange |
| Node authentication | ECDSA P-384 signature over a **timestamp** in gRPC metadata | `supercore/primitives/asymmetric.py`, `client/grpc_rere_client/node_auth_client_interceptor.py` | ML-DSA |
| Secure aggregation (SecAgg+) | ECDH P-384 pairwise keys, then HKDF and Fernet | `common/secure_aggregation/crypto/symmetric_encryption.py`, `client/mod/secure_aggregation/secaggplus_mod.py` | ML-KEM |
| Model update integrity | **None.** Updates are not signed. | none | ML-DSA signature on each update |

## Findings so far (2026-10-13)

- **Node auth does not cover the model update.** The SuperNode signs only the current timestamp. A forged or tampered update is not detected by this signature, so topic 3 adds a protection Flower does not have today.
- **PQC primitives are available in the library Flower already uses.** `cryptography` 50.0.2 (OpenSSL 3.5) has `mlkem` (768, 1024) and `mldsa` (44, 65, 87). Flower pins `cryptography<47`, so we override the pin.
- **The gRPC TLS server already accepts hybrid PQC.** An OpenSSL 3.6 client offering only `X25519MLKEM768` negotiated it with a plain `grpcio` 1.84 TLS server. A client offering only pure `MLKEM768` was rejected.
- **Open question:** whether the `grpcio` *client* offers X25519MLKEM768 by default. Our first probe was inconclusive because of a test-setup problem.
- **Upstream:** Flower has no issues or PRs about post-quantum crypto. The closest is [#6896](https://github.com/flwrlabs/flower/issues/6896) (mTLS node auth, classical).

### Classical vs PQC primitives (Apple M5 Pro, Python 3.12, `explore/bench_primitives.py`)

| Algorithm | Keygen (µs) | Op 1 (µs) | Op 2 (µs) | Public key (B) | Sig/ciphertext (B) |
|---|---|---|---|---|---|
| ECDSA P-384 (Flower) | 44 | 368 sign 1 MB | 444 verify | 97 | ~103 |
| ML-DSA-44 | 40 | 1,103 | 922 | 1,312 | 2,420 |
| ML-DSA-65 | 74 | 1,264 | 942 | 1,952 | 3,309 |
| ML-DSA-87 | 100 | 1,399 | 993 | 2,592 | 4,627 |
| ECDH P-384 (Flower) | 45 | 100 exchange | none | 97 | 97 |
| ML-KEM-768 | 36 | 9 encaps | 13 decaps | 1,184 | 1,088 |
| ML-KEM-1024 | 52 | 12 encaps | 17 decaps | 1,568 | 1,568 |

Takeaway: ML-KEM is about 10× faster than Flower's ECDH but sends about 12× more bytes. ML-DSA signs a 1 MB update about 3× slower than ECDSA, with 23–45× larger signatures. Both are small next to a model update of several MB.

## Classical baseline (2026-10-13)

Flower deployment mode on one laptop: one SuperLink (server) and 3 SuperNodes (farms) talking over real gRPC. Simulation mode skips the network, so it can't exercise TLS or node auth.

- **Data:** crop recommendation dataset, 2,200 samples, 7 features (soil N/P/K, temperature, humidity, pH, rainfall), 22 crops. 20% is held out as a test set. The rest is split non-IID across farms (Dirichlet α = 0.5), so each farm has 18–22 of the 22 crops.
- **Model:** softmax regression in NumPy, trained with FedAvg (20 local epochs, lr 1.0).
- **Result:** test accuracy 3.6% → **90.7% after 15 rounds**, matching 90.5% for pooled (non-federated) training. Mean round time is 9.8 s, almost all Flower scheduling/polling. See `results/baseline_classical_insecure_3farms_2026-10-13.txt`.
- **Note:** Flower installs each run's dependencies in a separate environment (with `cryptography` 46). The PQC version must declare `cryptography>=50` in `pyproject.toml`.

## Setup and run

```bash
uv venv -p 3.12 .venv
uv pip install -p .venv -r requirements.txt -e .
scripts/get_data.sh
scripts/run_local.sh 3 15          # 3 farms, 15 rounds (Ctrl-C after the last round)
.venv/bin/python explore/bench_primitives.py
```

## Next steps

- [x] Run a baseline Flower deployment with several farms (classical, no TLS yet)
- [ ] Add classical TLS + node auth to the baseline (the real "before" for comparison)
- [ ] Settle the gRPC client group question; enable X25519MLKEM768 on both ends
- [ ] Swap node auth ECDSA → ML-DSA
- [ ] Swap SecAgg+ ECDH → ML-KEM
- [ ] Sign model updates with ML-DSA; demo a tampered update being rejected
- [ ] Measure round time, bandwidth and handshake cost, classical vs PQC
