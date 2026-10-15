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
| Transport: key exchange | TLS 1.3, **already hybrid X25519MLKEM768** with grpcio 1.84 | `supercore/grpc.py` | Verify, measure, and keep (pin grpcio) |
| Transport: certificates | ECDSA P-384 (classical) | our `scripts/gen_credentials.sh` | ML-DSA certificates if gRPC supports them, else documented limitation |
| Node authentication | ECDSA P-384 signature over a **timestamp** in gRPC metadata | `supercore/primitives/asymmetric.py`, `client/grpc_rere_client/node_auth_client_interceptor.py` | ML-DSA |
| Secure aggregation (SecAgg+) | ECDH P-384 pairwise keys, then HKDF and Fernet | `common/secure_aggregation/crypto/symmetric_encryption.py`, `client/mod/secure_aggregation/secaggplus_mod.py` | ML-KEM |
| Model update integrity | **None.** Updates are not signed. | none | ML-DSA signature on each update |

## Findings so far (2026-10-13)

- **Node auth does not cover the model update.** The SuperNode signs only the current timestamp. A forged or tampered update is not detected by this signature, so topic 3 adds a protection Flower does not have today.
- **PQC primitives are available in the library Flower already uses.** `cryptography` 50.0.2 (OpenSSL 3.5) has `mlkem` (768, 1024) and `mldsa` (44, 65, 87). Flower pins `cryptography<47`, so we override the pin (`overrides.txt`).
- **Flower's TLS key exchange is already hybrid post-quantum.** With grpcio 1.84 on both ends, a farm offers X25519MLKEM768 first and the SuperLink picks it (`results/tls_handshake_flower_1.39_2026-10-13.txt`). This comes from gRPC's bundled TLS library, not from Flower. Server *authentication* (certificates) is still classical ECDSA, and older grpcio versions fall back to classical X25519.
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

### With Flower's built-in security (TLS 1.3 + ECDSA farm login)

`scripts/run_local.sh classical 3 15`: TLS on the gRPC link, and every farm's ECDSA P-384 key registered on the SuperLink. Test accuracy **90.9% after 15 rounds**, mean round time ~9.4 s, the same as without security. Verified during the run: plaintext gRPC is rejected, and a farm with an unregistered key is refused (exit code 305).

## Attack 1 demo: tampered model update (2026-10-15)

Farms can sign every model update with **ML-DSA-65** (`sign-updates = true`). The signature covers the round number, the farm id and the weights. The server (`SignedFedAvg`) drops any update whose signature fails. A simulated attacker (`attack-farm = 0`) alters farm 0's update in transit, flipping and amplifying its weights. It cannot re-sign the update without farm 0's private key.

All runs use 3 farms, 15 rounds, TLS 1.3 + ECDSA farm login (`results/attack1_*`):

| Run | Final test accuracy |
|---|---|
| Signed updates, no attack | 90.7% (signing costs no accuracy) |
| Attack, **unsigned** (how Flower behaves today) | **10.0%**, model ruined |
| Attack, **ML-DSA signed** | **82.5%**, tampered update rejected every round; the model trains on the 2 honest farms |

Attack 1 is stopped by *signing* updates; any secure signature would do. The post-quantum part, a simulated quantum attacker forging a farm's classical key, is Attack 2.

```bash
scripts/demo_attack.sh 8    # same attack, unsigned then signed (recording: demo/attack1_demo.gif)
```

![Attack 1 demo](demo/attack1_demo.gif)

## Setup and run

```bash
uv venv -p 3.12 .venv
uv pip install -p .venv -r requirements.txt --override overrides.txt -e .   # or: uv sync
scripts/get_data.sh
scripts/run_local.sh classical 3 15   # TLS + ECDSA login, 3 farms, 15 rounds (or: insecure)
scripts/stop_all.sh                  # stop leftover Flower processes if a run reports busy ports
.venv/bin/python explore/bench_primitives.py
```

## Next steps

- [x] Run a baseline Flower deployment with several farms (classical, no TLS yet)
- [x] Add classical TLS + node auth to the baseline (the real "before" for comparison)
- [x] Settle the gRPC client group question: hybrid X25519MLKEM768 is already negotiated
- [ ] Decide the classical reference for TLS (pin an older grpcio for a true classical X25519 baseline?)
- [ ] Swap node auth ECDSA → ML-DSA
- [ ] Swap SecAgg+ ECDH → ML-KEM
- [x] Sign model updates with ML-DSA; demo a tampered update being rejected (Attack 1)
- [ ] Attack 2: simulated quantum attacker (ECDSA key oracle) impersonating a farm
- [ ] Measure round time, bandwidth and handshake cost, classical vs PQC
