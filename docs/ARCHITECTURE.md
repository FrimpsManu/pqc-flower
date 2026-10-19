# Architecture

## System overview

![System architecture](architecture.svg)

Three farms (Flower **SuperNodes**) each keep their own soil and weather data and train the shared crop model locally. They talk to one server (Flower **SuperLink** + our **ServerApp**) over gRPC with TLS 1.3. The raw data never leaves a farm; only model updates are sent.

| Colour | Meaning |
|---|---|
| Green | Post-quantum, implemented by us (ML-DSA-65 farm login and signed model updates) |
| Blue | Post-quantum, already provided by gRPC 1.84 (hybrid X25519 + ML-KEM-768 key exchange) |
| Yellow | Classical today; PQC replacement planned |
| Red, dashed | Simulated attacker, used only in the demos |

## One training round

```mermaid
sequenceDiagram
    autonumber
    participant F as Farm (SuperNode + ClientApp)
    participant X as Attacker (simulated, Attack 1)
    participant S as Server (SuperLink + ServerApp)

    Note over F,S: gRPC over TLS 1.3, key exchange hybrid X25519 + ML-KEM-768
    F->>S: Farm login: ML-DSA-65 signature over a timestamp (pqc mode; ECDSA P-384 in classical mode)
    S->>F: Global model + round number
    F->>F: Train on private crop data
    F->>F: Sign (round, farm id, weights) with farm's ML-DSA-65 key
    F->>S: Model update + signature
    opt Attack 1 demo
        X-->>S: Alters the weights in transit (cannot re-sign without the farm's key)
    end
    S->>S: Verify signature with the farm's public key
    alt signature valid
        S->>S: Include update in FedAvg
    else signature invalid or missing
        S->>S: Reject update and log it
    end
    S->>S: Evaluate new global model on held-out test data
    S->>F: New global model (next round)
```

## Security layers

| Layer | Today (Flower 1.39.0) | Our version | Status |
|---|---|---|---|
| TLS key exchange | Hybrid X25519 + ML-KEM-768 (from gRPC 1.84) | Keep; measure against classical X25519 | Verified by handshake capture |
| TLS server certificate | ECDSA P-384 | ML-DSA, if gRPC supports it | Planned |
| Farm login (node auth) | ECDSA P-384 over a timestamp | ML-DSA-65 (`pqc` mode) | **Done** |
| Model-update integrity | None | ML-DSA-65 signature over round, farm id and weights | **Done** |
| Secure aggregation (SecAgg+) | ECDH P-384 | ML-KEM-768 | Stretch goal |

## Where things live in the code

| Component | File |
|---|---|
| Farm training + update signing | `pqcflower/client_app.py` |
| Server: signature check + FedAvg (`SignedFedAvg`) | `pqcflower/server_app.py` |
| ML-DSA-65 keys, sign and verify | `pqcflower/signing.py` |
| Simulated attacker (demo only) | `pqcflower/attack.py` |
| Data, farm split and model | `pqcflower/task.py` |
| ML-DSA-65 farm login (patches Flower's login path) | `pqcflower/pqc_login.py`, `pqcflower/cli.py` |
| Start server + farms (insecure / classical / pqc) | `scripts/run_local.sh` |
| TLS certificates and farm login keys | `scripts/gen_credentials.sh` |
| Attack 1 demo | `scripts/demo_attack.sh` |
| TLS handshake capture | `explore/tls_keyshare_sniffer.py` |
| Forged-login check | `explore/login_forgery_probe.py` |
