#!/usr/bin/env bash
# Classical credentials, as Flower's docs set them up:
#   - a CA and a SuperLink TLS certificate (ECDSA P-384)
#   - one ECDSA P-384 login key pair per farm (SSH format, for SuperNode authentication)
# Usage: scripts/gen_credentials.sh [num_farms]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FARMS="${1:-3}"
OPENSSL="${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}"
CERTS="$ROOT/credentials/certs"
KEYS="$ROOT/credentials/farm-keys"
mkdir -p "$CERTS" "$KEYS"

# Certificate authority
"$OPENSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -days 365 \
  -keyout "$CERTS/ca.key" -out "$CERTS/ca.crt" -subj "/CN=pqc-flower test CA" 2>/dev/null

# SuperLink server certificate, signed by the CA (gRPC requires a subjectAltName)
"$OPENSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
  -keyout "$CERTS/server.key" -out "$CERTS/server.csr" -subj "/CN=localhost" 2>/dev/null
"$OPENSSL" x509 -req -in "$CERTS/server.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" \
  -CAcreateserial -days 365 -out "$CERTS/server.pem" \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1") 2>/dev/null
rm -f "$CERTS/server.csr"

# Farm login keys
for ((i = 0; i < FARMS; i++)); do
  [[ -f "$KEYS/farm$i" ]] || ssh-keygen -q -t ecdsa -b 384 -N "" -C "farm$i" -f "$KEYS/farm$i"
done

echo "CA + server cert in $CERTS; $FARMS farm key pairs in $KEYS"
