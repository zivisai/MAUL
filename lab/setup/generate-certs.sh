#!/usr/bin/env bash
# Mint a self-signed CA and per-service mTLS certificates for the lab.
# Idempotent: re-running with the same CA preserves trust across restarts.

set -euo pipefail

CERTS_DIR="${CERTS_DIR:-/certs}"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

if [[ -f ca.crt && -f ca.key ]]; then
    echo "[certs] CA already present, reusing"
else
    echo "[certs] generating CA"
    openssl genrsa -out ca.key 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
        -subj "/CN=ATP Lab Root CA/O=Agent Trust Protocols Lab" \
        -out ca.crt
fi

# Services that need certs. Each gets a server cert valid for its DNS name +
# the same name as a SAN. Clients use mTLS so each cert is also a client cert
# (extendedKeyUsage = serverAuth + clientAuth).

SERVICES=(issuer originator orchestrator worker tool driver)

for svc in "${SERVICES[@]}"; do
    if [[ -f "${svc}.crt" && -f "${svc}.key" ]]; then
        echo "[certs] ${svc}.crt exists, skipping"
        continue
    fi
    echo "[certs] minting ${svc} cert"
    openssl genrsa -out "${svc}.key" 2048 >/dev/null 2>&1
    cat > "${svc}.cnf" <<EOF
[ req ]
default_bits = 2048
prompt = no
distinguished_name = dn
req_extensions = v3_req

[ dn ]
CN = ${svc}
O = Agent Trust Protocols Lab

[ v3_req ]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${svc}
DNS.2 = ${svc}.lab
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
    openssl req -new -key "${svc}.key" -out "${svc}.csr" -config "${svc}.cnf" >/dev/null 2>&1
    openssl x509 -req -in "${svc}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${svc}.crt" -days 365 -sha256 \
        -extensions v3_req -extfile "${svc}.cnf" >/dev/null 2>&1
    rm -f "${svc}.csr" "${svc}.cnf"
done

# Make all keys readable by the (non-root) lab containers.
chmod 644 *.key *.crt
echo "[certs] done. Files in ${CERTS_DIR}:"
ls -la "$CERTS_DIR"
