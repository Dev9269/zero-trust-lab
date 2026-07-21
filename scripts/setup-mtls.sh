#!/usr/bin/env bash
set -euo pipefail

# setup-mtls.sh — mTLS between gateway services using a local CA
#
# This is a LAB stopgap. A production deployment would use SPIFFE/SPIRE
# for workload identity (see README roadmap). The local CA approach here
# prevents unauthenticated processes from talking to the PEP/PDP stack
# but introduces key-management overhead that SPIRE solves natively.
#
# Prerequisites: docker compose running, step-cli available (or use the
# smallstep/step-ca container).
#
# Usage: bash scripts/setup-mtls.sh
#
# What this does:
#   1. Creates a local certificate authority (CA) using step-ca
#   2. Issues a certificate for each service (nginx, authz-bridge,
#      oauth2-proxy, OPA) signed by that CA
#   3. Configures each service to require client certs for inter-service
#      communication
#
# Lab Shortcut (documented trade-off):
#   A self-managed local CA is fine for a lab but creates a single point
#   of trust. If the CA private key is compromised, all service identities
#   are compromised. SPIFFE/SPIRE (Priority 3.8) fixes this with short-lived
#   certs and automatic rotation.
#
#   The current network-segmentation-only approach means any process that
#   reaches the compose network can talk to any service. mTLS closes this
#   gap without changing the network topology.

CA_DIR="${CA_DIR:-/opt/ztlab/ca}"
CERT_DIR="${CERT_DIR:-/opt/ztlab/gateway/certs}"
DOMAIN="${DOMAIN:-ztlab.local}"
DAYS="${DAYS:-365}"

SERVICES=("nginx" "authz-bridge" "oauth2-proxy" "opa" "demo-app" "loki")

echo "=== Setting up local CA ==="
mkdir -p "$CA_DIR" "$CERT_DIR"

# Generate CA key and cert if not already present
if [ ! -f "$CA_DIR/ca.key" ]; then
  openssl genrsa -out "$CA_DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" \
    -sha256 -days "$DAYS" -out "$CA_DIR/ca.crt" \
    -subj "/CN=ztlab-local-ca/O=ZeroTrustLab/C=IN"
  echo "CA created at $CA_DIR"
else
  echo "CA already exists at $CA_DIR — reusing"
fi

echo "=== Issuing service certificates ==="
for svc in "${SERVICES[@]}"; do
  KEY="$CERT_DIR/${svc}.key"
  CSR="$CERT_DIR/${svc}.csr"
  CRT="$CERT_DIR/${svc}.crt"
  EXT="$CERT_DIR/${svc}.ext"

  if [ -f "$CRT" ] && [ -f "$KEY" ]; then
    echo "  $svc — cert already exists, skipping"
    continue
  fi

  openssl genrsa -out "$KEY" 2048
  openssl req -new -key "$KEY" -out "$CSR" \
    -subj "/CN=${svc}.${DOMAIN}/O=ZeroTrustLab/C=IN"

  cat > "$EXT" <<-EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:${svc},DNS:${svc}.${DOMAIN}
EXTEOF

  openssl x509 -req -in "$CSR" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial -out "$CRT" -days "$DAYS" -sha256 -extfile "$EXT"

  rm -f "$CSR" "$EXT"
  echo "  $svc — cert issued ($CRT)"
done

echo ""
echo "=== mTLS setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Mount/COPY $CERT_DIR/*.crt and *.key into each service's container"
echo "  2. Configure nginx to require client certs for upstream connections:"
echo "       ssl_client_certificate /etc/nginx/certs/ca.crt;"
echo "       ssl_verify_client on;"
echo "  3. Configure each service to present its client cert when connecting"
echo "  4. Restart the stack: docker compose restart"
echo ""
echo "Verify with:"
echo "  curl --cacert $CA_DIR/ca.crt --cert $CERT_DIR/authz-bridge.crt"
echo "       --key $CERT_DIR/authz-bridge.key"
echo "       https://nginx.${DOMAIN}/healthz"
echo ""
echo "WARNING: This is a self-managed local CA. The CA key at"
echo "  $CA_DIR/ca.key"
echo "  is the root of trust for all service identities. Protect it accordingly."
