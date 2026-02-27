#!/usr/bin/env bash
set -euo pipefail

# Generate PKI files for Secure ADS examples.
#
# SCA (Shared CA) section based on Beckhoff documentation:
# https://infosys.beckhoff.com/content/1033/tc3_grundlagen/6798121483.html
#
# Produces:
#   sca/ca/rootCA.key               - CA private key
#   sca/ca/rootCA.pem               - CA certificate (PEM)
#   sca/client/client.key           - Client private key
#   sca/client/client.csr           - Client CSR (intermediate, kept for reference)
#   sca/client/client.crt           - Client certificate signed by CA
#   sca/plc/plc.key                 - PLC private key
#   sca/plc/plc.csr                 - PLC CSR (intermediate, kept for reference)
#   sca/plc/plc.crt                 - PLC certificate signed by CA
#   sca/client/client.p12           - PKCS#12 keystore (client key + cert + CA cert)
#   ssc/client-keystore.p12         - Self-signed PKCS#12 keystore

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <plc-ip> <client-ip>" >&2
  exit 1
fi

PLC_HOST="$1"
CLIENT_HOST="$2"

CA_DAYS=3600
CERT_DAYS=360
KEY_BITS=2048
P12_PASSWORD="password"

# ============================================================
#  SCA (Shared CA) material
# ============================================================

echo "=== Secure ADS SCA PKI Generation ==="
echo "PLC host:    $PLC_HOST"
echo "Client host: $CLIENT_HOST"
echo ""

# --- Root CA ---
mkdir -p sca/ca
echo "--- Generating Root CA ---"
openssl genrsa -out sca/ca/rootCA.key "$KEY_BITS" 2>/dev/null
openssl req -x509 -new -nodes \
  -key sca/ca/rootCA.key \
  -sha256 \
  -subj "/C=US/ST=Lab/L=Lab/O=SecureAdsResearch/OU=CA/CN=SecureAdsResearchCA" \
  -days "$CA_DAYS" \
  -out sca/ca/rootCA.pem
echo "  sca/ca/rootCA.key"
echo "  sca/ca/rootCA.pem"

# --- Client Certificate ---
mkdir -p sca/client
echo "--- Generating Client Certificate (CN=$CLIENT_HOST) ---"
openssl genrsa -out sca/client/client.key "$KEY_BITS" 2>/dev/null
openssl req -new \
  -key sca/client/client.key \
  -subj "/C=US/ST=Lab/L=Lab/O=SecureAdsResearch/OU=Client/CN=$CLIENT_HOST" \
  -out sca/client/client.csr
openssl x509 -req \
  -in sca/client/client.csr \
  -CA sca/ca/rootCA.pem \
  -CAkey sca/ca/rootCA.key \
  -CAcreateserial \
  -out sca/client/client.crt \
  -days "$CERT_DAYS" \
  -sha256 \
  -extfile <(printf "subjectAltName=IP:%s" "$CLIENT_HOST")
echo "  sca/client/client.key"
echo "  sca/client/client.crt"

# --- Client PKCS#12 Keystore ---
echo "--- Packaging Client PKCS#12 Keystore ---"
openssl pkcs12 -export \
  -in sca/client/client.crt \
  -inkey sca/client/client.key \
  -certfile sca/ca/rootCA.pem \
  -name "ads-client" \
  -out sca/client/client.p12 \
  -passout "pass:$P12_PASSWORD"
echo "  sca/client/client.p12 (password: $P12_PASSWORD)"

# --- PLC Certificate ---
mkdir -p sca/plc
echo "--- Generating PLC Certificate (CN=$PLC_HOST) ---"
openssl genrsa -out sca/plc/plc.key "$KEY_BITS" 2>/dev/null
openssl req -new \
  -key sca/plc/plc.key \
  -subj "/C=US/ST=Lab/L=Lab/O=SecureAdsResearch/OU=PLC/CN=$PLC_HOST" \
  -out sca/plc/plc.csr
openssl x509 -req \
  -in sca/plc/plc.csr \
  -CA sca/ca/rootCA.pem \
  -CAkey sca/ca/rootCA.key \
  -CAcreateserial \
  -out sca/plc/plc.crt \
  -days "$CERT_DAYS" \
  -sha256 \
  -extfile <(printf "subjectAltName=IP:%s" "$PLC_HOST")
echo "  sca/plc/plc.key"
echo "  sca/plc/plc.crt"

echo ""
echo "SCA fingerprints:"
echo "  CA:"
openssl x509 -in sca/ca/rootCA.pem -noout -fingerprint -sha256
echo "  Client:"
openssl x509 -in sca/client/client.crt -noout -fingerprint -sha256
echo "  PLC:"
openssl x509 -in sca/plc/plc.crt -noout -fingerprint -sha256

# ============================================================
#  SSC (Self-Signed Certificate) material
# ============================================================

echo ""
echo "=== Secure ADS SSC Keystore Generation ==="

mkdir -p ssc

# Generate a self-signed RSA cert with CN=ADS Client in a PKCS#12 keystore.
openssl req -x509 -newkey "rsa:$KEY_BITS" -nodes \
  -subj "/CN=ADS Client" \
  -days "$CERT_DAYS" \
  -keyout ssc/client.key \
  -out ssc/client.crt \
  2>/dev/null

openssl pkcs12 -export \
  -in ssc/client.crt \
  -inkey ssc/client.key \
  -name "ads-client" \
  -out ssc/client-keystore.p12 \
  -passout "pass:$P12_PASSWORD"

# Clean up intermediate files
rm -f ssc/client.key ssc/client.crt

echo "  ssc/client-keystore.p12 (alias: ads-client, password: $P12_PASSWORD)"
echo ""
echo "SSC fingerprint:"
keytool -list -keystore ssc/client-keystore.p12 -storepass "$P12_PASSWORD" -alias ads-client 2>/dev/null | grep -i fingerprint || true

echo ""
echo "=== Done ==="
