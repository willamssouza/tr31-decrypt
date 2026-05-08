#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Part 1 – Import Apple Public Key Chain into AWS Payment Cryptography
#
# The PEM file contains 3 certificates (leaf-first order):
#   [0] Leaf           – Apple transport RSA-4096 public key (pos-kek-cert)
#   [1] Intermediate   – Apple External Encryption RSA CA 3 - G1
#   [2] Root CA        – Apple External RSA Root (self-signed)
#
# Import order in AWS Payment Cryptography:
#   1. Root CA        → RootCertificatePublicKey
#   2. Intermediate   → TrustedCertificatePublicKey (signed by root)
#   3. Leaf           → TrustedCertificatePublicKey (signed by intermediate)
#
# Prerequisites:
#   - Apple transport certificate PEM file (downloaded from Apple Business Register)
#   - AWS credentials configured with permissions for Payment Cryptography operations
#   - OpenSSL installed for certificate parsing and base64 encoding
#
# Outputs:
#   apple-key-arns.json  – ARNs of imported keys for subsequent steps
# ──────────────────────────────────────────────────────────────────────────────

CERT_FILE="${1:-transport-key-certificate-PAN-NON_PROD.pem}"
REGION="${2:-us-east-1}"
OUTPUT_JSON="apple-key-arns.json"

LEAF_PEM="apple-cert-leaf.pem"
INTERMEDIATE_PEM="apple-cert-intermediate.pem"
ROOT_PEM="apple-cert-root.pem"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

cleanup() {
    rm -f "$LEAF_PEM" "$INTERMEDIATE_PEM" "$ROOT_PEM" \
          apple-cert-1.pem apple-cert-2.pem apple-cert-3.pem \
          root-import.json intermediate-import.json leaf-import.json
}
trap cleanup EXIT

echo "======================================================"
echo " Import Apple Public Key Chain to AWS"
echo "======================================================"
echo " Certificate  : $CERT_FILE"
echo " Region       : $REGION"
echo " Output       : $OUTPUT_JSON"
echo "======================================================"
echo ""

# ── Validate prerequisites ─────────────────────────────────────────────────
[ -f "$CERT_FILE" ] || fail "Certificate file not found: $CERT_FILE"
command -v aws     > /dev/null 2>&1 || fail "aws CLI not found. Install it first."
command -v openssl > /dev/null 2>&1 || fail "openssl not found."

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CERT_FILE")
info "Certificates found in chain: $CERT_COUNT"
[ "$CERT_COUNT" -eq 3 ] || fail "Expected 3 certificates in the chain, found $CERT_COUNT."

# ── Step 1: Split PEM chain into individual files ──────────────────────────
echo "[1/4] Splitting PEM certificate chain..."

awk '
    /-----BEGIN CERTIFICATE-----/ { idx++; out = "apple-cert-" idx ".pem" }
    out { print > out }
' "$CERT_FILE"

mv -f apple-cert-1.pem "$LEAF_PEM"
mv -f apple-cert-2.pem "$INTERMEDIATE_PEM"
mv -f apple-cert-3.pem "$ROOT_PEM"

for f in "$LEAF_PEM" "$INTERMEDIATE_PEM" "$ROOT_PEM"; do
    [ -s "$f" ] || fail "Failed to extract certificate: $f"
done

LEAF_SUBJECT=$(openssl x509 -noout -subject -in "$LEAF_PEM"         | sed 's/subject=//')
INT_SUBJECT=$(openssl x509  -noout -subject -in "$INTERMEDIATE_PEM" | sed 's/subject=//')
ROOT_SUBJECT=$(openssl x509 -noout -subject -in "$ROOT_PEM"         | sed 's/subject=//')

ok "Leaf         : $LEAF_SUBJECT"
ok "Intermediate : $INT_SUBJECT"
ok "Root         : $ROOT_SUBJECT"

# Helper: base64-encode the PEM file content (single line, no newlines)
# AWS Payment Cryptography expects: base64( PEM text )
cert_to_base64_der() {
    openssl base64 -A -in "$1"
}

# ── Step 2: Import Root CA (self-signed) ───────────────────────────────────
echo ""
echo "[2/4] Importing Apple Root CA..."

ROOT_CERT_B64=$(cert_to_base64_der "$ROOT_PEM")

cat > root-import.json << EOF
{
  "KeyMaterial": {
    "RootCertificatePublicKey": {
      "KeyAttributes": {
        "KeyAlgorithm": "RSA_4096",
        "KeyClass": "PUBLIC_KEY",
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyModesOfUse": {
          "Verify": true
        }
      },
      "PublicKeyCertificate": "$ROOT_CERT_B64"
    }
  }
}
EOF

ROOT_RESULT=$(aws payment-cryptography import-key \
    --cli-input-json file://root-import.json \
    --region "$REGION" \
    --output json)

ROOT_KEY_ARN=$(echo "$ROOT_RESULT" | grep -o '"KeyArn"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"KeyArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
ok "Root CA ARN  : $ROOT_KEY_ARN"

# ── Step 3: Import Intermediate CA ────────────────────────────────────────
echo ""
echo "[3/4] Importing Apple Intermediate CA..."

INT_CERT_B64=$(cert_to_base64_der "$INTERMEDIATE_PEM")

cat > intermediate-import.json << EOF
{
  "KeyMaterial": {
    "TrustedCertificatePublicKey": {
      "CertificateAuthorityPublicKeyIdentifier": "$ROOT_KEY_ARN",
      "KeyAttributes": {
        "KeyAlgorithm": "RSA_4096",
        "KeyClass": "PUBLIC_KEY",
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyModesOfUse": {
          "Verify": true
        }
      },
      "PublicKeyCertificate": "$INT_CERT_B64"
    }
  }
}
EOF

INT_RESULT=$(aws payment-cryptography import-key \
    --cli-input-json file://intermediate-import.json \
    --region "$REGION" \
    --output json)

INT_KEY_ARN=$(echo "$INT_RESULT" | grep -o '"KeyArn"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"KeyArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
ok "Intermediate ARN : $INT_KEY_ARN"

# ── Step 4: Import Leaf Certificate (Apple Transport Key) ─────────────────
echo ""
echo "[4/4] Importing Apple Transport Key (leaf certificate)..."

LEAF_CERT_B64=$(cert_to_base64_der "$LEAF_PEM")

cat > leaf-import.json << EOF
{
  "KeyMaterial": {
    "TrustedCertificatePublicKey": {
      "CertificateAuthorityPublicKeyIdentifier": "$INT_KEY_ARN",
      "KeyAttributes": {
        "KeyAlgorithm": "RSA_4096",
        "KeyClass": "PUBLIC_KEY",
        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
        "KeyModesOfUse": {
          "Verify": true
        }
      },
      "PublicKeyCertificate": "$LEAF_CERT_B64"
    }
  }
}
EOF

LEAF_RESULT=$(aws payment-cryptography import-key \
    --cli-input-json file://leaf-import.json \
    --region "$REGION" \
    --output json)

LEAF_KEY_ARN=$(echo "$LEAF_RESULT" | grep -o '"KeyArn"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"KeyArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
ok "Transport Key ARN : $LEAF_KEY_ARN"

# ── Save ARNs for subsequent steps ─────────────────────────────────────────
echo ""
cat > "$OUTPUT_JSON" << EOF
{
  "RootCaKeyArn":           "$ROOT_KEY_ARN",
  "IntermediateCaKeyArn":   "$INT_KEY_ARN",
  "AppleTransportKeyArn":   "$LEAF_KEY_ARN"
}
EOF

ok "ARNs saved to: $OUTPUT_JSON"
echo ""
echo "======================================================"
echo " Apple Public Key Chain imported successfully!"
echo "======================================================"
cat "$OUTPUT_JSON"
echo ""
