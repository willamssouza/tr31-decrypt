#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Part 3 – Generate KEK (Key Encryption Key)
#
# Creates an AES-256 KEK inside AWS Payment Cryptography HSM and exports it
# wrapped (encrypted) with the Apple Transport Public Key (RSA-4096) that
# was imported in Part 1.
#
# The wrapped KEK output is what gets sent to Apple.
# Apple decrypts it using their transport private key (held in their HSM).
#
# Prerequisites:
#   - Part 1 completed: apple-key-arns.json must exist
#   - Original Apple transport certificate PEM file must still be available
#   - AWS credentials configured with permissions for Payment Cryptography operations
#   - OpenSSL installed for certificate parsing and base64 encoding
#   - jq installed (optional, for JSON parsing; fallback to grep/sed if not available)
#
# Outputs:
#   kek-info.json         – Contains KEK ARN, wrapped key, and metadata for subsequent steps
#   kek-export-leaf.pem   – Temp leaf cert (removed on exit)
# ──────────────────────────────────────────────────────────────────────────────

APPLE_CERT_FILE="${1:-transport-key-certificate-PAN-NON_PROD.pem}"
ARNS_JSON="${2:-apple-key-arns.json}"
REGION="${3:-us-east-1}"

OUTPUT_JSON="kek-info.json"
LEAF_PEM="kek-export-leaf.pem"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

cleanup() {
    rm -f "$LEAF_PEM" create-key.json export-key.json
}
trap cleanup EXIT

echo "======================================================"
echo " Part 3 – Generate KEK"
echo "======================================================"
echo " Apple Cert   : $APPLE_CERT_FILE"
echo " ARNs JSON    : $ARNS_JSON"
echo " Region       : $REGION"
echo " Output       : $OUTPUT_JSON"
echo "======================================================"
echo ""

# ── Validate prerequisites ─────────────────────────────────────────────────
command -v aws    > /dev/null 2>&1 || fail "aws CLI not found."
command -v openssl > /dev/null 2>&1 || fail "openssl not found."

[ -f "$APPLE_CERT_FILE" ] || fail "Apple cert file not found: $APPLE_CERT_FILE"
[ -f "$ARNS_JSON"       ] || fail "ARNs JSON not found: $ARNS_JSON  (run Part 1 first)"

# ── Read ARNs from Part 1 ──────────────────────────────────────────────────
INTERMEDIATE_CA_ARN=$(grep -o '"IntermediateCaKeyArn"[[:space:]]*:[[:space:]]*"[^"]*"' "$ARNS_JSON" \
    | sed 's/.*"IntermediateCaKeyArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

[ -n "$INTERMEDIATE_CA_ARN" ] || fail "IntermediateCaKeyArn not found in $ARNS_JSON"
ok "Intermediate CA ARN : $INTERMEDIATE_CA_ARN"

# ── Step 1: Extract Apple leaf certificate (transport key) ─────────────────
echo ""
echo "[1/3] Extracting Apple transport key certificate..."

# The leaf certificate is the first cert in the PEM chain (index 1)
awk '/-----BEGIN CERTIFICATE-----/{idx++} idx==1{print} /-----END CERTIFICATE-----/ && idx==1{exit}' \
    "$APPLE_CERT_FILE" > "$LEAF_PEM"

[ -s "$LEAF_PEM" ] || fail "Failed to extract leaf certificate from $APPLE_CERT_FILE"

LEAF_SUBJECT=$(openssl x509 -noout -subject -in "$LEAF_PEM" | sed 's/subject=//')
ok "Leaf cert subject    : $LEAF_SUBJECT"

# AWS expects base64 of the full PEM content (including headers)
LEAF_CERT_B64=$(openssl base64 -A -in "$LEAF_PEM")

# ── Step 2: Create AES-128 KEK in AWS Payment Cryptography ────────────────
# NOTE: AES-128 is required here.
# RSA-4096 provides ~140 bits of security (NIST SP 800-57),
# which is sufficient to wrap AES-128 (128-bit) but NOT AES-256 (256-bit).
echo ""
echo "[2/3] Creating AES-128 KEK in AWS Payment Cryptography..."

# cat > create-key.json << EOF
# {
#   "KeyAttributes": {
#     "KeyAlgorithm": "AES_128",
#     "KeyClass":     "SYMMETRIC_KEY",
#     "KeyUsage":     "TR31_K0_KEY_ENCRYPTION_KEY",
#     "KeyModesOfUse": {
#       "Encrypt": true,
#       "Decrypt": true,
#       "Wrap":    true,
#       "Unwrap":  true
#     }
#   },
#   "Exportable": true,
#   "Enabled":    true
# }
# EOF

# CREATE_RESULT=$(aws payment-cryptography create-key \
#     --cli-input-json file://create-key.json \
#     --region "$REGION" \
#     --output json)

# KEK_ARN=$(echo "$CREATE_RESULT" | grep -o '"KeyArn"[[:space:]]*:[[:space:]]*"[^"]*"' \
#     | sed 's/.*"KeyArn"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

# [ -n "$KEK_ARN" ] || fail "Failed to create KEK. Check AWS credentials and region."
# ok "KEK ARN              : $KEK_ARN"

KEK_ARN="arn:aws:payment-cryptography:us-east-1:839834288637:key/nyrti5cdrzcnapql"
ok "KEK ARN              : $KEK_ARN"

# ── Step 3: Export KEK wrapped with Apple Transport Key ───────────────────
echo ""
echo "[3/3] Exporting KEK wrapped with Apple Transport Key (RSA_OAEP_SHA_256)..."

cat > export-key.json << EOF
{
  "ExportKeyIdentifier": "$KEK_ARN",
  "KeyMaterial": {
    "KeyCryptogram": {
      "CertificateAuthorityPublicKeyIdentifier": "$INTERMEDIATE_CA_ARN",
      "WrappingKeyCertificate": "$LEAF_CERT_B64",
      "WrappingSpec": "RSA_OAEP_SHA_256"
    }
  }
}
EOF

EXPORT_RESULT=$(aws payment-cryptography export-key \
    --cli-input-json file://export-key.json \
    --region "$REGION" \
    --output json)

# Response shape for KeyCryptogram export:
# { "WrappedKey": { "KeyMaterial": "BASE64...", "WrappedKeyMaterialFormat": "KEY_CRYPTOGRAM", ... } }
if command -v jq > /dev/null 2>&1; then
    WRAPPED_KEY=$(echo "$EXPORT_RESULT" | jq -r '.WrappedKey.KeyMaterial // empty')
    KEY_CHECK_VALUE=$(echo "$EXPORT_RESULT" | jq -r '.WrappedKey.KeyCheckValue // empty')
    KEY_CHECK_VALUE_ALGORITHM=$(echo "$EXPORT_RESULT" | jq -r '.WrappedKey.KeyCheckValueAlgorithm // empty')
else
    WRAPPED_KEY=$(echo "$EXPORT_RESULT" \
        | grep -o '"KeyMaterial"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*"KeyMaterial"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    KEY_CHECK_VALUE=$(echo "$EXPORT_RESULT" \
        | grep -o '"KeyCheckValue"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*"KeyCheckValue"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
    KEY_CHECK_VALUE_ALGORITHM=$(echo "$EXPORT_RESULT" \
        | grep -o '"KeyCheckValueAlgorithm"[[:space:]]*:[[:space:]]*"[^"]*"' \
        | sed 's/.*"KeyCheckValueAlgorithm"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
fi

[ -n "$WRAPPED_KEY" ] || fail "Failed to export KEK. Check ARNs and certificate. Raw response: $EXPORT_RESULT"
ok "KEK exported and wrapped successfully"
[ -n "$KEY_CHECK_VALUE" ] && ok "KCV                  : $KEY_CHECK_VALUE ($KEY_CHECK_VALUE_ALGORITHM)"

# ── Save results for subsequent steps ─────────────────────────────────────
echo ""
cat > "$OUTPUT_JSON" << EOF
{
  "KekArn":                  "$KEK_ARN",
  "KeyAlgorithm":            "AES_128",
  "KeyUsage":                "TR31_K0_KEY_ENCRYPTION_KEY",
  "WrappingSpec":            "RSA_OAEP_SHA_256",
  "WrappedKek":              "$WRAPPED_KEY",
  "KeyCheckValue":           "$KEY_CHECK_VALUE",
  "KeyCheckValueAlgorithm":  "$KEY_CHECK_VALUE_ALGORITHM"
}
EOF

ok "Results saved        : $OUTPUT_JSON"

echo ""
echo "======================================================"
echo " KEK generated and exported successfully!"
echo "======================================================"
cat "$OUTPUT_JSON"
echo ""
echo "======================================================"
echo " NEXT STEPS"
echo "======================================================"
echo "  1. Send 'WrappedKek' to Apple."
echo "     Apple will decrypt it using their transport private key."
echo ""
echo "  2. Use KEK ARN in subsequent steps to import/wrap"
echo "     the working keys (PEK, data keys, etc.)."
echo "======================================================"
echo ""
