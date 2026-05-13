#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Part 2 – Generate RSA Key Pair & CSR
#
# Generates a 2048-bit RSA key pair and a CSR (Certificate Signing Request)
# to be uploaded to Apple Business Register in order to issue a signing
# certificate.
#
# Outputs:
#   signing-private-key.pem  – RSA 2048 private key (keep secure, never share)
#   signing-public-key.pem   – Extracted public key
#   signing-csr.pem          – CSR for upload to Apple Business Register
#   signing-key-info.json    – Metadata for subsequent steps
# ──────────────────────────────────────────────────────────────────────────────

COMMON_NAME="${1:-www.userede.com.br}"
ORGANIZATION="${2:-Itau Unibanco S.A.}"
COUNTRY="${3:-BR}"

KEY_FILE="signing-private-key.pem"
PUB_FILE="signing-public-key.pem"
CSR_FILE="signing-csr.pem"
OUTPUT_JSON="signing-key-info.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

echo "======================================================"
echo " Part 2 – Generate RSA Key Pair & CSR"
echo "======================================================"
echo " Common Name  : $COMMON_NAME"
echo " Organization : $ORGANIZATION"
echo " Country      : $COUNTRY"
echo " Key File     : $KEY_FILE"
echo " CSR File     : $CSR_FILE"
echo " Output       : $OUTPUT_JSON"
echo "======================================================"
echo ""

# ── Validate prerequisites ─────────────────────────────────────────────────
command -v openssl > /dev/null 2>&1 || fail "openssl not found. Install it first."

# Warn if private key already exists to avoid accidental overwrite
if [ -f "$KEY_FILE" ]; then
    info "Private key already exists: $KEY_FILE"
    read -r -p "  Overwrite? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

# ── Step 1: Generate 2048-bit RSA private key ──────────────────────────────
echo "[1/3] Generating 2048-bit RSA private key..."

openssl genrsa -out "$KEY_FILE" 2048 2>/dev/null

# Restrict permissions – private key must not be world-readable
chmod 600 "$KEY_FILE"

KEY_SIZE=$(openssl rsa -in "$KEY_FILE" -text -noout 2>/dev/null | grep "Private-Key:" | grep -o '[0-9]*')
ok "Private key generated : $KEY_FILE  ($KEY_SIZE bit)"

# ── Step 2: Extract public key ─────────────────────────────────────────────
echo ""
echo "[2/3] Extracting public key..."

openssl rsa -in "$KEY_FILE" -pubout -out "$PUB_FILE" 2>/dev/null
ok "Public key extracted  : $PUB_FILE"

# ── Step 3: Generate CSR ───────────────────────────────────────────────────
echo ""
echo "[3/3] Generating CSR..."

SUBJECT="//CN=${COMMON_NAME}/O=${ORGANIZATION}/C=${COUNTRY}"

# MSYS_NO_PATHCONV=1 prevents Git Bash on Windows from converting
# the subject string (e.g. /CN=...) into a Windows file path.
MSYS_NO_PATHCONV=1 openssl req -new \
    -key   "$KEY_FILE" \
    -out   "$CSR_FILE" \
    -subj  "$SUBJECT" \
    -sha256

CSR_SUBJECT=$(openssl req -noout -subject -in "$CSR_FILE" | sed 's/subject=//')
ok "CSR generated         : $CSR_FILE"
ok "CSR subject           : $CSR_SUBJECT"

# Verify the CSR signature
openssl req -noout -verify -in "$CSR_FILE" -key "$KEY_FILE" 2>/dev/null \
    && ok "CSR signature verified" \
    || fail "CSR signature verification failed."

# ── Save metadata for subsequent steps ────────────────────────────────────
echo ""
FINGERPRINT=$(openssl req -noout -pubkey -in "$CSR_FILE" | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | awk '{print $2}')

cat > "$OUTPUT_JSON" << EOF
{
  "CommonName":      "$COMMON_NAME",
  "Organization":    "$ORGANIZATION",
  "Country":         "$COUNTRY",
  "PrivateKeyFile":  "$KEY_FILE",
  "PublicKeyFile":   "$PUB_FILE",
  "CsrFile":         "$CSR_FILE",
  "KeyAlgorithm":    "RSA_2048",
  "PublicKeySHA256": "$FINGERPRINT"
}
EOF

ok "Metadata saved        : $OUTPUT_JSON"

echo ""
echo "======================================================"
echo " RSA Key Pair & CSR generated successfully!"
echo "======================================================"
cat "$OUTPUT_JSON"
echo ""
echo "======================================================"
echo " NEXT STEPS"
echo "======================================================"
echo "  1. Upload '$CSR_FILE' to Apple Business Register"
echo "     to issue your signing certificate."
echo ""
echo "  2. Apple will return a signed certificate (.pem/.cer)."
echo "     Use it in Part 3 together with '$KEY_FILE'."
echo ""
echo "  ⚠  IMPORTANT: Keep '$KEY_FILE' secure."
echo "     Never share or commit the private key."
echo "======================================================"
echo ""
