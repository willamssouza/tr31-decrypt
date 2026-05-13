#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Part 4 – Prepend Key Block Header and Sign Encrypted KEK
#
# Prepends the encrypted KEK (from Part 3) with a predefined key block header,
# converts the concatenation to binary, then signs it using 2048-bit RSA with
# SHA-256 (signing private key generated in Part 2).
#
# Two header variants are processed in a single run:
#   3130303030545041454159  →  "10000TPAEAY"  (KEK for cardholder data)
#   3130303030545041454959  →  "10000TPAEIY"  (KEK for PIN)
#
# Prerequisites:
#   - Part 2 completed: signing-key-info.json and signing-private-key.pem exist
#   - Part 3 completed: kek-info.json exists
#   - OpenSSL installed
#   - xxd available (ships with Git for Windows / most Unix systems)
#
# Outputs:
#   keyblock_signature_cardholder.sig  – Binary signature for cardholder KEK block
#   keyblock_signature.json            – Metadata + hex/base64 signatures for both
# ──────────────────────────────────────────────────────────────────────────────

KEK_JSON="${1:-kek-info.json}"
SIGNING_JSON="${2:-signing-key-info.json}"
SIG_HEADER="${3:-${SIG_HEADER}}"

SIG_CARDHOLDER="keyblock_signature_cardholder.sig"
OUTPUT_JSON="keyblock_signature.json"

TMP_BIN_CARDHOLDER="header_and_encrypted_kek_cardholder.bin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

cleanup() {
    rm -f "$TMP_BIN_CARDHOLDER"
}
trap cleanup EXIT

echo "======================================================"
echo " Part 4 – Prepend Header & Sign Encrypted KEK"
echo "======================================================"
echo " KEK JSON      : $KEK_JSON"
echo " Signing JSON  : $SIGNING_JSON"
echo " Output        : $OUTPUT_JSON"
echo "======================================================"
echo ""

# ── Validate prerequisites ─────────────────────────────────────────────────
command -v openssl > /dev/null 2>&1 || fail "openssl not found."
command -v xxd     > /dev/null 2>&1 || fail "xxd not found. Install it (ships with Git for Windows)."

[ -f "$KEK_JSON"     ] || fail "KEK JSON not found: $KEK_JSON  (run Part 3 first)"
[ -f "$SIGNING_JSON" ] || fail "Signing JSON not found: $SIGNING_JSON  (run Part 2 first)"

# ── Read WrappedKek (hex) from kek-info.json ───────────────────────────────
WRAPPED_KEK=$(grep -o '"WrappedKek"[[:space:]]*:[[:space:]]*"[^"]*"' "$KEK_JSON" \
    | sed 's/.*"WrappedKek"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

[ -n "$WRAPPED_KEK" ] || fail "WrappedKek not found in $KEK_JSON"
ok "WrappedKek loaded  : ${WRAPPED_KEK:0:48}..."

# Normalise to uppercase to match reference script convention
WRAPPED_KEK=$(echo "$WRAPPED_KEK" | tr 'a-f' 'A-F')

# ── Read signing private key path from signing-key-info.json ──────────────
PRIVATE_KEY=$(grep -o '"PrivateKeyFile"[[:space:]]*:[[:space:]]*"[^"]*"' "$SIGNING_JSON" \
    | sed 's/.*"PrivateKeyFile"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')

[ -n "$PRIVATE_KEY" ] || fail "PrivateKeyFile not found in $SIGNING_JSON"
[ -f "$PRIVATE_KEY" ] || fail "Private key file not found: $PRIVATE_KEY"

KEY_BITS=$(openssl rsa -in "$PRIVATE_KEY" -text -noout 2>/dev/null \
    | grep "Private-Key:" | grep -o '[0-9]*' | head -1)
[ "$KEY_BITS" = "2048" ] || fail "Expected 2048-bit RSA key, got ${KEY_BITS}-bit"
ok "Signing key        : $PRIVATE_KEY  (${KEY_BITS} bit)"

# ── Helper: sign a binary payload and return hex signature ────────────────
# Usage: sign_payload <header_hex> <sig_file> <tmp_bin_file>
sign_payload() {
    local header_hex="$1"
    local sig_file="$2"
    local tmp_bin="$3"

    echo ""
    echo "Processing KEK..."

    local combined="${header_hex}${WRAPPED_KEK}"

    info "Header (hex)      : $header_hex"
    info "Combined (hex)    : ${combined:0:64}..."

    # Convert hex string to binary (same approach as reference script)
    echo -n "$combined" | xxd -r -p > "$tmp_bin"

    local byte_count
    byte_count=$(wc -c < "$tmp_bin")
    ok "Binary payload    : $byte_count bytes  →  $tmp_bin"

    # Sign with RSA-2048 / SHA-256
    openssl dgst -sha256 -sign "$PRIVATE_KEY" -out "$sig_file" "$tmp_bin"
    ok "Signature written  : $sig_file"

    # Emit hex (uppercase, no line breaks) – mirrors reference script output
    local sig_hex
    sig_hex=$(xxd -p "$sig_file" | tr -d '\n' | tr 'a-f' 'A-F')
    echo ""
    echo "  Signature of KeyBlock (HEX):"
    echo "  $sig_hex"

    # Return values via global variables (bash 3 compatible)
    LAST_COMBINED_HEX="$combined"
    LAST_SIG_HEX="$sig_hex"
    LAST_SIG_B64=$(openssl base64 -A -in "$sig_file")
}

# ── Step 1: Cardholder data KEK ────────────────────────────────────────────
sign_payload "$SIG_HEADER" "$SIG_CARDHOLDER" "$TMP_BIN_CARDHOLDER"
COMBINED_CARDHOLDER="$LAST_COMBINED_HEX"
SIG_HEX_CARDHOLDER="$LAST_SIG_HEX"
SIG_B64_CARDHOLDER="$LAST_SIG_B64"

# ── Save metadata ──────────────────────────────────────────────────────────
echo ""
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "$OUTPUT_JSON" << EOF
{
  "Timestamp":          "$TIMESTAMP",
  "SigningAlgorithm":   "RSA_2048_SHA256",
  "PrivateKeyFile":     "$PRIVATE_KEY",
  "WrappedKek":         "$WRAPPED_KEK",

  "SignedKekData": {
    "Header":           "$SIG_HEADER",
    "CombinedHex":      "$COMBINED_CARDHOLDER",
    "SignatureFile":    "$SIG_CARDHOLDER",
    "SignatureHex":     "$SIG_HEX_CARDHOLDER",
    "SignatureBase64":  "$SIG_B64_CARDHOLDER"
  }
}
EOF

ok "Metadata saved     : $OUTPUT_JSON"

echo ""
echo "======================================================"
echo " Part 4 complete"
echo "======================================================"
echo ""
echo "  KEK signature : $SIG_CARDHOLDER"
echo "  Metadata      : $OUTPUT_JSON"
echo ""
echo "======================================================"
echo " NEXT STEPS"
echo "======================================================"
echo "  1. Run 5-show-apple-payload.sh to view the payload to send to Apple."
echo "======================================================"
echo ""
