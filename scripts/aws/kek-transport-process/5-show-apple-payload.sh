#!/bin/bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Part 5 – Show Payload to Send to Apple
#
# Reads the output files from Parts 3 and 4 and displays the three values
# that must be submitted to Apple Business Register:
#
#   1. KEK HEX       – Wrapped KEK (RSA_OAEP_SHA_256), as hex string
#   2. KCV           – Key Check Value of the KEK
#   3. SIGNATURE HEX – RSA-2048/SHA-256 signature of (Header || WrappedKEK)
#
# Prerequisites:
#   - Part 3 completed: kek-info.json must exist
#   - Part 4 completed: keyblock_signature.json must exist
#
# Usage:
#   ./5-show-apple-payload.sh [kek-info.json] [keyblock_signature.json]
# ──────────────────────────────────────────────────────────────────────────────

# ── Load session config if available ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/session-config.env" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/session-config.env"
fi

KEK_JSON="${1:-kek-info.json}"
SIG_JSON="${2:-keyblock_signature.json}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $*"; }

# ── Validate prerequisites ─────────────────────────────────────────────────
[ -f "$KEK_JSON" ] || fail "KEK info not found: $KEK_JSON  (run Part 3 first)"
[ -f "$SIG_JSON" ] || fail "Signature info not found: $SIG_JSON  (run Part 4 first)"

# ── Read values ────────────────────────────────────────────────────────────
read_field() {
    local file="$1" field="$2"
    grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" \
        | sed "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/" \
        | head -1
}

WRAPPED_KEK=$(read_field "$KEK_JSON" "WrappedKek")
KEY_CHECK_VALUE=$(read_field "$KEK_JSON" "KeyCheckValue")
KEY_CHECK_ALG=$(read_field "$KEK_JSON" "KeyCheckValueAlgorithm")
SIG_HEADER_VAL=$(read_field "$SIG_JSON" "Header")
SIG_HEX=$(read_field "$SIG_JSON" "SignatureHex")

[ -n "$WRAPPED_KEK"    ] || fail "WrappedKek not found in $KEK_JSON"
[ -n "$KEY_CHECK_VALUE" ] || fail "KeyCheckValue not found in $KEK_JSON"
[ -n "$SIG_HEX"        ] || fail "SignatureHex not found in $SIG_JSON"

# Convert WrappedKek to HEX if it looks like Base64
# (Base64 uses A-Z, a-z, 0-9, +, /, = — if those chars are present it's Base64)
if echo "$WRAPPED_KEK" | grep -qE '[+/=]'; then
    KEK_HEX=$(echo "$WRAPPED_KEK" | openssl base64 -d -A 2>/dev/null | xxd -p | tr -d '\n' | tr 'a-f' 'A-F')
    info "WrappedKek was Base64 — converted to HEX for display"
else
    KEK_HEX=$(echo "$WRAPPED_KEK" | tr 'a-f' 'A-F')
fi

SIG_HEX=$(echo "$SIG_HEX" | tr 'a-f' 'A-F')

# ── Display ────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo -e " ${BOLD}Apple Payload – Data to Submit${NC}"
echo "======================================================"
echo " Source files:"
echo "   KEK       : $KEK_JSON"
echo "   Signature : $SIG_JSON"
[ -n "${DATA_TYPE:-}" ] && echo "   Data type : $DATA_TYPE"
echo "======================================================"
echo ""

echo -e "${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│  1. KEK HEX  (Wrapped KEK – RSA_OAEP_SHA_256)       │${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────┘${NC}"
echo "$KEK_HEX"
echo ""

echo -e "${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│  2. KCV  ($KEY_CHECK_ALG)$(printf '%*s' $((45 - ${#KEY_CHECK_ALG})) '')│${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────┘${NC}"
echo "$KEY_CHECK_VALUE"
echo ""

echo -e "${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│  3. SIGNATURE HEX  (RSA-2048 / SHA-256)             │${NC}"
[ -n "${SIG_HEADER_VAL:-}" ] && \
echo -e "${CYAN}│     Header: $SIG_HEADER_VAL$(printf '%*s' $((40 - ${#SIG_HEADER_VAL})) '')│${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────┘${NC}"
echo "$SIG_HEX"
echo ""

echo "======================================================"
ok "Payload ready to submit to Apple Business Register."
echo "======================================================"
echo ""
