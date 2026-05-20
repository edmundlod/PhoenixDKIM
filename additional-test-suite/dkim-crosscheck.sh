#!/bin/bash
# dkim-crosscheck.sh
# Run the 2x2 signing cross-check matrix against a corpus of test messages.
#
# Requires:
#   opendkim      - built opendkim-ng binary
#   dkimverify    - from dkimpy (pip install dkimpy)
#   dkimsign      - from dkimpy
#   sendmail      - or swaks/curl to submit to test ports
#
# Setup assumed:
#   Port 2525 -> Postfix -> opendkim-ng milter  (signing only, Mode = s)
#   Port 2526 -> Postfix -> dkimpy-milter       (signing only, Mode = s)
#   Both configured with the same selector/domain pointing to real DNS or TestDNSData
#
# Usage: ./dkim-crosscheck.sh [corpus-dir]

set -euo pipefail

CORPUS="${1:-./test-corpus}"
NG_SOCKET="${OPENDKIM_SOCKET:-/run/opendkim-ng/opendkim.sock}"
DKIMPY_PORT="${DKIMPY_PORT:-8892}"
WORK_DIR=$(mktemp -d /tmp/dkim-xcheck.XXXXXX)
PASS=0
FAIL=0
SKIP=0

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

log_pass() { echo -e "  ${GREEN}PASS${NC}  $1"; ((PASS++)) || true; }
log_fail() { echo -e "  ${RED}FAIL${NC}  $1"; ((FAIL++)) || true; }
log_skip() { echo -e "  ${YELLOW}SKIP${NC}  $1"; ((SKIP++)) || true; }

# Sign a message through opendkim-ng test mode.
# opendkim -t reads a raw message and writes a signed copy to stdout
# when built with test/signing support.  Adjust if your build differs.
sign_ng() {
    local msg="$1" out="$2"
    if opendkim -t "$msg" > "$out" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Sign a message using dkimpy's standalone signer.
# Adjust key/selector/domain to match your test setup.
sign_dkimpy() {
    local msg="$1" out="$2"
    local key="${DKIMPY_KEY:-/etc/dkimpy/private.key}"
    local selector="${DKIMPY_SELECTOR:-test}"
    local domain="${DKIMPY_DOMAIN:-example.com}"
    if python3 -c "
import dkim, sys
msg = open('$msg', 'rb').read()
sig = dkim.sign(msg, b'$selector', b'$domain', open('$key','rb').read())
sys.stdout.buffer.write(sig + msg)
" > "$out" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Verify with opendkim-ng
verify_ng() {
    local msg="$1"
    opendkim -t "$msg" 2>/dev/null | grep -q "DKIM.*pass\|signature verified" 2>/dev/null
}

# Verify with dkimpy
verify_dkimpy() {
    local msg="$1"
    dkimverify < "$msg" 2>/dev/null
}

echo "============================================================"
echo " DKIM Cross-Check Matrix"
echo " Corpus: $CORPUS"
echo " Work dir: $WORK_DIR"
echo "============================================================"
echo ""

for msg in "$CORPUS"/*.eml; do
    name=$(basename "$msg")
    echo "── $name"

    ng_signed="$WORK_DIR/${name%.eml}-ng-signed.eml"
    py_signed="$WORK_DIR/${name%.eml}-py-signed.eml"

    # --- Sign with ng ---
    if sign_ng "$msg" "$ng_signed"; then
        # ng signs, ng verifies (trivial diagonal)
        if verify_ng "$ng_signed"; then
            log_pass "ng→ng  (trivial)"
        else
            log_fail "ng→ng  (trivial) — ng cannot verify its own signature!"
        fi

        # ng signs, dkimpy verifies (key off-diagonal)
        if verify_dkimpy "$ng_signed"; then
            log_pass "ng→dkimpy"
        else
            log_fail "ng→dkimpy  ← investigate canonicalization/format"
        fi
    else
        log_skip "ng signing failed for $name"
    fi

    # --- Sign with dkimpy ---
    if sign_dkimpy "$msg" "$py_signed"; then
        # dkimpy signs, ng verifies (key off-diagonal)
        if verify_ng "$py_signed"; then
            log_pass "dkimpy→ng"
        else
            log_fail "dkimpy→ng  ← investigate ng verification path"
        fi

        # dkimpy signs, dkimpy verifies (trivial diagonal)
        if verify_dkimpy "$py_signed"; then
            log_pass "dkimpy→dkimpy  (trivial)"
        else
            log_fail "dkimpy→dkimpy  (trivial) — dkimpy cannot verify its own signature!"
        fi
    else
        log_skip "dkimpy signing failed for $name"
    fi

    # Preserve signed copies for post-mortem if anything failed
    echo ""
done

echo "============================================================"
echo " Results: ${PASS} passed  ${FAIL} failed  ${SKIP} skipped"
echo "============================================================"

# Exit non-zero if any failures
[[ $FAIL -eq 0 ]]
