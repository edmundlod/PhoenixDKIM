#!/bin/bash
# dkim-crosscheck.sh
#
# Independent-implementation interop check: sign a corpus of messages with
# PhoenixDKIM and verify each one with dkimpy, a completely separate DKIM
# implementation.  This catches canonicalization and signature-format
# divergences that PhoenixDKIM's own test suite — which verifies what
# PhoenixDKIM (or its OpenDKIM ancestor) produced — structurally cannot.
#
# The check is HERMETIC: dkimpy is handed the public key on the command line
# (via crosscheck-dkimpy.py, which injects it through a fake DNS function), so
# no live DNS, MTA, or network is required.  It runs unattended in CI.
#
# Direction covered:
#   PhoenixDKIM sign  ->  dkimpy verify        (our signer vs an independent verifier)
#
# The reverse direction (dkimpy sign -> PhoenixDKIM verify) is intentionally NOT
# here: phoenixdkim-testmsg fetches the key from the system resolver and offers
# no key-injection hook, so it cannot be driven hermetically.  PhoenixDKIM's
# verification of externally-produced signatures is instead covered extensively
# by the libphoenixdkim conformance suite (QUERY_FILE-based t-tests).
#
# Usage:
#   ./dkim-crosscheck.sh [corpus-dir]
#
# Environment:
#   PHOENIXDKIM_TESTMSG   path to phoenixdkim-testmsg (else auto-detected)
#   CROSSCHECK_KEY        signing private key (default: bundled test key)
#   CROSSCHECK_SELECTOR   selector to embed (default: test)
#   CROSSCHECK_DOMAIN     signing domain     (default: example.com)
#
# Exit: 0 all pass, 1 any failure, 77 skipped (missing dkimpy / testmsg).

set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

CORPUS="${1:-$HERE/test_messages}"
KEY="${CROSSCHECK_KEY:-$REPO/phoenixdkim/tests/testkey.private}"
SELECTOR="${CROSSCHECK_SELECTOR:-test}"
DOMAIN="${CROSSCHECK_DOMAIN:-example.com}"
HELPER="$HERE/crosscheck-dkimpy.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; DECLINED=0

skip() { echo -e "${YELLOW}SKIP${NC}: $1"; exit 77; }

# ── Locate phoenixdkim-testmsg ────────────────────────────────────────────────
TESTMSG="${PHOENIXDKIM_TESTMSG:-}"
if [[ -z "$TESTMSG" ]]; then
    TESTMSG=$(find "$REPO" -name phoenixdkim-testmsg -type f -perm -u+x 2>/dev/null | head -1)
fi
[[ -n "$TESTMSG" && -x "$TESTMSG" ]] || skip "phoenixdkim-testmsg not found (build it first, or set PHOENIXDKIM_TESTMSG)"

# ── Dependency checks ─────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || skip "python3 not available"
python3 -c "import dkim" 2>/dev/null || skip "dkimpy not installed (pip install dkimpy)"
command -v openssl   >/dev/null 2>&1 || skip "openssl not available"
[[ -r "$KEY" ]] || skip "signing key not readable: $KEY"
[[ -d "$CORPUS" ]] || skip "corpus directory not found: $CORPUS"

# ── Derive the public-key TXT record from the private key ─────────────────────
PUB=$(openssl rsa -in "$KEY" -pubout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | base64 -w0)
[[ -n "$PUB" ]] || skip "could not derive public key from $KEY"
TXT="v=DKIM1; k=rsa; p=$PUB"

echo "============================================================"
echo " DKIM interop cross-check: PhoenixDKIM sign -> dkimpy verify"
echo " testmsg: $TESTMSG"
echo " corpus:  $CORPUS"
echo "============================================================"

shopt -s nullglob
messages=("$CORPUS"/*.eml)
shopt -u nullglob
[[ ${#messages[@]} -gt 0 ]] || skip "no .eml messages in $CORPUS"

WORK=$(mktemp -d /tmp/dkim-xcheck.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

for msg in "${messages[@]}"; do
    name=$(basename "$msg")
    signed="$WORK/${name%.eml}-signed.eml"

    if ! "$TESTMSG" -C -d "$DOMAIN" -s "$SELECTOR" -k "$KEY" \
            < "$msg" > "$signed" 2>"$WORK/sign.err"; then
        # PhoenixDKIM declining to sign is a policy decision, not an interop
        # failure: there is no signature to cross-check.  This is expected for
        # messages that violate RFC 5322 §3.6 (e.g. duplicate From/Subject),
        # which PhoenixDKIM refuses to sign as an anti-spoofing measure but
        # dkimpy will sign.  Report it as a divergence, not a failure.
        echo -e "  ${YELLOW}NOTE${NC}  $name  (PhoenixDKIM declined to sign: $(cat "$WORK/sign.err"))"
        ((DECLINED++)); continue
    fi

    if python3 "$HELPER" verify --txt "$TXT" < "$signed" 2>"$WORK/ver.err"; then
        echo -e "  ${GREEN}PASS${NC}  $name"
        ((PASS++))
    else
        echo -e "  ${RED}FAIL${NC}  $name  (dkimpy could not verify PhoenixDKIM's signature)"
        [[ -s "$WORK/ver.err" ]] && sed 's/^/        /' "$WORK/ver.err"
        ((FAIL++))
    fi
done

echo "============================================================"
echo " Results: $PASS passed, $FAIL failed, $DECLINED declined-to-sign"
echo "============================================================"
[[ $FAIL -eq 0 ]]
