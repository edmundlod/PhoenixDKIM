#!/bin/sh
##
## Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
##
## Regression test for phoenixdkim-testmsg signing mode.
##
## testmsg once hardcoded its signing algorithm to DKIM_SIGN_RSASHA1; when
## RSA-SHA1 signing was removed from the library this silently broke *all*
## signing (dkim_eom() returned DKIM_STAT_INVALID for every key).  This test
## drives the actual testmsg binary in signing mode for both an RSA and an
## Ed25519 key and confirms it emits a well-formed DKIM-Signature carrying the
## algorithm the library derives from the key.  The cryptographic verifiability
## of a DKIM_SIGN_DEFAULT signature is covered separately by the library
## round-trip test (t-db-vault-sign); testmsg's own verify mode uses live DNS
## and so cannot verify offline here.
##
## Usage: t-testmsg-sign.sh <path-to-phoenixdkim-testmsg> <path-to-phoenixdkim-genkey>
##
## Exit codes: 0 = pass, 1 = fail, 77 = skipped (prerequisite missing).

set -u

TESTMSG="${1:-}"
GENKEY="${2:-}"

if [ -z "$TESTMSG" ] || [ -z "$GENKEY" ]; then
	echo "usage: $0 <testmsg> <genkey>" >&2
	exit 1
fi

# Prerequisites: the tools we are testing, plus perl/openssl that genkey needs.
[ -x "$TESTMSG" ] || { echo "SKIP: $TESTMSG not executable" >&2; exit 77; }
[ -f "$GENKEY" ]  || { echo "SKIP: $GENKEY not found" >&2; exit 77; }
command -v perl    >/dev/null 2>&1 || { echo "SKIP: perl not found" >&2; exit 77; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not found" >&2; exit 77; }

workdir=$(mktemp -d) || { echo "mktemp failed" >&2; exit 1; }
trap 'rm -rf "$workdir"' EXIT

# A minimal but RFC-conformant message: From and Date are required under the
# library's strict-headers mode that testmsg enables.
printf 'From: user@example.com\nDate: Tue, 03 Jun 2026 12:00:00 +0000\nTo: dest@example.com\nSubject: testmsg signing regression\n\nhello world\n' \
	> "$workdir/msg.eml"

rc=0

# $1 = selector, $2 = expected a= algorithm tag, $3.. = extra genkey args
check_sign()
{
	sel=$1
	want_alg=$2
	shift 2

	if ! ( cd "$workdir" && perl "$GENKEY" -s "$sel" -d example.com "$@" \
	       >/dev/null 2>&1 ); then
		echo "FAIL: genkey ($sel) failed" >&2
		rc=1
		return
	fi

	out=$("$TESTMSG" -d example.com -s "$sel" -k "$workdir/$sel.private" \
	      < "$workdir/msg.eml" 2>"$workdir/err")
	st=$?

	if [ "$st" -ne 0 ]; then
		echo "FAIL: testmsg sign ($sel) exited $st" >&2
		cat "$workdir/err" >&2
		rc=1
		return
	fi

	case "$out" in
	*"DKIM-Signature:"*) ;;
	*) echo "FAIL: ($sel) no DKIM-Signature in output" >&2; rc=1; return ;;
	esac

	case "$out" in
	*"a=$want_alg"*) ;;
	*) echo "FAIL: ($sel) expected a=$want_alg, got:" >&2
	   echo "$out" | grep -o 'a=[a-z0-9-]*' | head -1 >&2
	   rc=1; return ;;
	esac

	# the right selector and domain must be named, and the body preserved
	case "$out" in
	*"s=$sel"*) ;;
	*) echo "FAIL: ($sel) selector not in signature" >&2; rc=1; return ;;
	esac
	case "$out" in
	*"d=example.com"*) ;;
	*) echo "FAIL: ($sel) domain not in signature" >&2; rc=1; return ;;
	esac
	case "$out" in
	*"hello world"*) ;;
	*) echo "FAIL: ($sel) message body not preserved in output" >&2; rc=1; return ;;
	esac

	echo "ok: $sel -> a=$want_alg"
}

check_sign rsasel     rsa-sha256
check_sign ed25519sel ed25519-sha256 --type ed25519

if [ "$rc" -eq 0 ]; then
	echo "*** phoenixdkim-testmsg signing regression: PASS"
fi

exit "$rc"
