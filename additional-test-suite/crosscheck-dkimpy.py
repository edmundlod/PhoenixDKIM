#!/usr/bin/env python3
"""
crosscheck-dkimpy.py — independent-implementation helper for dkim-crosscheck.sh.

Wraps the dkimpy library (https://launchpad.net/dkimpy) so the shell harness can
sign and verify messages with an implementation entirely separate from
PhoenixDKIM.  Verification takes the public key on the command line and feeds it
to dkimpy through a fake DNS function, so the cross-check needs no live DNS, no
MTA, and no network — it runs hermetically in CI.

Subcommands:
  verify --txt "<DKIM TXT record>"      < signed.eml     exit 0 = pass
  sign   --key K --selector S --domain D < message.eml    > signed.eml

Exit status: 0 success, 1 verification/parse failure, 2 usage/dependency error.
"""

import argparse
import sys


def _load_dkim():
    try:
        import dkim
    except ImportError:
        sys.stderr.write("dkimpy not installed (pip install dkimpy)\n")
        sys.exit(2)
    return dkim


def cmd_verify(args):
    dkim = _load_dkim()
    txt = args.txt.encode()

    def fake_dns(name, timeout=5):
        # Serve the supplied key record for whatever selector is queried.
        return txt

    msg = sys.stdin.buffer.read()
    try:
        ok = dkim.verify(msg, dnsfunc=fake_dns)
    except Exception as e:                       # malformed sig, bad key, etc.
        sys.stderr.write(f"dkimpy verify raised: {e}\n")
        return 1
    return 0 if ok else 1


def cmd_sign(args):
    dkim = _load_dkim()
    with open(args.key, "rb") as fh:
        key = fh.read()
    msg = sys.stdin.buffer.read()
    sig = dkim.sign(msg, args.selector.encode(), args.domain.encode(), key)
    sys.stdout.buffer.write(sig + msg)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify stdin with an injected key record")
    v.add_argument("--txt", required=True, help="DKIM public-key TXT record value")
    v.set_defaults(func=cmd_verify)

    s = sub.add_parser("sign", help="sign stdin with dkimpy")
    s.add_argument("--key", required=True)
    s.add_argument("--selector", required=True)
    s.add_argument("--domain", required=True)
    s.set_defaults(func=cmd_sign)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
