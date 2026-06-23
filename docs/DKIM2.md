# DKIM2 Support (work in progress)

PhoenixDKIM is growing a **DKIM2** implementation alongside its existing DKIM1
signing and verification. This document records the design, the spec we track,
and the staged plan so the work stays reviewable while the standard is still
being written.

> **Status:** experimental, off by default, ABI not frozen. DKIM2 is an
> unfinished IETF draft. Nothing here is production-ready and tag/header
> details *will* change as the draft evolves.

## What DKIM2 is

DKIM1 attaches a single detached signature over selected headers and the body.
It cannot prove the intended recipient (enabling replay), cannot establish a
trustworthy return path, and breaks when intermediaries modify a message.

DKIM2 replaces the single signature with a **chain of per-hop signatures**.
Each handling domain adds a `DKIM2-Signature` that binds:

- the SMTP envelope it saw — `MAIL FROM` (`mf=`) and `RCPT TO` (`rt=`),
- the current message hashes, and
- **all prior signatures in the chain**.

A verifier walks the chain from `i=1` upward, checking it is contiguous (no
gaps), that each hop's envelope binding is consistent, and that every hop's
signature validates. The result is a tamper-evident record of custody that
defeats replay and makes every intermediary accountable.

## Spec we track

Authoritative target: **`draft-ietf-dkim-dkim2-spec`**, currently revision
**-02** (IETF DKIM working group).

- Spec: <https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/>
- Milter deployment profile (core vs extended):
  <https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/>
- DNS specification: <https://datatracker.ietf.org/doc/draft-chuang-dkim2-dns/>
- Best practices: <https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-bcp/>

The draft text is **not vendored** into this repository (see commit `8b221c7e`,
which dropped vendored IETF texts); follow the links above for the live copy.

### Profiles

Per the deployment-profile draft, DKIM2 splits into two profiles:

- **DKIM2-core** — stateless: envelope binding, chain of custody, header
  accountability, replay prevention. All inputs are available within the
  current SMTP session and the message headers, so it maps directly onto a
  milter with no persistent state. **This is the scope of the current work.**
- **DKIM2-extended** — adds body *recipes* via `Message-Instance` headers so
  intermediaries can declare reversible modifications. This needs message
  buffering and (potentially) shared state. **Deferred to a later milestone.**

### Header and tag shape (ietf-02)

`DKIM2-Signature` is a tag=value header. Core tags:

| tag | meaning |
|-----|---------|
| `i=` | hop sequence number (originator = 1, each hop increments) |
| `m=` | highest `Message-Instance` number this signature covers |
| `t=` | signature timestamp (Unix epoch) |
| `mf=` | base64 SMTP `MAIL FROM` (reverse-path) |
| `rt=` | base64 SMTP `RCPT TO` (forward-path), comma-separated |
| `d=` | signing domain (must align with the `mf=` domain) |
| `s=` | signature value(s): `selector:alg:sig` as base64-JSON |
| `n=` | optional nonce |
| `f=` | optional flags (`donotmodify`, `donotexplode`, `feedback`, `exploded`, ...) |

`Message-Instance` (extended) carries `v=` (version), `r=` (recipes, base64-JSON,
optional) and `h=` (hashes, base64-JSON).

Mandatory algorithms: **rsa-sha256** and **ed25519-sha256** (both must be
supported by verifiers; signers should offer both). Keys live in DNS at the
same `selector._domainkey.domain` TXT records used by DKIM1.

The header hash **excludes** `Received`, `Return-Path`, `Authentication-Results`,
`Message-Instance`, `DKIM2-Signature`, `X-*`, `DKIM-Signature`, and `ARC-*`.

## Architecture in this tree

DKIM2 is built **in parallel** to DKIM1, never by modifying the DKIM1 paths —
the two can coexist on one message.

- New `libphoenixdkim/dkim2-*.c/.h` modules, compiled only when the
  `WITH_DKIM2` CMake option is `ON`. Public API mirrors `dkim.h`
  (`dkim2_ctx_*`, `dkim2_sign()`, `dkim2_verify()`) in a new `dkim2.h`.
- Existing facilities are reused rather than duplicated: base64
  (`libphoenixdkim/base64.c`), DNS (`libphoenixdkim/dkim-dns.c`), and the
  OpenSSL/LibreSSL crypto shim (`libphoenixdkim/openssl-compat.h`).
- JSON uses **cJSON** (`libcjson`), pulled in only under `WITH_DKIM2`. ietf-02
  encodes `s=`/`h=`/`r=` as base64-JSON, so a JSON parser is required even for
  core.
- Two standalone test binaries, `phoenixdkim2-sign` and `phoenixdkim2-verify`,
  read a `.eml` on stdin so the chain can be exercised against the interop
  fixtures without standing up an MTA.

### Build gate

`WITH_DKIM2` defaults **OFF**; a default build is unaffected and needs no new
dependency. When it is explicitly `-DWITH_DKIM2=ON` but cJSON is missing, the
configure step **fails fatally** rather than silently disabling the feature
(consistent with the project's build-flag philosophy: a deliberate `WITH_X=ON`
must error if it cannot be satisfied; the default stays graceful).

All DKIM2 code is held to the same safety bar as the rest of the tree: it must
build clean under strict-C + extra-warnings, ASan/UBSan/LSan, TSan (the milter
is multithreaded and verification runs per-connection), and link-hardening, and
the new untrusted-input parsers ship fuzz harnesses.

## Reference implementations

The IETF DKIM working group maintains an interoperability harness with several
independent implementations (Perl, Python, Go, Haskell, C) that sign and verify
shared test messages:

- <https://github.com/dkim2wg/interop>

That repository has **no license**, so its code is **not** copied here. It is
used only as a reference to resolve spec ambiguities — `c/INTEROP-NOTES.md`
in particular logs real implementation pitfalls (trailing-semicolon
canonicalization, verifying from raw header bytes rather than re-serialized
structs, timestamp-window handling). Its `.eml` test vectors are checked in as
data, labelled by the draft revision that produced them, for cross-implementation
validation.

## Roadmap

DKIM2-core lands as a sequence of self-contained commits:

1. This design document.
2. `WITH_DKIM2` build option and the cJSON dependency.
3. Tag-value list parser.
4. base64-JSON helpers over cJSON.
5. Canonicalization and body/header hashing.
6. `DKIM2-Signature` / `Message-Instance` header model.
7. DKIM2 DNS key retrieval.
8. RSA-SHA256 and Ed25519-SHA256 sign/verify primitives.
9. DKIM2-core signing.
10. DKIM2-core chain verification.
11. `phoenixdkim2-sign` / `phoenixdkim2-verify` test CLIs.
12. Unit tests and interop fixtures.
13. Fuzz harnesses for the new parsers.
14. Milter integration behind config keys (default off).

### Out of scope (for now)

- **DKIM2-extended**: `Message-Instance` body recipes and modification
  rollback, and the stateful milter handling they need.
- DSN/bounce return-path authentication and mailing-list explosion handling.
- **ARC**: not extended. A draft proposes moving ARC to Historic because DKIM2
  is intended to supersede its intermediary-accountability role, so no new ARC
  surface is added.
