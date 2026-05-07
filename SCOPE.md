# OpenDKIM Modernisation — Project Scope

This document defines the scope for the modernisation of OpenDKIM
(trusteddomainproject/OpenDKIM). It is the authoritative reference for
all AI-assisted work on this project. Do not modify it without explicit
human approval.

---

## Goals

1. Produce a working, well-tested DKIM milter daemon and library.
2. Replace all deprecated OpenSSL 1.x / GnuTLS API usage with modern OpenSSL 3 EVP APIs.
3. Remove dead subsystems, dead standards, and unmaintained dependencies.
4. Replace the autoconf/automake build system with CMake + CTest.
5. Replace BerkeleyDB with LMDB for binary key storage.
6. The result must compile and run correctly on Linux and FreeBSD/OpenBSD.
7. All behaviour within scope must be covered by a conformance test suite
   validated against RFC 6376 and the existing 2.11.0 beta before any
   rewriting begins.

---

## What Is In Scope

### Core components — keep and modernise

| Component | Notes |
|---|---|
| `libopendkim/` | Core DKIM library: signing, verification, canonicalisation, key parsing. This is the heart of the project. |
| `opendkim/` | The milter filter daemon. Signing and verification of live mail via the milter protocol. |
| `libut/` | Internal utility library used by libopendkim. Keep. |
| `miltertest/` | Lua-based milter testing framework. Keep for integration tests. |
| `docs/` | RFC and draft reference documents. Keep. |

### Utility tools — carry forward as-is

| Tool | Notes |
|---|---|
| `opendkim-genkey` | Key generation tool. Carry forward; update crypto calls to OpenSSL 3 EVP API but do not redesign. |
| `opendkim-testkey` | Key validation tool. Carry forward; same crypto update treatment. |

Note: flowerysong/openarc has produced improved versions of these tools.
They may be incorporated in a future phase but are out of scope here to
avoid scope creep and compatibility breakage.

### Data set backends — keep

| Backend | Notes |
|---|---|
| Flat file (`file:`) | The primary backend for most installations. Keep. |
| Regex file (`refile:`) | Wildcard/glob matching for signing tables. Keep. |
| Comma-separated list (`csl:`) | Inline list in config. Keep. |
| LMDB (`lmdb:`) | **New.** Replaces BerkeleyDB (`bdb:`). Fast, crash-safe, actively maintained, single-file. Implement as the binary/indexed backend. |
| Lua script (`lua:`) | Dynamic key lookup via Lua script. Keep as optional (`-DWITH_LUA=ON`). Useful for multi-tenant and secrets-manager integrations. Lua 5.4 target. |

### Crypto — replace entirely

| Old | New |
|---|---|
| OpenSSL 1.x low-level APIs (`RSA_*`, `DSA_*`, `ENGINE_*` etc.) | OpenSSL 3 EVP high-level APIs |
| GnuTLS (alternative build path) | **Removed entirely** — see rationale below |

**Linking model: dynamic, against the system OpenSSL 3.**

This is a distribution package. The distro owns the crypto library. Dynamic
linking means:
- Security patches to OpenSSL flow automatically through the distro's
  package manager without any OpenDKIM rebuild or repackage.
- System administrators and packagers retain full control over the crypto
  layer, including RHEL/AlmaLinux/Rocky `update-crypto-policies` and FIPS mode.
- No binary size bloat from bundled crypto.
- OpenDKIM is not dragged into AWS-LC's frequent release cycle (multiple
  updates per week would mean multiple OpenDKIM package rebuilds per week —
  unacceptable for a stable mail server component).

**GnuTLS rationale**: The GnuTLS path is a complete parallel implementation
of every crypto operation in libopendkim, doubling the code surface that
needs auditing, testing, and maintaining. There is no reason to keep it.
Delete all `#ifdef USE_GNUTLS` blocks and remove GnuTLS detection from the
build system entirely. Do not leave dead code.

**EVP API usage**: All crypto calls must use the OpenSSL 3 EVP high-level
API exclusively. No direct `RSA_*`, `DSA_*`, or other low-level struct
access. No `ENGINE_*` API. Use `EVP_DigestSign*`, `EVP_DigestVerify*`,
`EVP_PKEY_*` throughout. Code written correctly to this API will compile
against AWS-LC with trivial or no changes, if that is ever needed.

**Algorithms supported:**
- RSA-SHA256 (required by RFC 6376) — minimum key size **2048 bits**
- Ed25519 (RFC 8463)

**RSA-SHA1**: Signing with RSA-SHA1 is **dropped entirely**. Verification
of incoming RSA-SHA1 signatures is retained for interoperability with
legacy signed mail. OpenDKIM will refuse to generate new RSA-SHA1 signatures
and will log a warning when verifying them.

**RSA key size enforcement**: Keys smaller than 2048 bits are rejected for
signing with a hard error. On verification, sub-2048-bit keys produce a
warning and the signature is treated as a weak/fail result (configurable).

### RHEL / AlmaLinux / Rocky system-wide crypto policy

Because OpenDKIM dynamically links the system OpenSSL 3, it is fully subject
to `update-crypto-policies`. On a RHEL system in FIPS mode, OpenSSL will
enforce FIPS-approved algorithms and OpenDKIM will inherit that enforcement
automatically — no special build flags or documentation caveats needed.
This is the correct behaviour for a distribution package.

### Lua integration

Lua is used for two purposes:
1. **Data set scripts**: A Lua script can be called to perform arbitrary
   key lookups (e.g. querying a secrets manager or dynamic database).
2. **Policy hooks**: Four hook points (setup, screen, eom, final) allow
   complex signing/verification policy decisions that the config file
   cannot express.

**Target: Lua 5.4.** The existing C embedding code was written for Lua 5.1.
The following C API breaks must be addressed during the audit and port:

- `lua_newuserdata` signature changed (extra `nuvalue` argument in 5.4)
- `luaL_register` removed (replaced by `luaL_setfuncs`)
- `setfenv`/`getfenv` removed (use `_ENV` upvalue mechanism)
- Module system changed — all module registration code needs review

User-written Lua *scripts* (policy hooks) are largely unaffected by these
changes as the language-level syntax is mostly backward compatible. The
breakage is in the C-side embedding code only.

Lua remains optional: `-DWITH_LUA=ON` (default OFF). The filter must build
and operate correctly without Lua.

### FFR features — selected subset promoted to supported

These were previously gated behind `#ifdef _FFR_*`. They are now promoted
to standard optional features, always compiled in, controlled by config.

| Feature | Config option | Rationale |
|---|---|---|
| `resign` | `Resign yes/no` in opendkim.conf | Re-sign messages in one pass. Useful for relay servers and mailing list managers. Distinct from ARC (RFC 8617) and SRS — those are separate mechanisms entirely. |
| `identity_header` | `IdentityHeader <headername>` | Select signing key based on a named message header. Low complexity, useful for multi-tenant setups where upstream systems control identity. |
| `sender_macro` | `SenderMacro <macroname>` | Read sender address from an MTA macro rather than the From: header. Both Postfix (`{mail_addr}`, `{sender}`) and Sendmail pass macros to milters. Solves real problems on multi-port submission setups with different signing identities. |

### Build system

Replace autoconf/automake/libtool with **CMake** (minimum 3.20) and **CTest**.
All tests must be runnable via `ctest`. The AI must not modify test files
once they are written and passing.

### Platform targets

- Linux (glibc 2.17+, i.e. RHEL 7 era and later)
- FreeBSD 13+
- OpenBSD 7+

---

## What Is Out of Scope — Remove Permanently

### Entire subsystems to delete

| Directory / Component | Reason |
|---|---|
| `libvbr/` | Vouch By Reference (RFC 5518) is a dead standard. No major provider ever adopted it. Delete. |
| `librbl/` | Realtime Blacklist support. Wrong layer for a signing daemon. Delete. |
| `reprrd/` | Collaborative reputation via rrdtool. Experimental, never shipped. Delete. |
| `reputation/` | Collaborative reputation system. Experimental, never shipped. Delete. |
| `stats/` | Per-message statistics. Upstream aggregation server dead. SQL infrastructure removed. Delete. See future notes. |
| `www/` | Static HTML files for the opendkim.org website. Not software. Delete. |
| `contrib/` | User-contributed shell scripts. Archive to a separate branch; do not carry forward. |

### External dependencies to remove

| Dependency | Reason |
|---|---|
| OpenSSL 1.x low-level APIs | Replaced by OpenSSL 3 EVP APIs (same library, modern interface) |
| GnuTLS | Entire alternative build path removed |
| BerkeleyDB (libdb) | Unmaintained upstream. Replaced by LMDB. |
| OpenDBX (libopendbx) | SQL abstraction layer. Unmaintained. All SQL backends removed. |
| OpenLDAP | LDAP directory lookups removed entirely. |
| tre (regex library) | Only used by `diffheaders` FFR. Both removed. |

### Data set backends to remove

| Backend | Reason |
|---|---|
| `bdb:` (BerkeleyDB) | Replaced by `lmdb:` |
| `dsn:` (SQL via OpenDBX) | OpenDBX unmaintained. SQL in a signing daemon is wrong architecture. |
| `ldap:` / `ldaps:` / `ldapi:` | LDAP removed entirely. |

### FFR features removed permanently

| Feature | Reason |
|---|---|
| `vbr` | RFC 5518 dead standard |
| `atps` | Authorized Third-Party Signatures — never standardised. Drop. |
| `db_handle_pools` | Only relevant with SQL/LDAP backends, both removed |
| `diffheaders` | Depends on `tre` library (removed). Forensic feature, not core. |
| `ldap_caching` | LDAP removed |
| `postgres_reconnect_hack` | PostgreSQL removed |
| `rate_limit` | Wrong layer for a signing daemon |
| `replace_rules` | Sendmail MASQUERADE_AS workaround. Sendmail-specific hack; not supported. Postfix users never need this. |
| `reprrd` | Subsystem removed |
| `reputation` | Subsystem removed |
| `reputation_cache` | Subsystem removed |
| `socketdb` | Arbitrary socket data sets. Lua scripts cover this use case more cleanly. |
| `stats` | Subsystem removed |
| `statsext` | Subsystem removed |
| `rbl` | Subsystem removed |
| `default_sender` | Low-value edge case. Trivial to add later if needed. |
| `libar/` | Async DNS resolver. Solves real operational timeout problems. Deprecated and removed in 2012. |

---

## Dependencies — Final List

| Dependency | Required / Optional | Notes |
|---|---|---|
| OpenSSL 3 | Required | Dynamically linked. System library. Minimum version 3.0.0. |
| libmilter | Required | MTA filter protocol. Sendmail or Postfix libmilter. |
| LMDB | Required | Binary key/table storage backend. |
| libresolv / libar | Required | DNS resolution. libar is the preferred async path. |
| Lua 5.4 | Optional (`-DWITH_LUA=ON`) | Data set scripts and policy hooks. Default OFF. |
| libbsd | Optional, auto-detected | Provides `strlcpy`/`strlcat` on older Linux. Not needed on FreeBSD/OpenBSD (in libc) or glibc 2.38+. |
| pthreads | Required | Thread support. |

### libbsd / strlcpy detection order (CMake)

1. Found in system libc (glibc 2.38+, FreeBSD, OpenBSD) — use directly.
2. Found via libbsd — link against it.
3. Neither found — compile bundled two-function implementation in `compat/strl.c`.

This ensures the build works on all target platforms without forcing a
dependency on any distribution package.

---

## Future Development Notes (Out of Scope Now)

- **Stats / metrics**: If implemented later, should emit via StatsD or
  Prometheus rather than a proprietary SQL schema. Optional at compile time.
- **ARC (Authenticated Received Chain)**: RFC 8617. Related to but distinct
  from DKIM. Would be a new subsystem, not built on `resign`. Out of scope.
- **openarc / flowerysong tools**: Improved genkey/testkey implementations
  exist. May be incorporated in a future phase once API compatibility is
  assessed.

---

## Process Rules for AI-Assisted Work

These rules apply to every Claude Code session on this project.

1. **Do not modify test files.** Once a test is written and passing, it is
   frozen. If a test appears wrong, raise it for human review — never
   silently fix the test to match the implementation.

2. **Audit before rewriting.** Session 1 produces `AUDIT.md`: a complete
   inventory of all OpenSSL 1.x / GnuTLS API calls in scope, all deprecated
   functions, all Lua C API calls (flagging any 5.1-specific usage), and
   a module dependency map. No code changes in Session 1.

3. **Tests before implementation changes.** Session 2 produces the
   conformance test suite (RFC 6376 test vectors + real-world signed email
   corpora), validated against the running 2.11.0 beta. No crypto porting
   until Session 3.

4. **Crypto layer first.** Port `libopendkim` crypto to OpenSSL 3 EVP APIs
   before touching anything else. Get the test suite green on the new
   crypto before proceeding.

5. **Use EVP APIs exclusively.** No direct `RSA_*`, `DSA_*`, low-level
   struct access, or `ENGINE_*` API. Every operation through
   `EVP_DigestSign*`, `EVP_DigestVerify*`, `EVP_PKEY_*`.

6. **GnuTLS path deleted, not ifdef'd out.** Remove all `#ifdef USE_GNUTLS`
   blocks and their contents. Do not leave dead code.

7. **One concern per session.** Do not mix crypto porting with build system
   changes or subsystem removal in the same session.

8. **Build must be clean at all times.** Every session ends with a clean
   build and all tests passing.

9. **Do not invent scope.** If a file or feature is not mentioned in this
   document, ask before touching it.

---

*Last updated: April 2026. Human review required before any changes.*
