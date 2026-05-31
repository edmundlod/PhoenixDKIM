# PhoenixDKIM — Project Scope

This document defines the scope for the PhoenixDKIM project. It is the
authoritative reference for all AI-assisted work on this project.
Do not modify it without explicit human approval.

PhoenixDKIM began as a modernisation fork of trusteddomainproject/OpenDKIM,
but has since become a standalone project with its own direction. The goals
are no longer just "bring OpenDKIM up to date" — they are to produce the
milter daemon that is cleanest, most secure, best optimised, and most ready
for DKIM2 when the RFC lands. We track upstream OpenDKIM bug fixes and port
the relevant ones, but we are not bound to upstream's architecture or
decisions.

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
8. **Security**: Treat memory safety as a first-class concern throughout.
   Proactively audit the codebase for exploitable defects using both static
   analysis and LLM-assisted review on a regular cadence. See the Security
   section and `ai/security-audit-process.md`.
9. **Performance**: Optimise the signing and verification hot paths so that
   PhoenixDKIM performs well at high mail volumes and is not a bottleneck
   when DKIM2's higher per-message CPU requirements arrive. See the
   Performance section and `ai/optimization-roadmap.md`.
10. **DKIM2 readiness**: Track the DKIM2 specification
    (draft-ietf-dkim-dkim2-spec) and implement DKIM2-core support when
    the RFC reaches Proposed Standard. The milter deployment profile
    (draft-moccia-dkim2-deployment-profile) confirms our architecture is
    already the right target. See `ai/dkim2-readiness.md`.
11. **HTTP/Vault backend**: Provide an optional HTTP/HTTPS data set backend
    so that operators can integrate with secrets managers (Vault, Infisical,
    etc.) and LDAP/SQL systems via a thin HTTP bridge, without native
    directory or database drivers. See `ai/backend-extension-plan.md`.

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
| HTTP / HTTPS (`http:`, `https:`) | **New. Optional (`-DWITH_CURL=ON`).** GET-based key lookup against any HTTP endpoint. Bearer token auth. Covers secrets managers and LDAP/SQL bridge services. See `ai/backend-extension-plan.md`. |
| Vault (`vault:`) | **New. Optional (`-DWITH_CURL=ON`).** Convenience wrapper over `https:` that knows the HashiCorp Vault KVv2 JSON envelope and the `X-Vault-Token` header. See `ai/backend-extension-plan.md`. |

**Why no native LDAP or SQL drivers**: The original OpenLDAP code depended on
`libldap`, optional Cyrus SASL, and a BerkeleyDB caching layer (now gone).
The usage evidence across OpenDKIM's entire history traces to 2–3
organisations. OpenDBX is unmaintained. An HTTP bridge (a 50-line Python or
Go script) is the architecturally cleaner answer: it decouples the signing
daemon from directory service authentication complexity, can be written in
any language with mature DB/LDAP libraries, and the HTTP backend covers it
cleanly. Lua scripts (with OS-installed `luasql-*` or `lualdap`) cover the
use case when Lua is enabled.

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

**Crypto provider — OpenSSL 3 or LibreSSL, selectable**: PhoenixDKIM supports
building against either OpenSSL 3 or LibreSSL; both implement the OpenSSL 3 EVP
API this code uses. Neither is a lesser build target — the choice is exposed as
a first-class build option, `-DSSL_PROVIDER=auto|openssl|libressl` (default
`auto`, which uses whatever the system provides: OpenSSL on Linux, LibreSSL on
OpenBSD base). A non-default install of either is pointed to with
`-DSSL_ROOT_DIR=<prefix>`, so a LibreSSL build on an otherwise-OpenSSL Linux
host is fully supported. LibreSSL needs only a small compatibility header
(`libopendkim/openssl-compat.h`, mapping the OpenSSL 3 `EVP_PKEY_get_size`/
`EVP_PKEY_get_bits` spellings onto LibreSSL's legacy `EVP_PKEY_size`/
`EVP_PKEY_bits`) and a provider-aware version gate in the build system.

The two providers differ only in these factual respects, not in support tier:
- **Minimum versions:** OpenSSL ≥ 3.0.0; LibreSSL ≥ 3.7.0 (the first release
  with `EVP_PKEY_new_raw_public_key()` and working Ed25519, RFC 8463, which
  this fork mandates).
- **FIPS / crypto policy:** LibreSSL has **no FIPS mode** and is **not** subject
  to `update-crypto-policies`. The RHEL crypto-policy behaviour described below
  applies to the OpenSSL build only.
- **Default:** on Linux the system libcrypto is OpenSSL, so `auto` selects it
  there; OpenSSL is therefore the most widely deployed and exercised path, but
  not a privileged one.

**Algorithms supported:**
- RSA-SHA256 (required by RFC 6376) — minimum key size **2048 bits**
- Ed25519 (RFC 8463)

**RSA-SHA1**: Signing and verifying with RSA-SHA1 is **dropped entirely**.
SHA1 code stays in code base, because we must recognise rsa-sha1, so that
we can permfail the message with the appropriate comment.

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

**`pdkim` Lua module**: When `WITH_CURL` is also enabled, the Lua sandbox
exposes a built-in `pdkim` module providing `pdkim.http_get(url, opts)` —
a synchronous HTTP GET using libcurl, with optional Bearer token and timeout.
This allows Lua data set scripts to query Vault or any HTTP bridge without
OS-installed Lua packages. See `ai/backend-extension-plan.md`.

### Performance targets

The goal is for PhoenixDKIM to not be the bottleneck at any realistic mail
volume, and to remain competitive when DKIM2's higher per-message CPU
requirements arrive. Specific targets, all tracked in `ai/optimization-roadmap.md`:

**Body hash sharing.** When a message carries multiple signatures with the
same body canonicalization algorithm and length (e.g. dual-signing RSA-SHA256
and Ed25519 during key rotation, or DKIM1+DKIM2 during the transition
period), the body is hashed once and the digest shared. Currently each
`DKIM_CANON` instance runs a separate `EVP_DigestUpdate` pass over the full
body. This is the highest-impact optimization.

**Hot path cleanup.** The `sha_tmpbio` debug branch in `dkim_canon_write()`
executes a pointer load and conditional branch on every call — which fires
for every chunk of every message body fed to the hash. It must be
compile-time gated (`#ifdef DKIM_DEBUG`) or removed. This is pure overhead
with no production value.

**Pre-sized string buffers.** The DKIM-Signature header for RSA-SHA256 is
typically 400–700 bytes; Ed25519 is 250–350 bytes. The `dkim_dstring` used
to construct it starts small and doubles. Pre-allocating 512 bytes eliminates
2–4 reallocs per signed message.

**Ed25519 as the documented recommendation for high-volume deployments.**
RSA-3072 signing takes ~2–5 ms per message. Ed25519 signing takes ~0.05 ms.
For DKIM2, where a message to 50 recipients requires generating 51 signed
headers, this is a 40–100× difference. Documentation should steer
high-volume operators towards Ed25519 clearly and early.

### Security

PhoenixDKIM is written in C. C is memory-unsafe by default. It runs as a
daemon processing attacker-influenced data (email messages, DNS responses).
It is open source. Everyone now has access to LLM tools capable of
identifying exploitable patterns in C code given the source as input.

This changes the threat model: it is no longer sufficient to fix bugs when
reported. We must proactively find them first, faster than an attacker
would, using the same tools.

**Threat model — attack surfaces:**

| Surface | Risk class |
|---|---|
| DKIM-Signature header parsing | Buffer overflow, integer overflow, format string |
| DNS TXT record parsing | Oversized records, malformed tag=value, NUL injection |
| Message body canonicalisation | Off-by-one in CRLF handling, integer wraparound in `canon_remain` |
| Base64 decode (public keys, signature values) | Overlong input, invalid alphabet |
| Config file parsing | Path traversal in `KeyFile`/`SigningTable` values |
| opendkim-db.c backends | Injection via key value into Lua sandbox, HTTP URI, Redis prefix |
| Lua sandbox | Sandbox escape via upvalue manipulation or C API misuse |
| HTTP backend (new) | SSRF via attacker-influenced key values substituted into URI templates |

**Proactive audit cadence:**

A security-focused LLM review of the codebase is run on a regular schedule
(target: weekly, minimum: before every release). The process is documented
in `ai/security-audit-process.md` and includes:
- File-by-file review of all parsing and buffer manipulation code
- Review of every code path that handles externally-supplied data
- Review of threading primitives for race conditions and TOCTOU
- Tracking of all findings in a structured log with severity and disposition

**Static analysis and fuzzing:**
- The build must remain clean under `-Wall -Wextra -Wformat-security
  -Wformat-overflow -fstack-protector-strong` at all times.
- AddressSanitizer and UBSanitizer CI builds (`-DENABLE_SANITIZERS=ON`)
  catch use-after-free, buffer overreads, integer overflow, and undefined
  behaviour.
- Fuzzing targets for DKIM-Signature header parsing, DNS record parsing, and
  the opendkim-db URI parser are tracked in `ai/security-audit-process.md`.

**Defensive coding rules** (binding on all new code):
- Every `strlcpy`/`strlcat`/`snprintf` result must be checked or
  explicitly documented as truncation-safe.
- No `sprintf`, `strcpy`, `strcat`, `gets` anywhere.
- Every externally-supplied value that is substituted into a URI, log
  format, Lua string, or shell command must be validated and/or escaped
  before use.
- Every error path must free all in-flight allocations. Valgrind is the
  reference; the build must be leak-free under `ctest -T memcheck`.
- Signed/unsigned comparisons in bounds checks use the guarded-subtraction
  form: `buflen < N || (size_t)n > buflen - N`, never `(size_t)n + N > buflen`.

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
| OpenLDAP | LDAP directory lookups removed entirely. HTTP bridge is the replacement path. |
| tre (regex library) | Only used by `diffheaders` FFR. Both removed. |

### Data set backends to remove

| Backend | Reason |
|---|---|
| `bdb:` (BerkeleyDB) | Replaced by `lmdb:` |
| `dsn:` (SQL via OpenDBX) | OpenDBX unmaintained. SQL in a signing daemon is wrong architecture. Use HTTP bridge + `http:` backend. |
| `ldap:` / `ldaps:` / `ldapi:` | Native LDAP removed. Use HTTP bridge + `http:` backend, or Lua with `lualdap`. |

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
| OpenSSL 3 **or** LibreSSL 3.7+ | Required (one of) | Dynamically linked system library. Selected via `-DSSL_PROVIDER` (default `auto`); a non-default install is located with `-DSSL_ROOT_DIR`. OpenSSL minimum 3.0.0 (4.x supported); LibreSSL minimum 3.7.0. FIPS / crypto-policy applies to the OpenSSL build only. See Crypto section. |
| libmilter | Required | MTA filter protocol. Sendmail or Postfix libmilter. |
| LMDB | Required | Binary key/table storage backend. |
| libresolv | Required | DNS resolution. |
| Lua 5.4 | Optional (`-DWITH_LUA=ON`) | Data set scripts and policy hooks. Default OFF. |
| libcurl | Optional (`-DWITH_CURL=ON`) | Enables two features: (1) SMTP delivery for RFC 6651 failure reports (`SMTPURI`); (2) HTTP/HTTPS/Vault data set backends and `pdkim.http_get()` in the Lua sandbox. Minimum 7.20.0. Default OFF. |
| libbsd | Optional, auto-detected | Provides `strlcpy`/`strlcat` on older Linux. Not needed on FreeBSD/OpenBSD (in libc) or glibc 2.38+. |
| pthreads | Required | Thread support. |

### libbsd / strlcpy detection order (CMake)

1. Found in system libc (glibc 2.38+, FreeBSD, OpenBSD) — use directly.
2. Found via libbsd — link against it.
3. Neither found — compile bundled two-function implementation in `compat/strl.c`.

This ensures the build works on all target platforms without forcing a
dependency on any distribution package.

---

## Future Development — Active Roadmap

These items are out of scope for the current milestone but are on the active
roadmap with concrete plans. Each has a corresponding document in `ai/`.

### DKIM2-core

**Specification**: `draft-ietf-dkim-dkim2-spec` (active WG document, May 2026).
**Milter profile**: `draft-moccia-dkim2-deployment-profile` — explicitly
confirms that DKIM2-core is implementable via existing milter callbacks
without MTA core changes.

**What DKIM2-core adds** (DKIM1 infrastructure unchanged):
- `DKIM2-Signature` header (new; `DKIM-Signature` continues in parallel)
- Envelope binding: MAIL FROM and all RCPT TO addresses signed into the header
- Replay prevention: timestamp binding
- Chain of custody: forwarding MTAs that modify content add their own signature

**What DKIM2-core does NOT require**:
- New DNS record types (same `selector._domainkey.domain` structure)
- New key management infrastructure (same keys as DKIM1)
- Database backends (no new lookup complexity)

**Transition model**: Dual-signing (DKIM1-Signature + DKIM2-Signature on
every outgoing message) for several years. DKIM2 verifiers ignore
DKIM-Signature; DKIM1 verifiers ignore DKIM2-Signature. No flag day.
One program handles both; DKIM2 is an opt-in compile flag initially.

**DKIM2-extended** (body recipes, stateful intermediate signing) is explicitly
out of scope until the WG resolves the open design issues.

**When to implement**: When `draft-ietf-dkim-dkim2-spec` advances to Proposed
Standard and has a document shepherd and IESG date. Track the mailing list at
`ietf-dkim@ietf.org`. See `ai/dkim2-readiness.md`.

### Performance optimization

Tracked in `ai/optimization-roadmap.md`. Three items with clear implementation paths:

1. **Body hash sharing** (highest impact): Share the `EVP_MD_CTX` body hash
   across multiple signatures on the same message when they use the same
   canonicalization parameters. Currently each `DKIM_CANON` runs a separate
   pass. Directly enables efficient dual-signing for both DKIM1 key rotation
   and the DKIM1+DKIM2 transition period.

2. **`sha_tmpbio` removal** (zero-risk quick win): The debug BIO path in
   `dkim_canon_write()` runs a pointer load and branch on every body chunk.
   Wrap in `#ifdef DKIM_DEBUG` or remove entirely.

3. **Pre-sized signature buffer** (trivial): Pre-allocate 512 bytes for
   `dkim_dstring` when constructing the DKIM-Signature header. Eliminates
   2–4 reallocs per signed message.

### HTTP/HTTPS/Vault backend

Implementation plan in `ai/backend-extension-plan.md`. Summary:
- `http:` and `https:` URIs as data set backends, using existing `WITH_CURL`
  libcurl detection. Synchronous GET, Bearer token auth, 404 = miss.
- `vault:` URI as a convenience wrapper: translates to `https:`, adds
  `X-Vault-Token` header, extracts from KVv2 JSON envelope.
- `pdkim.http_get()` exposed to the Lua sandbox when both `WITH_LUA` and
  `WITH_CURL` are enabled.
- Type IDs: `http/https` = 13, `vault` = 14.

### Stats / metrics

If implemented, emit via StatsD or Prometheus, not a proprietary SQL schema.
Optional at compile time.

### ARC (Authenticated Received Chain)

RFC 8617. Related to but distinct from DKIM. Would be a new subsystem, not
built on `resign`. Out of scope until DKIM2 is implemented.

### DKIM failure reporting (RFC 6651)

Inherited from upstream and currently compiled in. RFC 6651 has essentially
zero deployed footprint (DMARC RUF supplanted it). Revisit: decide whether
to keep the popen/sendmail path, drop only the `SMTPURI` libcurl transport,
or remove the whole surface.

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
   build and all tests passing. The build must be warning-clean under
   `-Wall -Wextra -Wformat-security`.

9. **Do not invent scope.** If a file or feature is not mentioned in this
   document, ask before touching it.

10. **Security review on every change touching a parsing or buffer path.**
    Before committing any change to a function that handles externally-supplied
    data (message headers, DNS responses, config file values, URI parsing,
    base64 decode), feed the modified function and its callers to an LLM with
    the security audit prompt from `ai/security-audit-process.md` and address
    any findings. This is not optional.

11. **No unsafe string functions.** `sprintf`, `strcpy`, `strcat`, `gets` are
    banned. Use `strlcpy`, `strlcat`, `snprintf` with checked results. New
    code using a banned function will not be merged.

12. **Check all error paths for leaks.** Every function that allocates on
    entry must free on every error return. Use Valgrind or ASan to verify
    before committing.

---

*Last updated: May 2026. Human review required before any changes.*
