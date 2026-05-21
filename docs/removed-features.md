# Removed Features

`PhoenixDKIM` 3.0 narrows the scope of the upstream
[trusteddomainproject/OpenDKIM](https://github.com/trusteddomainproject/OpenDKIM)
tree to its DKIM core, retiring subsystems and build paths whose
external dependencies are no longer maintained, or whose use cases
have been overtaken by better-fitting tools elsewhere in the modern
mail stack.

The original code remains available in the upstream repository for
anyone who needs it. This document records each removal with the
reasoning behind the call, so that future contributors can understand
the shape of the project as it stands today. The scope decisions
originate in `SCOPE.md`; this is the user-facing version.

---

## Crypto

### GnuTLS

A complete second crypto backend, selectable in the autotools build
via `--with-gnutls`. Every signing, verifying, and hashing operation
in libopendkim had a parallel GnuTLS implementation kept in lockstep
with the OpenSSL path.

**Reasoning:**

- The modernisation target for this fork is the OpenSSL 3 EVP API.
  Keeping a second backend in sync would split maintenance effort
  between two crypto libraries that the project does not need to
  support simultaneously.
- OpenSSL 3 is widely available and is now an unconditional
  dependency.

See `docs/crypto-policy.md` for the interaction with hardened crypto
policies on RHEL-family distros.

### RSA-SHA1 signing

`rsa-sha1` has been removed from the signing-algorithm table.
Verification of RSA-SHA1 signatures is retained so that mail signed
by older signers still in operation can still be verified.

**Reasoning:**

- SHA1 is no longer collision-resistant by current standards.
- RFC 8301 (2018) deprecated `rsa-sha1` for DKIM signing.

---

## Database / data-set backends

### BerkeleyDB (`bdb:` / libdb)

The binary key-table backend (`bdb:` URI prefix in `KeyTable` /
`SigningTable` etc.).

**Reasoning:**

- Upstream Oracle BerkeleyDB has had no public release in years, and
  its 2013 licence change to AGPL led most Linux distributions to move
  away from it. Some have dropped the package entirely.
- LMDB is a good fit for the same role: crash-safe, single-file,
  memory-mapped, and actively maintained. It replaces BDB as the
  binary backend (`lmdb:`).

### QUERY_CACHE (internal DNS-result cache)

A libopendkim-internal cache layer in front of `dkim-keys.c`'s
TXT-record lookups. Signed key data was stored in a local BerkeleyDB
hash file so that repeated verifications wouldn't re-query DNS.

**Reasoning:**

- The implementation is BerkeleyDB-only at the source level (`<db.h>`,
  `DB *`, `db_create`, `DB_VERSION_CHECK`). With BDB itself removed,
  the natural follow-on is to remove the cache that depended on it.
- A recursive (or stub-to-recursive) DNS resolver caches TXT-record
  answers at the DNS layer with the right semantics for the job, so
  losing this in-process cache should not change observable behaviour
  in a normally-configured deployment.

The public APIs `dkim_flush_cache` and `dkim_getcachestats`, and the
`DKIM_LIBFLAGS_CACHE` flag, are removed from `dkim.h` alongside the
feature.

### OpenDBX (`dsn:` SQL backend)

A SQL abstraction layer fronting MySQL/MariaDB/PostgreSQL/SQLite
through a single `dsn:` URI scheme.

**Reasoning:**

- `libopendbx` is no longer actively maintained upstream.
- Holding an SQL connection pool inside a per-message milter couples
  mail flow to database availability in a way that flat-file or LMDB
  key tables avoid. For the multi-instance / shared-state cases that
  motivated the SQL backend, this fork adds first-class Redis
  support, which is a closer fit operationally.

### OpenLDAP (`ldap:` / `ldaps:` / `ldapi:`)

LDAP directory lookup for key tables and signing tables, including
the `LDAPSoftStart` and `LDAPDisableCache` configuration options.

**Reasoning:**

- Same coupling concern as SQL: directory binds in the message path
  add a runtime dependency on the directory server.
- The deployment patterns LDAP supported (centralised tenant key
  lookup, dynamic policy) can be expressed via Lua hooks or Redis
  with less operational overhead.

---

## DKIM-adjacent subsystems

### VBR (Vouch By Reference)

RFC 5518. Allowed a sending domain to assert that a third-party
"voucher" endorses its mail. Implemented as the `libvbr/` library
plus daemon wiring.

**Reasoning:**

- VBR did not see significant deployment in the years following its
  publication, and the reputation/voucher ecosystem that would have
  given it teeth never materialised at scale.
- Maintaining the implementation absent a deployment story is hard
  to justify when the project is scoping down to DKIM.

### ATPS (Authorized Third-Party Signatures)

RFC 6541 (Experimental). A mechanism for a domain to delegate signing
authority to a named third party.

**Reasoning:**

- ATPS remained Experimental and did not attract production
  deployment.
- The broader problem ATPS addressed — preserving authentication
  across mailing lists and other intermediaries that legitimately
  modify mail — is still unsettled in the standards community. ARC
  (RFC 8617) has been deployed but has its own trade-offs, and DKIM2
  is in development. This fork's position is to wait for the dust to
  settle rather than carry a third experimental mechanism alongside
  the DKIM core.

### RBL (Realtime Blacklist lookups)

`librbl/` and the associated daemon glue, which consulted DNSBLs as
part of message disposition.

**Reasoning:**

- DNSBL evaluation fits more naturally in the MTA's policy stage
  (postfix policy daemons, smtpd restrictions, opendmarc-style
  rejection logic) than inside a DKIM signing daemon. Keeping it in
  opendkim duplicates functionality available elsewhere.

### Reputation subsystems (`reputation/`, `reprrd/`)

Two collaborative-reputation systems: one rrdtool-backed, one feeding
an aggregation backend with per-sender data.

**Reasoning:**

- Both were Experimental and did not graduate to a production
  feature.
- The aggregation backend they fed did not see wide adoption.

### Stats subsystem

Per-message statistics emitted via SQL to an aggregation server.

**Reasoning:**

- The aggregation server is no longer running upstream.
- The SQL backend it depended on has been removed (see OpenDBX
  above).
- A future telemetry story should probably emit StatsD or Prometheus,
  rather than write rows to a project-specific schema.

---

## FFR (Future Feature Release) flags

The upstream tree used `_FFR_*` preprocessor guards to ship code for
features that were under development or that the maintainers wanted
available as opt-in build-time experiments. As this fork has narrowed
its scope to the DKIM core, those experiments either tied into
subsystems that are no longer present (SQL, LDAP, stats, ATPS, VBR,
diffheaders), or addressed concerns that belong in another layer
(rate limiting), or were small parser/identity tweaks that did not
graduate to defaults. In each case the guarded code has been removed
along with the surrounding subsystem rather than kept as conditional
code without a way to turn it on.

Removed FFRs include `_FFR_RESIGN`, `_FFR_IDENTITY_HEADER`,
`_FFR_SENDER_MACRO`, `_FFR_ATPS`, `_FFR_VBR`, `_FFR_STATS`,
`_FFR_STATSEXT`, `_FFR_DB_HANDLE_POOLS`, `_FFR_LDAP_CACHING`,
`_FFR_POSTGRES_RECONNECT_HACK`, `_FFR_RATE_LIMIT`, `_FFR_SOCKETDB`,
`_FFR_DEFAULT_SENDER`, `_FFR_DIFFHEADERS`.

### diffheaders / tre

A header-diffing diagnostic helper using the `tre` regex library to
show which header bytes a signer touched.

**Reasoning:**

- A useful debugging aid, but not on the signing/verification path.
- `tre` itself is no longer actively maintained, and was the only
  dependency on it in this tree. With diffheaders removed, the
  dependency can go with it.

### Other FFR flags

The remaining FFR removals are recorded in their individual removal
commits — `git log --grep=_FFR_` lists them.

---

## Build system

### Autotools (autoconf + automake + libtool)

**Reasoning:**

- Replaced by CMake + CTest once the new build reached test parity on
  Debian and Arch.
- The autotools build remains in the upstream repository for anyone
  who needs to compare or to retrieve it.

### `libar/` (async DNS resolver)

The internal asynchronous DNS resolver.

**Reasoning:**

- Already deprecated and effectively retired in opendkim 2.x.
- libunbound (optional, `-DWITH_UNBOUND=ON`) covers DNSSEC-aware
  resolution; the system stub resolver covers the rest.

---

## What this fork keeps

For balance, the components that remain:

- DKIM signing and verification (the core of the project).
- Lua 5.4 policy scripting (`-DWITH_LUA=ON`).
- libunbound DNSSEC resolution (`-DWITH_UNBOUND=ON`).
- The `file:` / `refile:` / `csl:` / `lmdb:` / `redis:` / `lua:` data
  set backends.
- The milter integration (libmilter from Sendmail or as a standalone
  package).
