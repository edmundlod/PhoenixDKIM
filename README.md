# PhoenixDKIM

PhoenixDKIM is a modernised, somehwat OpenDKIM-compatible (see Removed section
below) DKIM signing and verification daemon, focused on security, correctness,
and modern platform support. It originated as a fork of
[trusteddomainproject/OpenDKIM](https://github.com/trusteddomainproject/OpenDKIM)
and is a drop-in replacement for existing OpenDKIM deployments.

## What's New in 3.0

- **OpenSSL 3+** — all cryptography ported to the EVP high-level API
- **Ed25519** — signing and verification per RFC 8463
- **LMDB** — replaces unmaintained BerkeleyDB for key storage
- **CMake** — replaces autoconf/automake
- **Lua 5.4** — updated from Lua 5.1
- RSA-SHA1 signing and verifying dropped per RFC 8301 sub 3.1
- Minimum RSA signing key size: 2048 bits (this is deliberately chosen in
  PhoenixDKIM - RFC 8301 allows 1024 bits)

## Removed from pre-fork OpenDKIM 2.11.0-beta2 (d.d. 15-NOV-2018)

Removed: VBR, ATPS, RBL, reputation subsystems, LDAP, SQL/OpenDBX,
  GnuTLS, BerkeleyDB (and its `QUERY_CACHE` DNS-result cache),
  `diffheaders` (tre dependency).
See [docs/removed-features.md](docs/removed-features.md) for the
rationale behind each.

## Dependencies
To build the library and filter you will need:

- A C17-capable compiler (GCC 8+ or Clang 5+)
- CMake >= 3.20
- OpenSSL >= 3.0
- LMDB
- libmilter (from Sendmail or as a standalone package)
- libresolv

Optional:

- Lua 5.4+ — policy scripting hooks (`-DWITH_LUA=ON`)
- libunbound — DNSSEC-aware DNS resolution (`-DWITH_UNBOUND=ON`)
- libcurl >= 7.20.0 — SMTP report delivery via the `SMTPURI` config option (`-DWITH_CURL=ON`)
- hiredis or libvalkey — Redis/Valkey signing-table backend (`-DWITH_REDIS=ON`)
- libsystemd — `Type=notify` readiness signalling and watchdog (`-DWITH_SYSTEMD`; auto-detected on Linux)
- libbsd — provides `strlcpy`/`strlcat` on systems without them
  (not needed on glibc 2.38+, FreeBSD, or OpenBSD)

### Debian / Ubuntu

```
apt install build-essential cmake libssl-dev liblmdb-dev \
            libmilter-dev liblua5.4-dev
# optional
apt install libcurl4-openssl-dev libhiredis-dev libsystemd-dev
```

### RHEL / AlmaLinux / Rocky

```
dnf install gcc cmake openssl-devel lmdb-devel sendmail-devel lua-devel
# optional
dnf install libcurl-devel hiredis-devel systemd-devel
```

### FreeBSD

```
pkg install cmake openssl lmdb milter lua54
# optional
pkg install curl hiredis
```

## Building

```
cmake -B build
cmake --build build
ctest --test-dir build
```
Common build options:

| Option | Default | Description |
|---|---|---|
| `-DWITH_LUA=ON` | OFF | Enable Lua 5.4 policy scripting |
| `-DWITH_UNBOUND=ON` | ON | Enable libunbound DNSSEC resolver |
| `-DWITH_CURL=ON` | OFF | Enable libcurl SMTP report delivery (`SMTPURI`) |
| `-DWITH_REDIS=ON` | OFF | Enable Redis/Valkey signing-table backend |
| `-DWITH_SYSTEMD=AUTO` | AUTO | systemd `sd_notify` readiness/watchdog: `AUTO` detects, `ON` requires it (configure fails if libsystemd is absent), `OFF` disables |
| `-DINSTALL_SYSTEMD_UNIT=ON` | ON on Linux | Install the generated `opendkim.service` (its `Type=`/`WatchdogSec` match the build) |
| `-DCMAKE_BUILD_TYPE=Release` | `RelWithDebInfo` | Build type (Debug/Release/RelWithDebInfo/MinSizeRel) |

To install:

```
cmake --install build
```

## Configuration

See `opendkim.conf(5)` for the full list of configuration options.
A sample configuration file, which needs editing, is installed at
`/usr/share/doc/phoenixdkim/opendkim.conf.sample`.

For an example on using multiple signatures per e-mail (e.g. Ed25519 with
an RSA key as fall-back), see `docs/multisigning.md`.

The filter integrates with Postfix and Sendmail via the milter protocol.
For Postfix, add to `main.cf`:

```
smtpd_milters = unix:/run/opendkim/opendkim.sock
non_smtpd_milters = unix:/run/opendkim/opendkim.sock
milter_default_action = accept (or: tempfail)
```

The systemd service unit is generated from `contrib/systemd/opendkim.service.in`
at build time (so its `Type=`/`WatchdogSec` match what was compiled) and
installed by `make install`; the Debian package ships its own unit in `debian/`.

## Key Generation

_Note: Run the following in the directory where you want your keys, e.g.
`/etc/dkimkeys/domain.com/`, or move the files after generating them._

Generate an RSA-2048 or Ed25519 signing keypair with `opendkim-genkey`:

```
# RSA
opendkim-genkey -b 2048 -d domain.com -s selector

# Ed25519
opendkim-genkey -t ed25519 -d domain.com -s selector
```

## Platforms

- Linux (glibc 2.17+)
- FreeBSD 13+
- OpenBSD 7+

## Documentation

Man pages are installed for `opendkim(8)`, `opendkim.conf(5)`,
`opendkim-genkey(8)`, `opendkim-genzone(8)`, `opendkim-testkey(8)`,
`opendkim-testmsg(8)`, and `opendkim-lua(3)`.

RFC and draft reference documents are in the `docs/` directory.

## Known Runtime Issues

### WARNING: symbol 'X' not available

The filter attempted to read an MTA macro that the MTA did not provide.
For Postfix, ensure the relevant macros are configured. For Sendmail,
regenerate `sendmail.cf` from your M4 configuration.

### MTA Timeouts

DNS queries for key records may exceed the default MTA milter timeout.
Increase `milter_timeout` in Postfix, or the milter timeout in Sendmail
if you encounter this.

### EVP key decode failures

A public key record was retrieved but could not be decoded. Possible
causes: memory exhaustion, or a corrupted or malformed key record in
DNS. If using tempfail mode the sender will retry; a repeated failure
indicates a problem with the published key.

### Sendmail Header Rewriting

If you use Sendmail's `MASQUERADE_AS` or `FEATURE(genericstable)`,
opendkim signs headers before Sendmail rewrites them. The verifying
side will see rewritten headers that do not match the signature.
Solutions: disable the rewriting features, use a two-MTA setup where
the signing MTA does no rewriting, or use multiple `DaemonPortOptions`
entries to separate rewriting from signing.

## Origin

> Note that as per May 2026 it seems that OpenDKIM is getting updates again,
> currently in the 'develop' branch. Perhaps a new release is in the making!

OpenDKIM had seen no meaningful upstream development for years, yet remained
widely deployed. Rather than abandon it or switch to an alternative, I decided
to fork it — to continue using a tool I relied on, updated and hardened to the
standard an internet-facing daemon handling email deserves.

The work focused on what matters for a long-lived, security-sensitive daemon:

- Removed obsolete and unmaintained subsystems (VBR, ATPS, RBL, LDAP, GnuTLS,
  BerkeleyDB, and others) — less code means fewer vulnerabilities and an easier
  codebase to reason about
- Modernised cryptography: ported to the OpenSSL 3 EVP API, added Ed25519
  signing and verification
- Replaced the autoconf/automake build system with CMake
- Updated the systemd unit files to current best practices
- Hardened the build (compiler warnings, sanitisers, security flags) and fixed
  the bugs they exposed
- Security-audited the daemon and library code, with assistance from AI tooling

The project was originally named *opendkim-ng*. It was renamed to PhoenixDKIM
to avoid confusion with the upstream trusteddomainproject/OpenDKIM project,
which after a long period of inactivity has indicated plans to resume active
development.

## Licence

The licence for this package is in the `LICENSE` file. Portions of
the code originating from Sendmail are covered by the Sendmail Open
Source Licence, found in `LICENSE.Sendmail`. See the copyright notice
in each source file for which licence(s) apply.

## Legal notice
A number of legal regimes restrict the use or export of cryptography.
If you are potentially subject to such restrictions you should seek legal
advice before using, developing, or distributing cryptographic code.

## Bugs and Contributions

Please report bugs and submit contributions via GitHub:

https://github.com/edmundlod/PhoenixDKIM
