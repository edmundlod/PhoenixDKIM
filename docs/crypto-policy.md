# SHA1 and System Crypto Policies

## Background

opendkim-ng **drops RSA-SHA1 signing** — new signatures use RSA-SHA256 or
Ed25519 — but **retains RSA-SHA1 verification** for interoperability.  A
significant volume of mail in the wild is still signed with RSA-SHA1 (RFC 6376
Section 3.3.1), and a verifying MTA that rejects or ignores those signatures
would silently treat legitimate mail as unsigned.  SHA1 verification is therefore
kept intentionally.

## What Are System Crypto Policies?

Several distributions ship a system-wide cryptographic policy framework that
controls which algorithms OpenSSL (and other TLS/crypto libraries) will accept
at runtime, independent of any compile-time configuration.

| Platform | Policy tool | Config file |
|---|---|---|
| RHEL 9+ / AlmaLinux 9+ / Rocky Linux 9+ | `update-crypto-policies` | `/etc/crypto-policies/config` |
| Fedora 38+ | `update-crypto-policies` | `/etc/crypto-policies/config` |
| CentOS Stream 9+ | `update-crypto-policies` | `/etc/crypto-policies/config` |

On these systems the **DEFAULT** policy disables SHA1 for digital signature
operations (signing and verification alike).  The intent is to prevent SHA1
from being used in new TLS certificates; the side-effect is that it also
prevents verifying *existing* DKIM signatures that use RSA-SHA1.

Debian, Ubuntu, FreeBSD, and OpenBSD do not ship this framework.  SHA1
signature verification is available there unless someone has manually
edited `/etc/ssl/openssl.cnf`.

## Symptoms

### At configure time

CMake emits a `WARNING` during `cmake -B build`:

```
SHA1 RSA signature verification is disabled by the current OpenSSL/system
configuration. ...approximately 26 libopendkim tests...will FAIL.
```

### In the test suite

Running `ctest --test-dir build` will show approximately 26 failures, all in
`libopendkim/tests/`.  Every failing test verifies a message that was signed
with RSA-SHA1 in the test fixture data.  Tests that use RSA-SHA256 or Ed25519
are unaffected.

### In production

The filter will report incoming RSA-SHA1-signed mail as having a key-decode
error (`DKIM_SIGERROR_KEYDECODE`) rather than a bad-signature error.  The
signature is treated as failed, which is the same practical outcome a strict
verifier would apply anyway — but the diagnostic is misleading.

## Enabling SHA1 for the Test Suite (RHEL/Fedora)

The recommended approach is a scoped subpolicy that adds SHA1 to the DEFAULT
policy without downgrading anything else:

```sh
sudo update-crypto-policies --set DEFAULT:SHA1
```

After changing the policy you **must** reconfigure CMake so the cached probe
result is refreshed:

```sh
rm build/CMakeCache.txt        # or delete the whole build directory
cmake -B build
ctest --test-dir build
```

Restore the default when done:

```sh
sudo update-crypto-policies --set DEFAULT
rm build/CMakeCache.txt
cmake -B build
```

The full `LEGACY` policy also works but is broader than necessary:

```sh
sudo update-crypto-policies --set LEGACY
```

## Enabling SHA1 in Production (RHEL/Fedora)

If you want the running filter to verify RSA-SHA1-signed mail, the same
`DEFAULT:SHA1` subpolicy applies to the whole system.  Alternatively, you can
scope the override to the opendkim process by setting the `OPENSSL_CONF`
environment variable to point at a custom `openssl.cnf` that re-enables SHA1,
and running opendkim with that variable set.

## Other Platforms

On systems without `update-crypto-policies`, SHA1 for signature operations is
typically controlled by the `[system_default_sect]` block in `openssl.cnf`
(often `/etc/ssl/openssl.cnf` or `/usr/lib/ssl/openssl.cnf`).  Look for a
`MinProtocol` or `CipherString` setting that may be excluding legacy hash
algorithms.

On stock Debian, Ubuntu, FreeBSD, and OpenBSD installations no adjustment
should be necessary.

## Why Not Remove SHA1 Verification?

Removing SHA1 verification would mean silently treating all mail signed with
RSA-SHA1 as unsigned.  For an MTA that uses the DKIM result to make
delivery decisions, this is a material correctness issue.  The right long-term
solution is for senders to migrate to RSA-SHA256 or Ed25519; in the meantime,
the verifier needs to handle what it actually receives.

If your deployment policy mandates rejecting RSA-SHA1 signatures, you can
achieve that through a policy script (Lua hook) or by configuring opendkim to
require a minimum algorithm strength, rather than by removing the verification
capability from the library.
