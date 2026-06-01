# libopendkim

C library implementing the DKIM specification (RFC 6376) including signing,
verification, canonicalisation, and key parsing.

## Crypto

libopendkim uses **OpenSSL 3** exclusively, via the EVP high-level API
(`EVP_DigestSign*`, `EVP_DigestVerify*`, `EVP_PKEY_*`). GnuTLS support
has been removed. There is no compile-time choice of crypto backend.

OpenSSL is dynamically linked against the system library. This means
security patches to OpenSSL are applied via the OS package manager
without rebuilding libopendkim.

**Supported algorithms:**

- RSA-SHA256 (required by RFC 6376) — minimum key size 2048 bits
- Ed25519-SHA256 (RFC 8463)

RSA-SHA1 signing is not supported. RSA-SHA1 verification is retained for
compatibility with legacy signed mail.

## Initialisation

libopendkim does not initialise the crypto library for you. The calling
application must call `OPENSSL_init_crypto()` (or otherwise initialise
OpenSSL) before any DKIM signing or verification operation.

## Environment Variables

| Variable     | Description |
|---|---|
| `DKIM_TMPDIR` | Directory for temporary files. Default: `/tmp` |

## Self-Tests

Run the library unit tests with:

```
ctest --test-dir build
```

To run only library tests:

```
ctest --test-dir build -R libopendkim
```

## API Documentation

HTML API documentation is in the `docs/` directory of the source tree.
