# Conformance Test Audit — t-conformance.c

Audited against: `SCOPE.md` (April 2026)
Source file: `libopendkim/tests/t-conformance.c`

---

## Global Issues

| Location | Classification | Reason |
|---|---|---|
| Lines 25-27: `#ifdef USE_GNUTLS` / `#include <gnutls/gnutls.h>` | **REVISE** | GnuTLS removed entirely per SCOPE.md |
| Lines 80-82: `gnutls_global_init()` in `make_lib()` | **REVISE** | GnuTLS removed entirely per SCOPE.md |

---

## RFC 6376 Section 3.3 — Signing and Verification Algorithms

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s3_3_rsa_sha1_roundtrip` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; SCOPE.md drops RSA-SHA1 signing. Should become a verify-only test using a pre-generated RSA-SHA1 signature to confirm legacy verification still works |
| `test_rfc6376_s3_3_rsa_sha256_roundtrip` | **KEEP** | Core in-scope algorithm |

## RFC 6376 Section 3.4 — Canonicalization

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s3_4_canon_simple_simple` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_canon_simple_relaxed` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_canon_relaxed_simple` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_canon_relaxed_relaxed` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_relaxed_hdr_ws_folding` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_simple_hdr_ws_strict` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_relaxed_body_trailing` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_4_crlf_fixing` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

## RFC 6376 Section 3.5 — Signature Field Tags

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s3_5_version_must_be_1` | **KEEP** | Verification-only; hardcoded `a=rsa-sha1` in malformed sig string is acceptable for error-path testing |
| `test_rfc6376_s3_5_missing_required_tags` | **KEEP** | Verification-only; tests syntax rejection of malformed signatures |
| `test_rfc6376_s3_5_expiration` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_5_body_length` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

## RFC 6376 Section 3.6 — Key Records

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s3_6_key_bad_version` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_6_key_bad_type` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_6_key_revoked` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s3_6_key_bad_hash` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

## RFC 6376 Section 5.4 — Header Field Signing

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s5_4_from_must_be_signed` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

## RFC 6376 Section 6 — Verifier Actions

| Test | Classification | Reason |
|---|---|---|
| `test_rfc6376_s6_no_signature` | **KEEP** | No crypto dependency |
| `test_rfc6376_s6_tampered_body` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s6_tampered_header` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_rfc6376_s6_multiple_signatures` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

## API Conformance Tests

| Test | Classification | Reason |
|---|---|---|
| `test_api_init_close` | **KEEP** | No crypto dependency |
| `test_api_getmode` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_getid` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_margin_and_partial` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_signer` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_user_context` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_getresultstr` | **KEEP** | No crypto dependency |
| `test_api_sig_geterrorstr` | **KEEP** | No crypto dependency |
| `test_api_libversion` | **KEEP** | No crypto dependency |
| `test_api_libfeature` | **KEEP** | No crypto dependency |
| `test_api_sig_syntax` | **KEEP** | Syntax validation only; `a=rsa-sha1` in string is acceptable for parse testing |
| `test_api_key_syntax` | **KEEP** | No algorithm-specific code |
| `test_api_options` | **KEEP** | No crypto dependency |
| `test_api_mail_parse` | **KEEP** | No crypto dependency |
| `test_api_qp_decode` | **KEEP** | No crypto dependency |
| `test_api_sig_accessors` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_minbody` | **KEEP** | Verification-only; hardcoded `a=rsa-sha1` in string is acceptable for l= tag testing |
| `test_api_getsighdr_d` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_xtag` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |
| `test_api_chunk` | **REVISE** | Signs with `DKIM_SIGN_RSASHA1`; change to `DKIM_SIGN_RSASHA256` |

---

## Summary

| Classification | Count |
|---|---|
| **KEEP** | 15 tests |
| **REVISE** | 30 (28 tests + 2 global GnuTLS blocks) |
| **REMOVE** | 0 |

Total tests in file: 43 (15 KEEP + 28 REVISE).

No tests reference out-of-scope subsystems (VBR, RBL, stats, BerkeleyDB,
LDAP, SQL/OpenDBX, reputation, GnuTLS-specific logic, AWS-LC, tre/diffheaders,
ATPS). The file is clean of deleted-subsystem contamination.

The dominant revision theme is mechanical: 27 of 28 test revisions are the
same change — replace `DKIM_SIGN_RSASHA1` with `DKIM_SIGN_RSASHA256` in
signing calls (note: the 4 canonicalization combo tests all call through
`test_canon_combo`, so the actual code change is in one place for those 4).
The RSA-SHA1 round-trip test requires a structural change to become a
verify-only test.

---

## Missing RFC 6376 Coverage

The following in-scope behaviours have no test coverage in `t-conformance.c`:

### Algorithms (Section 3.3 / SCOPE.md)

- **Ed25519 (RFC 8463) sign/verify round-trip** — SCOPE.md lists Ed25519 as a supported algorithm; no test exists
- **RSA-SHA1 signing refusal** — SCOPE.md mandates that signing with RSA-SHA1 is rejected with a hard error; no test confirms this
- **RSA-SHA1 verification with warning** — SCOPE.md retains RSA-SHA1 verification for interop but requires a warning; no test for warning/weak-result behaviour
- **RSA key size enforcement on signing** — SCOPE.md requires minimum 2048-bit keys for signing with a hard error; no test exists
- **RSA key size enforcement on verification** — SCOPE.md specifies sub-2048-bit keys produce a warning/weak-fail on verification (configurable); no test exists

### Canonicalization (Section 3.4)

- **Simple body canonicalization trailing blank lines** — RFC 6376 Section 3.4.3 specifies that simple body canon ignores trailing empty lines; no dedicated test (only relaxed body trailing is tested)
- **Empty body hash** — RFC 6376 Section 3.4.3/3.4.4 define specific body hashes for empty bodies under both canonicalization methods; no test exists

### Signature Tags (Section 3.5)

- **i= tag (AUID) domain matching** — RFC 6376 Section 3.5 requires that the i= domain must be the same as or a subdomain of d=; no test validates this constraint
- **q= tag handling** — RFC 6376 Section 3.5 defines the query method tag; no test for unknown or unsupported q= values
- **t= tag (timestamp) in the future** — No test for timestamp-in-the-future handling
- **z= tag (copied header fields)** — RFC 6376 Section 3.5 defines diagnostic copied headers; no test exists

### Key Records (Section 3.6)

- **Key with s= (service type) mismatch** — RFC 6376 Section 3.6.1 allows keys to restrict service type via s= tag; no test for `s=email` restriction or mismatch
- **Key with t=y (testing mode)** — RFC 6376 Section 3.6.1 defines the testing flag; no test exists
- **Key with t=s (strict domain match)** — RFC 6376 Section 3.6.1 defines strict mode requiring exact i=/d= domain match; no test exists

### Header Field Signing (Section 5.4)

- **Oversigning (duplicate h= entries)** — RFC 6376 Section 5.4 allows listing a header field name more than once in h= to protect against header addition attacks; no test exists
- **Header field ordering** — RFC 6376 Section 5.4 specifies bottom-up matching of h= entries against headers; no test validates correct ordering behaviour

### Verifier Actions (Section 6)

- **DNS TEMPFAIL handling** — RFC 6376 Section 6.1.2 specifies that DNS timeouts or server failures produce TEMPFAIL; no test exists
- **DNS NXDOMAIN handling** — RFC 6376 Section 6.1.2 specifies that missing key records produce PERMFAIL; no test exists
- **Unknown algorithm (a= tag) rejection** — RFC 6376 Section 6.1.2 requires that unrecognised algorithms cause signature failure; no test exists
- **Multiple signatures with mixed results** — RFC 6376 Section 6.1 requires all signatures to be evaluated; no test verifies correct handling when one passes and one fails
