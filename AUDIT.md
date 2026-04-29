# libopendkim Crypto Audit — OpenSSL 1.x → OpenSSL 3 EVP

Audited against: `SCOPE.md` (April 2026)
Scope of this audit: `libopendkim/*.c` and `libopendkim/*.h` only.
Out of scope: `opendkim/` daemon, `libopendkim/tests/`, GnuTLS code paths
(those are deleted, not ported, per SCOPE.md).

This document is the inventory and ordered porting plan for the next
session. **No code changes were made in producing this audit.**

---

## 1. Files in scope

| File | Crypto present? | Notes |
|---|---|---|
| `dkim.c` | YES | Privkey load, sign, verify, init/cleanup, free, error queue, version reporting, hash-tmpfd accessor |
| `dkim-canon.c` | YES | SHA-1 / SHA-256 hashing for header + body canonicalization |
| `dkim-test.c` | YES | `dkim_test_key()` — load PEM private key, derive public key, byte-compare against published key |
| `dkim-types.h` | YES (definitions only) | `struct dkim_sha1`, `struct dkim_sha256`, `struct dkim_rsa` — embed `RSA *`, `SHA_CTX`, `SHA256_CTX`, `BIO *`, `EVP_PKEY *`. Top-of-file includes `<openssl/rsa.h>` etc. |
| `dkim-atps.c` | YES | **OUT OF SCOPE THIS SESSION** — ATPS subsystem is permanently removed (SCOPE.md). File is to be deleted in a separate cleanup session. Do not port. |
| `base32.c` | YES (test-only) | `SHA1_*` calls live inside `#ifdef TEST` test main(). Not part of the library binary. **Defer**; will be addressed when test infra is reorganised or when the file is restructured. |
| `base64.c`, `dkim-cache.c`, `dkim-dns.c`, `dkim-keys.c`, `dkim-mailparse.c`, `dkim-report.c`, `dkim-tables.c`, `dkim-util.c`, `util.c` | NO | No crypto. Not touched. |

GnuTLS `#ifdef USE_GNUTLS` blocks: SCOPE.md says "delete, not ifdef". They
are not part of this crypto port — they are the next session's cleanup.
Where this audit shows a line number inside such a block, the porting
work happens on the OpenSSL `#else` branch only; the GnuTLS branch is
left untouched here and removed wholesale later.

---

## 2. API call inventory

Each row is one call site that must change. "→" shows the OpenSSL 3 EVP
replacement. Comments and string literals are not listed.

### 2.1 Hashing — `dkim-canon.c`

All sites work on `struct dkim_sha1` / `struct dkim_sha256` (defined in
`dkim-types.h`). Both must collapse to a single `struct dkim_sha` carrying
an `EVP_MD_CTX *` and a digest output buffer sized to `EVP_MAX_MD_SIZE`,
plus the existing `tmpfd` / `tmpbio` mirroring fields.

| Line | Function | Old call | Replacement |
|---|---|---|---|
| 126 | `dkim_canon_free` | `BIO_free(sha1->sha1_tmpbio)` | unchanged (BIO is not deprecated; OpenSSL 3 retains the BIO API). Add `EVP_MD_CTX_free(sha->sha_mdctx)`. |
| 143 | `dkim_canon_free` | `BIO_free(sha256->sha256_tmpbio)` | merged into single `dkim_sha` case after struct unification |
| 224 | `dkim_canon_write` | `SHA1_Update(&sha1->sha1_ctx, buf, buflen)` | `EVP_DigestUpdate(sha->sha_mdctx, buf, buflen)` |
| 227 | `dkim_canon_write` | `BIO_write(sha1->sha1_tmpbio, buf, buflen)` | unchanged (BIO retained) |
| 238 | `dkim_canon_write` | `SHA256_Update(&sha256->sha256_ctx, buf, buflen)` | merged with SHA1 case after unification |
| 241 | `dkim_canon_write` | `BIO_write(sha256->sha256_tmpbio, buf, buflen)` | unchanged |
| 717 | `dkim_canon_init` | `SHA1_Init(&sha1->sha1_ctx)` | `EVP_MD_CTX_new()` + `EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)` |
| 729 | `dkim_canon_init` | `BIO_new_fd(fd, 1)` | unchanged |
| 753 | `dkim_canon_init` | `SHA256_Init(&sha256->sha256_ctx)` | `EVP_MD_CTX_new()` + `EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)` |
| 765 | `dkim_canon_init` | `BIO_new_fd(fd, 1)` | unchanged |
| 1427 | `dkim_canon_runheaders` | `SHA1_Final(sha1->sha1_out, &sha1->sha1_ctx)` | `EVP_DigestFinal_ex(sha->sha_mdctx, sha->sha_out, &sha->sha_outlen)` |
| 1430 | `dkim_canon_runheaders` | `BIO_flush(sha1->sha1_tmpbio)` | unchanged |
| 1441 | `dkim_canon_runheaders` | `SHA256_Final(sha256->sha256_out, &sha256->sha256_ctx)` | merged with SHA1 case |
| 1444 | `dkim_canon_runheaders` | `BIO_flush(sha256->sha256_tmpbio)` | unchanged |
| 1565 | `dkim_canon_signature` | `SHA1_Final(...)` | as above |
| 1568 | `dkim_canon_signature` | `BIO_flush(...)` | unchanged |
| 1579 | `dkim_canon_signature` | `SHA256_Final(...)` | as above |
| 1582 | `dkim_canon_signature` | `BIO_flush(...)` | unchanged |
| 2000 | `dkim_canon_closebody` | `SHA1_Final(...)` | as above |
| 2003 | `dkim_canon_closebody` | `BIO_flush(...)` | unchanged |
| 2014 | `dkim_canon_closebody` | `SHA256_Final(...)` | as above |
| 2017 | `dkim_canon_closebody` | `BIO_flush(...)` | unchanged |
| 2077 | `dkim_canon_getfinal` | `*digest = sha1->sha1_out; *dlen = sizeof sha1->sha1_out;` | `*digest = sha->sha_out; *dlen = sha->sha_outlen;` (size now runtime-known from `EVP_DigestFinal_ex`) |
| 2089 | `dkim_canon_getfinal` | `*digest = sha256->sha256_out; *dlen = sizeof sha256->sha256_out;` | merged |

### 2.2 Hashing — `dkim.c` (struct field accessor only)

| Line | Function | Old | Replacement |
|---|---|---|---|
| 7173, 7180 | `dkim_sig_getreportinfo` | reads `sha1->sha1_tmpfd` | reads `sha->sha_tmpfd` after struct unification |
| 7191, 7198 | `dkim_sig_getreportinfo` | reads `sha256->sha256_tmpfd` | merged |

### 2.3 Header includes — `dkim-types.h`

Lines 32–39 (the `#else /* USE_GNUTLS */` branch):

```c
# include <openssl/pem.h>
# include <openssl/rsa.h>      ← drop after RSA struct removed
# include <openssl/bio.h>
# include <openssl/err.h>
# include <openssl/sha.h>      ← drop after SHA_CTX/SHA256_CTX removed
```

Add `#include <openssl/evp.h>`. Drop `<openssl/sha.h>` and `<openssl/rsa.h>`
once the struct fields no longer reference `SHA_CTX`, `SHA256_CTX`, `RSA`.
Keep `<openssl/pem.h>`, `<openssl/bio.h>`, `<openssl/err.h>`.

### 2.4 RSA — struct definitions in `dkim-types.h`

Current `struct dkim_rsa` (lines 218–229, OpenSSL branch) carries
redundant low-level fields:

| Field | Disposition |
|---|---|
| `u_char rsa_pad` | **Drop.** Padding is set on the `EVP_PKEY_CTX`, not stored. |
| `int rsa_keysize` | Keep (still useful for key-size policy enforcement). |
| `size_t rsa_rsainlen`, `size_t rsa_rsaoutlen` | Keep. |
| `EVP_PKEY *rsa_pkey` | Keep — primary key handle. |
| `RSA *rsa_rsa` | **Drop.** Replaced by EVP_PKEY-based ops. |
| `BIO *rsa_keydata` | Keep (input buffer for PEM/DER parse). |
| `u_char *rsa_rsain`, `u_char *rsa_rsaout` | Keep (signature buffers). |

Current `struct dkim_sha1` and `struct dkim_sha256` (lines 161–177)
collapse into:

```c
struct dkim_sha
{
    int          sha_tmpfd;
    BIO *        sha_tmpbio;
    EVP_MD_CTX * sha_mdctx;
    u_int        sha_outlen;
    u_char       sha_out[EVP_MAX_MD_SIZE];
};
```

The `dkim_canon` consumer chooses `EVP_sha1()` vs `EVP_sha256()` from the
existing `canon->canon_hashtype` discriminator at init time.

### 2.5 Privkey load — `dkim.c::dkim_privkey_load` (line 1036)

| Line | Old call | Replacement |
|---|---|---|
| 1074 | `BIO_new_mem_buf(...)` | unchanged (BIO retained) |
| 1137 | `PEM_read_bio_PrivateKey(...)` | unchanged (already returns `EVP_PKEY*`) |
| 1144, 1157, 1168, 1182 | `BIO_free(rsa->rsa_keydata)` | unchanged |
| 1151 | `d2i_PrivateKey_bio(...)` | unchanged (already returns `EVP_PKEY*`) |
| 1163 | `EVP_PKEY_get1_RSA(rsa->rsa_pkey)` | **Drop.** `rsa_rsa` field gone. |
| 1167 | `dkim_error("EVP_PKEY_get1_RSA() failed")` | drop |
| 1173 | `RSA_size(rsa->rsa_rsa) * 8` | `EVP_PKEY_get_bits(rsa->rsa_pkey)` |
| 1174 | `rsa->rsa_pad = RSA_PKCS1_PADDING` | drop (padding moves to sign-time CTX) |
| 1175 | `DKIM_MALLOC(dkim, rsa->rsa_keysize / 8)` | `DKIM_MALLOC(dkim, EVP_PKEY_get_size(rsa->rsa_pkey))` |
| 1180 | `RSA_free(rsa->rsa_rsa)` | drop |

### 2.6 Signing — `dkim.c::dkim_eom_sign` (line 3511)

| Line | Old call | Replacement |
|---|---|---|
| 3779–3784 | `nid = NID_sha1; if (sha256) nid = NID_sha256;` | Drop. RSA-SHA1 *signing* is dropped per SCOPE.md. Refuse RSA-SHA1 sign with hard error; only RSA-SHA256 proceeds. (The signing-refusal *test* coverage is listed missing in TEST_AUDIT.md and is a separate concern; here we only port the existing path.) |
| 3786 | `RSA_sign(nid, digest, diglen, rsa->rsa_rsaout, &l, rsa->rsa_rsa)` | `EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(rsa->rsa_pkey, NULL); EVP_PKEY_sign_init(pctx); EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING); EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256()); EVP_PKEY_sign(pctx, rsa->rsa_rsaout, &outlen, digest, diglen); EVP_PKEY_CTX_free(pctx);` |
| 3795 | `RSA_free(rsa->rsa_rsa)` | drop |
| 3797, 3825, 3836 | `BIO_free(rsa->rsa_keydata)` | unchanged |

Note: `RSA_PKCS1_PADDING` here is the constant macro passed *to* the EVP
context — that is the prescribed EVP usage and is not a low-level call.

### 2.7 Verify — `dkim.c::dkim_sig_process` (line 5296)

| Line | Old call | Replacement |
|---|---|---|
| 5378 | `BIO_new_mem_buf(...)` | unchanged |
| 5396, 5464, 5481, 5508 | `BIO_free(key)` | unchanged |
| 5456 | `d2i_PUBKEY_bio(key, NULL)` | unchanged (returns `EVP_PKEY*`) |
| 5472 | `EVP_PKEY_get1_RSA(rsa->rsa_pkey)` | **Drop.** |
| 5477 | `dkim_error("EVP_PKEY_get1_RSA() failed")` | drop |
| 5488 | `RSA_size(rsa->rsa_rsa)` | `EVP_PKEY_get_size(rsa->rsa_pkey)` (bytes; `5494` then keeps the existing `* 8` to publish bits) |
| 5489 | `rsa->rsa_pad = RSA_PKCS1_PADDING` | drop |
| 5496–5501 | `nid = NID_sha1; if (sha256) nid = NID_sha256;` | Replace with selection of `EVP_sha1()` or `EVP_sha256()`. RSA-SHA1 verification is **retained** for legacy interop per SCOPE.md (warning logged separately). |
| 5503 | `RSA_verify(nid, digest, diglen, rsa->rsa_rsain, rsa->rsa_rsainlen, rsa->rsa_rsa)` | `EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(rsa->rsa_pkey, NULL); EVP_PKEY_verify_init(pctx); EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING); EVP_PKEY_CTX_set_signature_md(pctx, md); EVP_PKEY_verify(pctx, rsa->rsa_rsain, rsa->rsa_rsainlen, digest, diglen); EVP_PKEY_CTX_free(pctx);` |
| 5509 | `RSA_free(rsa->rsa_rsa)` | drop |

### 2.8 Test-key cross-check — `dkim-test.c::dkim_test_key` (line 289)

| Line | Old call | Replacement |
|---|---|---|
| 395 | `BIO_new_mem_buf(key, keylen)` | unchanged |
| 419 | `PEM_read_bio_PrivateKey(...)` | unchanged |
| 423, 437, 453, 463–464, 481, 484–485 | `BIO_free(...)` | unchanged |
| 434 | `EVP_PKEY_get1_RSA(rsa->rsa_pkey)` | **Drop.** |
| 441 | `dkim_error("EVP_PKEY_get1_RSA() failed")` | drop |
| 447 | `RSA_size(rsa->rsa_rsa)` | `EVP_PKEY_get_size(rsa->rsa_pkey)` |
| 448 | `rsa->rsa_pad = RSA_PKCS1_PADDING` | drop |
| 450 | `BIO_new(BIO_s_mem())` | unchanged |
| 460 | `i2d_RSA_PUBKEY_bio(outkey, rsa->rsa_rsa)` | `i2d_PUBKEY_bio(outkey, rsa->rsa_pkey)` |
| 468 | `dkim_error("i2d_RSA_PUBKEY_bio() failed")` | message text update |
| 474 | `BIO_get_mem_data(outkey, &ptr)` | unchanged |
| 476 | `BIO_number_written(outkey)` | unchanged |

### 2.9 OpenSSL init/cleanup — `dkim.c`

| Line | Old call | Replacement |
|---|---|---|
| 4199 | `OpenSSL_add_all_algorithms()` | drop. OpenSSL 3 auto-initialises on first use (`OPENSSL_init_crypto()` is implicit). The whole `dkim_init_openssl()` function and its refcount can be removed. |
| 4224 | `EVP_cleanup()` | drop. OpenSSL 3 cleans up via atexit. The whole `dkim_close_openssl()` function and its calls in `dkim_init`/`dkim_close` can be removed. |

### 2.10 Error queue — `dkim.c` (no change needed)

`dkim_load_ssl_errors` (line 904) and `dkim_sig_load_ssl_errors` (line 972)
use `ERR_peek_error`, `ERR_get_error`, `ERR_error_string_n`. **All three
remain valid in OpenSSL 3.** No change. Confirm in the final pass.

### 2.11 Version reporting — `dkim.c::dkim_ssl_version` (line 8131)

`OPENSSL_VERSION_NUMBER` macro is still defined in OpenSSL 3
(`<openssl/opensslv.h>`). No change. Confirm in the final pass.

### 2.12 CLOBBER macros — `dkim.c` (lines 199–215) and `dkim_free` (line 4819)

| Line | Old | Replacement |
|---|---|---|
| 205–209 | `RSA_CLOBBER(x): RSA_free(x); x = NULL;` | **Delete macro.** |
| 4913 | `RSA_CLOBBER(rsa->rsa_rsa)` | delete the line |
| 199–203 | `BIO_CLOBBER` | unchanged (still used for `rsa_keydata`) |
| 211–215 | `EVP_CLOBBER` | unchanged |
| 4911 | `BIO_CLOBBER(rsa->rsa_keydata)` | unchanged |
| 4912 | `EVP_CLOBBER(rsa->rsa_pkey)` | unchanged |

---

## 3. Out-of-scope items (deferred, not ported here)

| Item | Reason |
|---|---|
| `dkim-atps.c` (entire file) | ATPS removed permanently per SCOPE.md. File deletion is a separate cleanup session. |
| `base32.c` lines 160–183 (`#ifdef TEST` block) | Test main(), not part of library binary. Defer to test-infra reorganisation. |
| GnuTLS `#ifdef USE_GNUTLS` blocks across all files | SCOPE.md mandates wholesale deletion in a separate session, not OpenSSL-3 porting. |
| `libopendkim/tests/*.c` | Tests are frozen. SCOPE.md process rule 1 + this session's rule 1. |
| `opendkim/` daemon | Out of scope per this session's rule 3. |
| Ed25519 (RFC 8463) signing/verification | Out of scope per this session's rule 2. RSA-SHA256 only. |

---

## 4. Ordered porting plan

Each step is a unit of work to complete and review before the next. Steps
within a phase share a struct or compile dependency and must be staged so
the file remains internally consistent after each step.

### Phase 1 — Hashing (file: `dkim-canon.c`, type: `dkim-types.h`)

1. **Redesign `struct dkim_sha`** in `dkim-types.h`: merge `dkim_sha1`
   and `dkim_sha256` into one struct carrying `EVP_MD_CTX *sha_mdctx`,
   `u_int sha_outlen`, `u_char sha_out[EVP_MAX_MD_SIZE]`, plus existing
   `tmpfd` / `tmpbio`. Update `<openssl/...>` includes.
2. **`dkim_canon_init`** (line 622): allocate the unified struct;
   `EVP_MD_CTX_new` + `EVP_DigestInit_ex(ctx, md, NULL)` where `md` is
   `EVP_sha1()` or `EVP_sha256()` per `canon_hashtype`.
3. **`dkim_canon_write`** (line 186): `EVP_DigestUpdate` in place of
   both `SHA*_Update` calls.
4. **`dkim_canon_runheaders`** (line 1122): `EVP_DigestFinal_ex` in
   place of both `SHA*_Final` calls.
5. **`dkim_canon_signature`** (line 1478): same finalization replacement.
6. **`dkim_canon_closebody`** (line 1924): same finalization replacement.
7. **`dkim_canon_free`** (line 82): `EVP_MD_CTX_free` added; merge SHA1
   and SHA256 cases under unified struct.
8. **`dkim_canon_getfinal`** (line 2047): use `sha->sha_out` and
   `sha->sha_outlen` from the unified struct.
9. **`dkim_sig_getreportinfo`** in `dkim.c` (line 7122): adjust
   struct-field reads to the unified `dkim_sha`.

### Phase 2 — RSA key handling (files: `dkim.c`, `dkim-test.c`, type: `dkim-types.h`)

10. **Simplify `struct dkim_rsa`** in `dkim-types.h`: drop `RSA *rsa_rsa`,
    drop `u_char rsa_pad`. Keep `EVP_PKEY *rsa_pkey`, `BIO *rsa_keydata`,
    sig buffers.
11. **`dkim_privkey_load`** (`dkim.c` line 1036): drop
    `EVP_PKEY_get1_RSA`, `RSA_size`, `RSA_PKCS1_PADDING` field, `RSA_free`;
    use `EVP_PKEY_get_bits` and `EVP_PKEY_get_size`.
12. **`dkim_free`** (`dkim.c` line 4819): delete `RSA_CLOBBER` macro and
    its call (line 4913). Keep `BIO_CLOBBER` and `EVP_CLOBBER`.
13. **`dkim_eom_sign`** (`dkim.c` line 3511): replace `RSA_sign` with the
    `EVP_PKEY_CTX` + `EVP_PKEY_sign_init` + `EVP_PKEY_CTX_set_rsa_padding`
    + `EVP_PKEY_CTX_set_signature_md(EVP_sha256())` + `EVP_PKEY_sign`
    sequence. Drop the RSA-SHA1 signing branch (return error).
14. **`dkim_sig_process`** verify path (`dkim.c` line 5296): replace
    `RSA_verify` with the `EVP_PKEY_CTX` + `EVP_PKEY_verify_init` +
    `EVP_PKEY_CTX_set_rsa_padding` + `EVP_PKEY_CTX_set_signature_md` +
    `EVP_PKEY_verify` sequence. RSA-SHA1 verify branch retained.
15. **`dkim_test_key`** (`dkim-test.c` line 289): drop `EVP_PKEY_get1_RSA`,
    `RSA_size`, `RSA_PKCS1_PADDING`; replace `i2d_RSA_PUBKEY_bio` with
    `i2d_PUBKEY_bio` taking the `EVP_PKEY *` directly.

### Phase 3 — Library init/teardown (file: `dkim.c`)

16. **`dkim_init_openssl`** (line 4194): remove
    `OpenSSL_add_all_algorithms` call. Function body is then empty;
    delete the function and its call site in `dkim_init` (line 4256).
17. **`dkim_close_openssl`** (line 4216): remove `EVP_cleanup` call.
    Delete the function and its call site in `dkim_close` (line 4389).
    Remove the `openssl_lock` / `openssl_refcount` statics.

### Phase 4 — Verify clean

18. Confirm `dkim_load_ssl_errors`, `dkim_sig_load_ssl_errors`,
    `dkim_ssl_version` need no change (`ERR_*`, `OPENSSL_VERSION_NUMBER`
    are valid in OpenSSL 3).
19. Run the acceptance grep below.

---

## 5. Acceptance criteria

After porting:

- `grep -RE 'RSA_|DSA_|ENGINE_' libopendkim/*.c` returns only matches
  inside C comments or string literals (e.g. `RSA_PKCS1_PADDING` passed
  to `EVP_PKEY_CTX_set_rsa_padding` — that is a *constant*, not a
  function call, and is the prescribed EVP usage).
- No occurrences of `EVP_PKEY_get1_RSA`, `EVP_PKEY_set1_RSA`,
  `RSA_sign`, `RSA_verify`, `RSA_size`, `RSA_free`, `i2d_RSA_*`,
  `d2i_RSA_*`, `OpenSSL_add_all_algorithms`, `EVP_cleanup`,
  `SHA_CTX`, `SHA256_CTX`, `SHA1_Init`, `SHA1_Update`, `SHA1_Final`,
  `SHA256_Init`, `SHA256_Update`, `SHA256_Final`.
- No occurrences of `ENGINE_*`.
- `<openssl/rsa.h>` and `<openssl/sha.h>` includes removed from
  `dkim-types.h`. `<openssl/evp.h>` added.
- All crypto goes through `EVP_DigestUpdate`/`EVP_DigestFinal_ex`,
  `EVP_PKEY_sign`/`EVP_PKEY_verify`, `EVP_PKEY_get_size`/`_get_bits`.
- `dkim-atps.c` and `base32.c` `#ifdef TEST` block remain unchanged
  this session (deferred per §3).

---

*Produced as the missing Session 1 deliverable. No code changes were
made in producing this audit.*
