# opendkim/ Daemon Crypto Audit — OpenSSL 1.x → OpenSSL 3 EVP

Audited against: `SCOPE.md` (April 2026)
Scope of this audit: `opendkim/*.c` and `opendkim/*.h` only.
Out of scope: `libopendkim/` (covered by `AUDIT.md`), `libopendkim/tests/`.

This document is the inventory and ordered porting plan for the daemon
session. **No code changes were made in producing this audit.**

---

## 0. grep output (as requested)

```
$ grep -rn "RSA_\|DSA_\|ENGINE_\|SHA1_\|SHA256_\|SHA_CTX\|SHA256_CTX\|EVP_PKEY_get1_RSA\|OpenSSL_add_all\|EVP_cleanup\|d2i_RSA\|i2d_RSA\|RSA_sign\|RSA_verify\|RSA_size\|RSA_free\|RSA_new\|PEM_read.*RSA\|RSA_generate" opendkim/*.c opendkim/*.h

opendkim/opendkim-crypto.c:298:		EVP_cleanup();
opendkim/opendkim-genzone.c:729:		rsa = EVP_PKEY_get1_RSA(pkey);
opendkim/opendkim-genzone.c:733:			        "%s: EVP_PKEY_get1_RSA() failed\n",
opendkim/opendkim-genzone.c:743:		status = PEM_write_bio_RSA_PUBKEY(outbio, rsa);
opendkim/opendkim-genzone.c:747:			        "%s: PEM_write_bio_RSA_PUBKEY() failed\n",

$ grep -rn "gnutls" opendkim/*.c opendkim/*.h
(no output)
```

The initial grep identified three files with hits. Reading the files in full
revealed additional deprecated calls not matched by those patterns; they are
catalogued in §2 below.

---

## 1. Files in scope

| File | Crypto present? | Notes |
|---|---|---|
| `opendkim-crypto.c` | YES — critical | Entire OpenSSL 1.x threading/locking boilerplate. Every non-trivial call in this file is removed in OpenSSL 3. Replacement is a two-function stub. |
| `opendkim-genzone.c` | YES | `EVP_PKEY_get1_RSA` + `PEM_write_bio_RSA_PUBKEY`. Two call sites. |
| `opendkim.c` | YES — minor | `#include <openssl/sha.h>` for `SHA_DIGEST_LENGTH` (defined but never used — dead). Calls `dkimf_crypto_init/free` which become no-ops after §2.1 is ported. |
| `opendkim-testkey.c` | YES — minor | `ERR_load_crypto_strings()` deprecated/no-op in OpenSSL 3. Other `ERR_*` calls are valid. |
| `opendkim-crypto.h` | NO | Header declares two prototypes only. No crypto types. No change needed. |
| `opendkim.h`, `opendkim-config.h`, `config.h`, `config.c` | NO | No deprecated crypto. |
| `opendkim-ar.c/h`, `opendkim-arf.c/h`, `opendkim-db.c/h` | NO | No deprecated crypto. |
| `opendkim-dns.c/h`, `opendkim-lua.c/h`, `opendkim-spam.c` | NO | No deprecated crypto. |
| `opendkim-testmsg.c`, `flowrate.c/h`, `test.c/h`, `util.c/h` | NO | No deprecated crypto. |

GnuTLS: no `#ifdef USE_GNUTLS` blocks in any `opendkim/` file. Nothing to
delete.

---

## 2. API call inventory

Each row is one call site that must change. "→" shows the OpenSSL 3 replacement.

### 2.1 OpenSSL 1.x threading callbacks — `opendkim-crypto.c`

**Background.** OpenSSL ≤ 1.0 required the application to register mutex and
thread-ID callbacks so the library could be used safely from multiple threads.
OpenSSL 1.1 removed the requirement and made the library self-thread-safe.
OpenSSL 3 removed the callback symbols entirely. The entire
`opendkim-crypto.c` is this adapter — nothing in it has an equivalent in
OpenSSL 3. After porting, both public functions become empty one-liners.

#### Removed types

| Line | Declaration | Status in OpenSSL 3 | Replacement |
|---|---|---|---|
| 146, 180, 205 | `struct CRYPTO_dynlock_value *` | **Type does not exist.** | Drop. All four functions that accept or return this type are deleted. |

#### Removed constants

| Line | Function | Old | Replacement |
|---|---|---|---|
| 63, 213 | `dkimf_crypto_lock_callback`, `dkimf_crypto_dyn_lock` | `CRYPTO_LOCK` flag test | **Constant removed.** Both functions deleted with the rest of the locking machinery. |

#### Removed functions — `dkimf_crypto_init` (line 233)

| Line | Old call | Replacement |
|---|---|---|
| 239 | `CRYPTO_num_locks()` | **Removed.** No lock count needed; OpenSSL 3 manages its own locks. |
| 261 | `SSL_load_error_strings()` | **Removed in OpenSSL 3** (no-op in 1.1). Drop. |
| 262 | `SSL_library_init()` | **Removed in OpenSSL 3** (deprecated in 1.1). Drop. OpenSSL 3 auto-initialises on first use. |
| 263 | `ERR_load_crypto_strings()` | **No-op / deprecated in OpenSSL 3.** Drop. |
| 265 | `CRYPTO_set_id_callback(...)` | **Removed in OpenSSL 1.1.** Drop. |
| 266 | `CRYPTO_set_locking_callback(...)` | **Removed in OpenSSL 1.1.** Drop. |
| 267 | `CRYPTO_set_dynlock_create_callback(...)` | **Removed in OpenSSL 1.1.** Drop. |
| 268 | `CRYPTO_set_dynlock_lock_callback(...)` | **Removed in OpenSSL 1.1.** Drop. |
| 269 | `CRYPTO_set_dynlock_destroy_callback(...)` | **Removed in OpenSSL 1.1.** Drop. |
| 271–273 | `#ifdef USE_OPENSSL_ENGINE` / `SSL_set_engine(NULL)` | **ENGINE API removed from default OpenSSL 3 build.** Delete entire `#ifdef USE_OPENSSL_ENGINE` block. |

After removing all of the above, `dkimf_crypto_init` body is: allocate and
initialise mutex arrays, set a thread key, and return 0. **None of this is
needed in OpenSSL 3.** The function body becomes `return 0;`.

#### Removed functions — `dkimf_crypto_free` (line 291)

| Line | Old call | Replacement |
|---|---|---|
| 296 | `CRYPTO_cleanup_all_ex_data()` | **Removed in OpenSSL 3.** Drop. |
| 297 | `CONF_modules_free()` | Still exists in OpenSSL 3 but CONF modules are released automatically via `atexit`. Drop. |
| 298 | `EVP_cleanup()` | **Removed in OpenSSL 3.** Drop. OpenSSL 3 performs its own cleanup via `atexit`. |
| 299 | `ERR_free_strings()` | **Removed in OpenSSL 3.** Drop. |
| 300 | `ERR_remove_state(0)` | **Removed in OpenSSL 1.1.** Drop. |

After removing the above, the mutex teardown loop also becomes pointless
(no mutexes were ever allocated). `dkimf_crypto_free` body becomes empty.

#### Removed helper functions

The four static helpers — `dkimf_crypto_lock_callback`,
`dkimf_crypto_get_id`, `dkimf_crypto_free_id`, `dkimf_crypto_dyn_create`,
`dkimf_crypto_dyn_destroy`, `dkimf_crypto_dyn_lock` — exist solely to
supply the removed callbacks. All six are deleted.

#### Static state deleted

`id_lock`, `id_key`, `nmutexes`, `threadid`, `mutexes` — all deleted.

#### Header includes in `opendkim-crypto.c` to remove

| Include | Reason to drop |
|---|---|
| `<openssl/crypto.h>` | `CRYPTO_*` threading API removed; no other use. |
| `<openssl/ssl.h>` | `SSL_library_init` / `SSL_load_error_strings` removed. |
| `<openssl/conf.h>` | `CONF_modules_free` call removed. |
| `<openssl/evp.h>` | No EVP calls remain in the stub. |
| `<openssl/err.h>` | No ERR calls remain in the stub. |
| `<pthread.h>` | Mutex arrays and thread-key removed. |

**Net result:** `opendkim-crypto.c` collapses to ~10 lines:
two trivial public functions and a `crypto_init_done` bool (retained for
the `conf_disablecryptoinit` logic in the caller to remain consistent).

---

### 2.2 RSA key serialisation — `opendkim-genzone.c`

`opendkim-genzone` reads a signing key table, loads each private key, derives
the corresponding public key, and writes it as a DNS zone record. The public
key is currently obtained by extracting the `RSA *` from the `EVP_PKEY *` and
passing it to the `RSA`-specific PEM writer. The fix is to use the
EVP-level writer directly on the `EVP_PKEY *`.

| Line | Function | Old call | Replacement |
|---|---|---|---|
| 23 | (includes) | `#include <openssl/rsa.h>` | **Drop** after `RSA *rsa` local variable is removed. |
| 250 | `main` | `RSA *rsa;` (local variable declaration) | **Drop.** |
| 729 | `main` | `rsa = EVP_PKEY_get1_RSA(pkey)` | **Drop.** Pass `pkey` directly to the replacement writer below. |
| 730–740 | `main` | `if (rsa == NULL) { fprintf … ; BIO_free … ; EVP_PKEY_free … ; return 1; }` | **Drop entire null-check block.** The new call takes `EVP_PKEY *` and cannot fail in this way. |
| 743 | `main` | `PEM_write_bio_RSA_PUBKEY(outbio, rsa)` | `PEM_write_bio_PUBKEY(outbio, pkey)` — takes `EVP_PKEY *` directly; works for both RSA and Ed25519. |
| 747 | `main` | `"%s: PEM_write_bio_RSA_PUBKEY() failed\n"` | `"%s: PEM_write_bio_PUBKEY() failed\n"` (message text only). |

`EVP_PKEY_free(pkey)` calls on lines 737 and 751 are the correct OpenSSL 3
API — unchanged. All `BIO_*` calls in this file remain valid in OpenSSL 3.

Note: The existing `RSA *rsa` code path includes `EVP_PKEY_free(pkey)` in
every error branch after the RSA extraction (lines 736–738, 750–752). After
removing those error branches, the remaining `EVP_PKEY_free` calls in the
cleanup path are already present and correct.

---

### 2.3 Dead `#include <openssl/sha.h>` — `opendkim.c`

| Line | Old | Status | Replacement |
|---|---|---|---|
| 57 | `#include <openssl/sha.h>` | `<openssl/sha.h>` is deprecated in OpenSSL 3. | **Drop.** |
| 60–62 | `#ifndef SHA_DIGEST_LENGTH` / `# define SHA_DIGEST_LENGTH 20` / `#endif` | `SHA_DIGEST_LENGTH` is defined here as a fallback constant provided by `<openssl/sha.h>`. Reading the file in full shows it is **never referenced anywhere else in `opendkim.c`**. The define block is dead code. | **Drop entire three-line block.** |

---

### 2.4 `ERR_load_crypto_strings` — `opendkim-testkey.c`

| Line | Function | Old call | Replacement |
|---|---|---|---|
| 441 | `main` | `ERR_load_crypto_strings()` | **No-op / deprecated in OpenSSL 3** (marked with deprecation attribute; generates a compiler warning). Drop. |

Other ERR calls in `opendkim-testkey.c` — `ERR_peek_error` (line 85),
`ERR_get_error` (line 98), `ERR_error_string_n` (line 103) — are valid in
OpenSSL 3. No change needed.

---

### 2.5 Call sites of `dkimf_crypto_init` / `dkimf_crypto_free` — `opendkim.c`

| Line | Function | Old call | Replacement |
|---|---|---|---|
| 15515 | `main` | `status = dkimf_crypto_init()` | After §2.1, `dkimf_crypto_init` is a no-op stub that always returns 0. The call site and the `conf_disablecryptoinit` guard may be retained for backwards-config-compatibility or removed — either is correct. No deprecated symbol remains. |
| 15686 | `main` (shutdown) | `dkimf_crypto_free()` | After §2.1, `dkimf_crypto_free` is an empty stub. Call site may be retained or removed. |

---

### 2.6 SSL version check — `opendkim.c` (no change needed)

| Line | Old | Status |
|---|---|---|
| 14389–14394 | `dkim_ssl_version() != OPENSSL_VERSION_NUMBER` | `OPENSSL_VERSION_NUMBER` is still defined in OpenSSL 3 (`<openssl/opensslv.h>`). The `<openssl/err.h>` include on line 58 transitively includes `<openssl/opensslv.h>`. After dropping `<openssl/sha.h>` from line 57, `<openssl/err.h>` remains on line 58 — the check continues to compile. **No change needed.** |

---

## 3. Out-of-scope items

| Item | Reason |
|---|---|
| `opendkim-spam.c` ODBX references | OpenDBX backend removed per SCOPE.md (separate cleanup session). |
| `opendkim-genzone.c` LDAP `#ifdef USE_LDAP` blocks | LDAP removed per SCOPE.md (separate cleanup session). |
| `opendkim-testkey.c` LDAP `#ifdef USE_LDAP` blocks | Same. |
| Ed25519 key handling in `opendkim-genzone.c` | The replacement `PEM_write_bio_PUBKEY` is algorithm-agnostic; Ed25519 support becomes implicit after §2.2 is ported. No additional work needed here. |
| `opendkim/` Lua integration (`opendkim-lua.c`) | No deprecated crypto. |

---

## 4. Ordered porting plan

### Phase 1 — Replace `opendkim-crypto.c` with a stub

1. **Delete all six static helper functions** (`dkimf_crypto_lock_callback`,
   `dkimf_crypto_get_id`, `dkimf_crypto_free_id`, `dkimf_crypto_dyn_create`,
   `dkimf_crypto_dyn_destroy`, `dkimf_crypto_dyn_lock`) and all associated
   static state (`id_lock`, `id_key`, `nmutexes`, `threadid`, `mutexes`).
2. **Replace `dkimf_crypto_init`** body with `crypto_init_done = TRUE; return 0;`
   (or simply `return 0;` if the flag is also removed from the caller).
3. **Replace `dkimf_crypto_free`** body with nothing (empty function) or
   `crypto_init_done = FALSE;`.
4. **Remove all OpenSSL includes** from `opendkim-crypto.c` (see §2.1 table).
   The stub needs no OpenSSL headers.
5. **Remove `<openssl/ssl.h>` and `<pthread.h>`** specifically — these are
   the most likely to cause confusion if left.

### Phase 2 — `opendkim-genzone.c`

6. **Drop `RSA *rsa` local variable** and `#include <openssl/rsa.h>`.
7. **Remove `EVP_PKEY_get1_RSA` call** (line 729) and its error block
   (lines 730–740).
8. **Replace `PEM_write_bio_RSA_PUBKEY(outbio, rsa)`** with
   `PEM_write_bio_PUBKEY(outbio, pkey)` and update error message text.

### Phase 3 — Minor cleanup

9. **`opendkim.c`**: Drop `#include <openssl/sha.h>` (line 57) and the
   three-line `SHA_DIGEST_LENGTH` dead-define block (lines 60–62).
10. **`opendkim-testkey.c`**: Drop `ERR_load_crypto_strings()` (line 441).

### Phase 4 — Verify clean

11. Run the acceptance grep (§5).
12. Build the daemon; confirm clean compile with `-DOPENSSL_API_COMPAT=0x30000000L`
    to catch any remaining deprecated-API warnings.

---

## 5. Acceptance criteria

After porting:

- `grep -rn "CRYPTO_num_locks\|CRYPTO_set_.*callback\|CRYPTO_dynlock\|SSL_library_init\|SSL_load_error_strings\|ERR_remove_state\|ERR_free_strings\|EVP_cleanup\|CONF_modules_free\|CRYPTO_cleanup_all" opendkim/*.c` returns no hits.
- `grep -rn "EVP_PKEY_get1_RSA\|PEM_write_bio_RSA_PUBKEY\|ERR_load_crypto_strings" opendkim/*.c` returns no hits.
- `grep -rn "#include.*openssl/sha\.h\|#include.*openssl/rsa\.h" opendkim/*.c opendkim/*.h` returns no hits (both removed).
- `grep -rn "#include.*openssl/ssl\.h" opendkim/*.c opendkim/*.h` returns no hits.
- `opendkim-crypto.c` contains no mutex arrays, no `pthread_key_t`, no OpenSSL includes.
- `opendkim-genzone.c` contains no `RSA *` local variable and no `RSA`-typed function calls.
- No GnuTLS code exists anywhere in `opendkim/` (confirmed by initial grep).

---

*Produced as the daemon-session audit deliverable. No code changes were
made in producing this audit.*
