# Task: triage and clear the conversion-family strict warnings

## Current state (as of 2026-05-27, after commits 17f5a79f / 912d8ffa / 68d3daa3)

`build-warnings.txt` is fresh.  **67 conversion-family warnings remain**, all in
`opendkim/opendkim.c`.  Buckets 3 and 6 are fully done.

| Category             | WAS | NOW | Disposition |
|----------------------|-----|-----|-------------|
| -Wsign-conversion    | 519 |  54 | IN SCOPE    |
| -Wconversion         | 327 |  12 | IN SCOPE    |
| -Wfloat-conversion   |  13 |   1 | IN SCOPE    |
| -Wcast-qual          |  66 |  66 | OUT — already triaged/annotated in prior pass |
| -Wformat-truncation= |  45 |  45 | OUT — SKIP policy, all verified safe |
| -Wformat=            |   3 |   0 | Fixed in prior pass |

In-scope total: **859 → 67** (792 cleared).

## What was already done

| Commit     | Scope |
|------------|-------|
| `17f5a79f` | Bucket 3 (partial): `(u_char)` casts in `dkim_base64_decode()` |
| `912d8ffa` | Bucket 3 (rest): byte-extraction across all other files (`dkim-canon.c`, `util.c`, `dkim-util.c`, `opendkim/util.c`, `dkim.c`, `dkim-dns.c`, `dkim-test.c`, `opendkim-dns.c`, `t-test73.c`, `t-signperf.c`, `t-verifyperf.c`); also added `DKIM_PUTSHORT`/`DKIM_PUTLONG` file-local macros in 4 files to replace the system `PUTSHORT`/`PUTLONG` which lack `(unsigned char)` casts |
| `68d3daa3` | Bucket 6: all 13 "changes value" sign-flip sentinels (hand-audited; all were intentional sentinels or a private-struct type fix — none were missing error checks) |

## Verdict: NOT a one-sweep fix

A blind cast sweep would silence the compiler but mask real bugs.  Work it as
clusters within the remaining file, confirming each before casting.

## Constraints

- One cluster (or one logical group) per commit; "Fix:" prefix; no
  Co-Authored-By line; commits must be GPG-signed.
- **Stop and ask before any API signature/typedef change** — that decision is
  the user's (precedent: the prior pass changed `dkim_sigkey_t` and split
  `dkim_options` only after explicit approval).
- Prefer fixing the underlying type over casting when the type is clearly wrong
  and local; annotate/cast when it's a forced external-boundary conversion.
- After a batch lands, regenerate `build-warnings.txt` (incremental rebuild —
  do NOT do a clean rebuild unless the file clearly lags):
  `cmake --build build-strict -j$(nproc) 2>&1 | tee build-warnings.txt`
- `awk`/`sed`/`grep` are fine for locating/measuring; edits must be reviewed,
  not blind global substitutions.
- Do NOT touch `-Wcast-qual` or `-Wformat-truncation=` warnings.

---

## Remaining warnings — all in `opendkim/opendkim.c`

### Cluster A — `int dbflags` → `u_int flags` param (21 warnings) ★ do first

Lines: **6361, 6380, 6408, 6426, 6455, 6483, 6505, 6526, 6547, 6568, 6589,
6616, 6638, 6663, 6684, 6716, 6755, 6788, 6814, 6841, 6865**

`dbflags` is declared `int` at line 5734.  At every callsite it holds only
`DKIMF_DB_FLAG_*` OR-combinations (always ≥ 0).  `dkimf_db_open()` takes
`u_int flags` (see `opendkim-db.h:59`).

**Fix**: change the declaration at line 5734 from `int dbflags = 0;` to
`u_int dbflags = 0;`.  That makes all 21 call-site warnings disappear without
any casts.  No API change — `dbflags` is a local variable.

### Cluster B — `__off_t` (stat.st_size) → `size_t` params (12 warnings)

Lines: **4334, 6155, 6164, 6165, 6221, 6230, 6231, 6287, 6296, 6297,
7155, 7174, 7176**

`stat.st_size` is `__off_t` (= `long int`).  It is passed to `malloc(size_t)`,
`memset(…, size_t)`, and `read(…, size_t)`.  A file size is never negative
(and `stat` checks are already present at each site).  Fix with explicit
`(size_t)` cast; for `read()` the existing `rlen < 0` check after the call
already guards the negative case.

### Cluster C — `size_t` → `int` narrowing (5 warnings)

Lines: **4379, 4386** (`strlen` result → `BIO_new_mem_buf(int len)`),
**10499, 10500** (`strlen` result accumulated into `mctx_hdrbytes`),
**12630** (need to check context).

For 4379/4386: `BIO_new_mem_buf` takes `int len`; a PEM/DER key is always
< INT_MAX bytes.  Cast `(int)keylen`.

For 10499/10500: check `mctx_hdrbytes` field type — if it is `size_t`,
the narrowing is in the assignment direction (size_t += strlen = size_t, OK);
if it is `int`, consider changing the field type (local struct, not public API).

### Cluster D — `int` → `size_t` sign-conversion (10 warnings, spread)

Lines: **3769, 3771, 3776** (`n * sizeof(time_t)` where `n` is `int`,
`alen` is `size_t` — `n > 0` is confirmed by the `if (t == 0)` guard),
**9777** (confirm context),
**10376** (size comparison of `mctx_hdrbytes + strlen(…)`),
**10499, 10500** (overlap with Cluster C),
**11640, 11653** (`dkimf_dstring_len()` returns `int`, passed to `dkim_header()`
which takes `size_t`),
**14685, 14691** (check context).

For 11640/11653: `dkimf_dstring_len()` returns `int` (always ≥ 0 per
contract); `dkim_header()`/`dkimf_msr_header()` take `size_t`.  **Stop and
ask** before changing `dkimf_dstring_len()` return type — that would be an API
change.  Prefer explicit `(size_t)` cast at the call sites here.

### Cluster E — Lua API boundary (3 warnings, Bucket 5)

Lines:
- **3128, 3190**: `ssize_t body` (canonicalized-body length) → `lua_pushnumber(…, lua_Number)`.  Explicit `(lua_Number)` cast with a comment.
- **3280**: `lua_tonumber(…)` → `int idx`.  Lua returns `lua_Number` (double); `idx` is a header-occurrence index that fits in `int`.  Explicit `(int)` cast.

### Cluster F — Miscellaneous single-site (remaining warnings)

| Line  | Type pair                          | Context / likely fix |
|-------|------------------------------------|----------------------|
| 990   | `long int` → `int` (lua_pushboolean) | `lg->lg_value` is a boolean (0/1); cast `(int)` |
| 4831  | `u_long` → `int` return            | check what mb holds; cast if bounded |
| 4904  | `int nsigs` → `size_t` malloc      | `nsigs ≥ 0`; cast `(size_t)` |
| 4912  | `u_int conf_maxverify` → `int n`   | check if sign-flip possible; if conf_maxverify fits int, cast |
| 7524  | `int conf_clockdrift` → `uint64_t` | clockdrift is seconds, non-negative; cast `(uint64_t)` |
| 9088  | `random()` (`long`) → `u_int rn`   | `random() % 100` is 0–99; cast `(u_int)` |
| 12518 | `ssize_t canonlen` → `size_t` division | guard `canonlen >= 0` already present? check, then cast |
| 13241 | `time_t now` → `srandom(unsigned int)` | `time_t` is `long`; `(unsigned int)now` |
| 13692 | `int` → `unsigned long`            | check context |
| 13713 | `int` → `unsigned long`            | check context |
| 13732 | `int` → `unsigned int`             | check context |
| 13824 | `long int` → `int`                 | check context |

---

## Suggested order for remaining work

1. **Cluster A** (change `dbflags` local var to `u_int` — 21 warnings gone, one-liner fix)
2. **Cluster B** (file-offset `__off_t` → `size_t` casts)
3. **Cluster D** (int → size_t sign-conversion; call sites only, no API changes)
4. **Cluster C** (size_t → int narrowing)
5. **Cluster F** (miscellaneous single-site)
6. **Cluster E** (Lua boundary, Bucket 5)

One cluster per commit.  After each commit, run the incremental rebuild and
update `build-warnings.txt`.

---

## Strict-build reproduce line (reference)

```bash
cmake --build build-strict -j$(nproc) 2>&1 | tee build-warnings.txt
```

Full clean rebuild (expensive, only if incremental is stale):
```bash
rm -rf build-strict/* && cmake -S . -B build-strict \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWITH_LUA=1 -DWITH_REDIS=1 -DWITH_UNBOUND=1 -DWITH_SYSTEMD=1 -DWITH_CURL=1 \
    -DOPENDKIM_ENABLE_STRICT_C=ON \
    -DOPENDKIM_ENABLE_EXTRA_WARNINGS=ON \
    -DOPENDKIM_ENABLE_UBSAN=ON \
    -DOPENDKIM_ENABLE_ASAN=ON && \
  cmake --build build-strict -j$(nproc) 2>&1 | tee build-warnings.txt
```
