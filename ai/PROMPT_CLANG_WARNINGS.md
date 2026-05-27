# Task: clear remaining Clang strict-build conversion warnings

## Context

This project is a fork of OpenDKIM.  A second build tree `build-clang/` was
added alongside the existing `build-strict/` (GCC) tree.  The Clang build uses
the same flag set as the GCC strict build (ASAN + UBSAN, strict C, extra
warnings) but additionally fires `-Wshorten-64-to-32` (Clang-specific name for
64→32-bit truncation that GCC calls `-Wconversion`).

Commits already landed (Clang warning work):

| Commit     | Scope |
|------------|-------|
| `52a16356` | Add MemorySanitizer (MSan) support to Sanitizers.cmake |
| `adfcfe93` | Cluster G — Clang correctness: K&R→prototype, fallthrough attributes, dead `&&` condition |
| `f1f6a739` | Cluster H — sign-compare at MIN() sites |
| `e9678071` | Cluster I — const cast direction at strncasecmp sites; propagate const through dkimf_add_signrequest |
| `d7c05254` | Cluster J — -Wimplicit-int-conversion, -Wfloat-conversion, -Wcast-align (high-severity) |

## Current state — remaining Clang warnings

A full clean Clang rebuild is needed to get exact post-Cluster-J counts.
Reproduce with:

```bash
rm -rf build-clang && CC=clang cmake -S . -B build-clang \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWITH_LUA=1 -DWITH_REDIS=1 -DWITH_UNBOUND=1 -DWITH_SYSTEMD=1 -DWITH_CURL=1 \
    -DOPENDKIM_ENABLE_STRICT_C=ON \
    -DOPENDKIM_ENABLE_EXTRA_WARNINGS=ON \
    -DOPENDKIM_ENABLE_UBSAN=ON \
    -DOPENDKIM_ENABLE_ASAN=ON && \
  cmake --build build-clang -j$(nproc) 2>&1 | tee build-clang-warnings.txt
```

Pre-Cluster-J baseline (for reference):

| Category                | Count | Status |
|-------------------------|-------|--------|
| `-Wsign-conversion`     | 383   | **TODO** |
| `-Wshorten-64-to-32`    | 160   | **TODO** |
| `-Wcast-qual`           |  57   | **LEAVE** — annotated API-boundary casts |
| `-Wfloat-conversion`    |  12   | ✅ Fixed in Cluster J |
| `-Wimplicit-int-conversion` | 8 | ✅ Fixed in Cluster J |
| `-Wcast-align`          |   6   | ✅ Fixed in Cluster J |

Pre-Cluster-J breakdown by file for the two remaining categories:

**`-Wsign-conversion`** (383 total):

| File | Count |
|------|-------|
| `libopendkim/dkim.c` | 134 |
| `libopendkim/dkim-canon.c` | 56 |
| `opendkim/util.c` | 68 |
| `opendkim/opendkim-db.c` | 44 |
| `libopendkim/dkim-util.c` | 26 |
| `miltertest/miltertest.c` | 15 |
| `opendkim/opendkim-dns.c` | 8 |
| `opendkim/opendkim-testmsg.c` | 6 |
| `libopendkim/dkim-mailparse.c` | 6 |
| `opendkim/opendkim-lua.c` | 4 |
| `libopendkim/dkim-test.c` | 4 |
| smaller / test files | 12 |

**`-Wshorten-64-to-32`** (160 total):

| File | Count |
|------|-------|
| `opendkim/util.c` | 44 |
| `libopendkim/dkim.c` | 28 |
| `opendkim/opendkim-db.c` | 24 |
| `libopendkim/dkim-test.c` | 10 |
| `libopendkim/dkim-util.c` | 8 |
| `opendkim/opendkim-genzone.c` | 7 |
| `opendkim/opendkim-dns.c` | 6 |
| `libopendkim/dkim-canon.c` | 6 |
| `miltertest/miltertest.c` | 5 |
| smaller / test files | 22 |

## Constraints

- **No pragmas** — `#pragma GCC diagnostic` is rejected.
- **Leave `-Wcast-qual` alone** — the 57 remaining are annotated API-boundary
  casts (libmilter `smfi_*`, Lua C API).  These were explicitly discussed and
  intentionally left as-is.
- Prefer fixing the underlying type over casting when clearly wrong and local.
  Cast only at forced external-boundary conversions.
- One logical cluster per commit; "Fix:" prefix; no Co-Authored-By line;
  commits must be GPG-signed.
- **Stop and ask before any API signature / typedef change** (the user decides).
- `awk`/`sed`/`grep` are fine for locating/measuring; edits are reviewed, not
  blind global substitutions.

## Strategy

Work file by file, heaviest warning count first.  For each file:

1. `grep` the actual warning lines out of `build-clang-warnings.txt` to
   confirm current count and exact locations.
2. Triage: is the conversion a latent bug (negative int used as size_t, or
   size_t truncated to int that could exceed INT_MAX)?  Or is it structurally
   bounded (a loop index, an enum value, a strlen result capped by a preceding
   check)?  Fix the type when possible; cast explicitly when not.
3. Commit that file or logical group as one "Cluster K / L / M …" commit.

Suggested order (heaviest first):

1. `libopendkim/dkim.c` (134 + 28 = 162)
2. `opendkim/util.c` (68 + 44 = 112)
3. `libopendkim/dkim-canon.c` (56 + 6 = 62)
4. `opendkim/opendkim-db.c` (44 + 24 = 68)
5. `libopendkim/dkim-util.c` (26 + 8 = 34)
6. `miltertest/miltertest.c` (15 + 5 = 20 — some already reduced by Cluster J)
7. Remaining smaller files

## Useful one-liners

```bash
# Current warning counts by category
grep -E '^.+: warning:' build-clang-warnings.txt | grep -oP '\[-W[^\]]+\]' | sort | uniq -c | sort -rn

# Warnings in a specific file, deduped
grep -E '^.+: warning:' build-clang-warnings.txt \
  | grep 'libopendkim/dkim\.c' \
  | sed 's|/home/edmund/devel/projects/PhoenixDKIM/||' \
  | sort -u

# Incremental rebuild (fast, reuses existing build-clang/ tree)
cmake --build build-clang -j$(nproc) 2>&1 | tee build-clang-warnings.txt
```
