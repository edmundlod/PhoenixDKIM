---
  Build Warnings Analysis — New vs. Already Known
  
  ✅ Already known / expected noise (filter out)

  These are 936 of the ~973 total warning instances and are explicitly acknowledged in cmake/Hardening.cmake as "high noise in legacy C code", gated behind the optional
  OPENDKIM_ENABLE_EXTRA_WARNINGS and OPENDKIM_ENABLE_STRICT_C flags:

  ┌──────────────────────────────────────────────────────────┬───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │                           Flag                           │ Count │                                                       Notes                                                       │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wsign-conversion]                                      │ 519   │ Endemic to upstream OpenDKIM code mixing int/u_int/size_t                                                         │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wconversion]                                           │ 327   │ Same — int↔char/u_char/size_t throughout the legacy base                                                          │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wcast-qual]                                            │ 66    │ const cast-away; upstream pattern, mostly in dkim.c/test.c                                                        │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wfloat-conversion]                                     │ 13    │ All in Lua binding code (miltertest.c, opendkim-lua.c): lua_Number (double) → int. Expected Lua API pattern.      │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wformat-truncation=] at opendkim.c:12644 (mlfi_eom)    │ 1     │ Explicitly documented as a known instance in Hardening.cmake:217 (was line 12408 before recent commits shifted    │
  │                                                          │       │ it)                                                                                                               │
  ├──────────────────────────────────────────────────────────┼───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ [-Wformat-truncation=] in test files (t-conformance.c,   │ ~25   │ All are the snprintf(path, sizeof path, "%s/...", srcdir) pattern where srcdir is a test fixture path. Background │
  │ t-test*.c)                                               │       │  noise in test infra.                                                                                             │
  └──────────────────────────────────────────────────────────┴───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
  
  ---
  🔴 New findings — worth fixing
  
  1. [-Wformat=] — actual type mismatch (not just noise)

  opendkim/config.c:800:  %p used with struct config *, expects void *
  fprintf(out, "%p: \"%s\" ", cur, cur->cfg_name) — %p formally requires void *. Technically UB on platforms where struct and void pointers differ in representation. Fix: cast to (void *).
   (Fires 3× total because config.c is compiled into 3 targets.)

  ---
  2. [-Wformat-truncation=] in production library/daemon code — new instances
  
  These are distinct from the one known instance and are all in production paths, not tests:

  ┌─────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────┬───────────────────────────────────────────────────┐
  │                  Location                   │                                       Issue                                       │                     Severity                      │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ libopendkim/dkim.c:7228                     │ snprintf(val, vallen, "@%s", param) — GCC says "destination of size 1", i.e. if   │ Medium — depends on callers passing adequate      │
  │ (dkim_sig_getidentity)                      │ caller passes vallen=1, the @ takes the only byte and the NUL is lost             │ vallen                                            │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ libopendkim/dkim-util.c:144,150             │ Temp-file path: snprintf(path, sizeof path, "%s/dkim.%s.XXXXXX", tmpdir, id) — if │ Low — tmpdir is config-controlled                 │
  │                                             │  tmpdir is close to PATH_MAX, the fixed suffix overflows                          │                                                   │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ opendkim/opendkim.c:11517 (mlfi_eoh)        │ snprintf(identity, sizeof identity /*257*/, "@%s", domain) — output 2–258 bytes   │ Medium — real mail domain limit is 253 bytes, but │
  │                                             │ into 257-byte buf; a max-length domain would lose the NUL                         │  the buffer is only 257 with the @ prefix         │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ opendkim/opendkim.c:9482 (dkimf_sigreport)  │ snprintf(dest, sizeof dest /*257*/, "%s@%s", addr, domain) — can truncate report  │ Low — report path                                 │
  │                                             │ destination address                                                               │                                                   │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ opendkim/opendkim.c:9760 (APPEND macro in   │ Writing 1 byte into remaining region of 0–1 bytes — the growing A-R header        │ Low — the APPEND macro checks r < 0 but not       │
  │ dkimf_ar_all_sigs)                          │ assembly                                                                          │ truncation                                        │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ opendkim/opendkim.c:8606                    │ snprintf(replybuf, 1024, "%s: %s", ...) — :  truncation, assuming output ≥1044    │ Low — milter reply buffer                         │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ opendkim/opendkim.c:6339                    │ chdir error message snprintf                                                      │ Low — error path                                  │
  ├─────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────┤
  │                                             │ snprintf(query, 1025, "%s%.*s", prefix, len, buf) — GCC warns because %.*s max is │ False positive — the guard at line 1688 makes     │
  │ opendkim/opendkim-db.c:1695                 │  INT_MAX from its perspective, but code already has buflen > INT_MAX guard above  │ this safe; suppress with (void) or __attribute__  │
  │                                             │ it                                                                                │                                                   │
  └─────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────┘
  
  ---
  3. [-Wsign-conversion] instances that are actual code smells (not just background noise)
  
  Two stand out from the sea of routine sign-conversion churn:

  ┌─────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │        Location         │                                                                            Issue                                                                            │
  ├─────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim.c:4067 │ sig->sig_flags &= ~DKIM_SIGFLAG_PASSED — ~ of an int constant yields int, then assigned to u_int sig_flags. The value -5 → 4294967291 is correct on two's   │
  │                         │ complement but is technically implementation-defined. Fix: cast DKIM_SIGFLAG_PASSED as (u_int) in the macro definition or use (u_int)~.                     │
  ├─────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim.c:5124 │ new->dkim_signlen = ULONG_MAX where dkim_signlen is ssize_t. This is the "sign of -1" sentinel pattern — intentional, but should be written as              │
  │                         │ new->dkim_signlen = -1 directly.                                                                                                                            │
  └─────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  ---
  Summary by priority
  
  ┌──────────────────┬───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │       Pri        │ Count │                                                      What                                                       │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Fix now          │ 1     │ config.c:800 — %p format type mismatch (UB)                                                                     │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Review           │ 2     │ dkim.c:7228, opendkim.c:11517 — plausible off-by-one on edge-case inputs                                        │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Cosmetic/intent  │ 2     │ dkim.c:4067 bitwise NOT sign, dkim.c:5124 ULONG_MAX sentinel                                                    │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ False positive   │ 1     │ opendkim-db.c:1695 — already guarded                                                                            │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Low priority     │ 5     │ Remaining truncation warnings in error/report paths                                                             │
  ├──────────────────┼───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Background noise │ ~963  │ All -Wconversion, -Wsign-conversion, -Wcast-qual, -Wfloat-conversion, and the known opendkim.c:12644 truncation │
  └──────────────────┴───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  
  _________________________________________________________________________________________________________
  
  New warnings (not previously known)
  
  [-Wformat=] — 1 location × 3 targets

  opendkim/config.c:800:  %p used with struct config *, should be void *
  config_dump(): fprintf(out, "%p: \"%s\" ", cur, cur->cfg_name) — technically UB; fix is cast cur to (void *).
  
  ---
  [-Wformat-truncation=] — 38 new locations
  
  (You know which 7 are safe; all others follow. Since I don't know which 7 you've cleared, the full list is below — subtract yours.)

  libopendkim/ — library production code (3 locations)
  libopendkim/dkim.c:7228        '%s' may truncate writing into region of size 0  ← notable: size 0
  libopendkim/dkim-util.c:144    '/dkim.' truncation (6 bytes into buffer of 1–4097)
  libopendkim/dkim-util.c:150    '/dkim.XXXXXX' truncation (12 bytes into buffer of 1–4097)
  The dkim.c:7228 one says size 0 — that's dkim_sig_getidentity() writing @%s into a buffer when vallen is 1 (only room for NUL).
  
  opendkim/ — daemon production code (7 locations)
  opendkim/opendkim.c:6339       chdir error msg: output may exceed minimum size
  opendkim/opendkim.c:8606       replybuf: ': ' truncation (output ≥1044 into buf of 1024)
  opendkim/opendkim.c:9482       dest address: '%s@%s' truncation (likely 1+ byte, 0–256 remaining)
  opendkim/opendkim.c:9760       APPEND macro: '%s' writing 1 byte into region of 0–1 bytes
  opendkim/opendkim.c:11517      identity buf: output 2–258 bytes into 257-byte buffer
  opendkim/opendkim.c:12644      AUTHRESULTSHDR snprintf: output may exceed min size of 4095
  opendkim/opendkim-db.c:1695    '%.*s' up to 2147483647 bytes (GCC ignores INT_MAX guard above)

  libopendkim/tests/ — test infrastructure (28 locations)
  libopendkim/tests/t-conformance.c:270, 337, 429, 516, 601, 682, 864, 939,
                                    1011, 1078, 1145, 1214, 1360, 1429, 1530,
                                    1535, 2057, 2270, 2422, 2489   (20 locations, same pattern)
  libopendkim/tests/t-test120.c:145 
  libopendkim/tests/t-test128.c:219
  libopendkim/tests/t-test129.c:296
  libopendkim/tests/t-test204.c:187, 191
  libopendkim/tests/t-test205.c:214, 218
  libopendkim/tests/t-test206.c:124
  libopendkim/tests/t-test207.c:116
  All test instances are the same pattern: snprintf(path, sizeof path, "%s/...", srcdir) where srcdir could theoretically be up to 4096 bytes, and the fixed suffix pushes over the buffer.
  
  ---
  [-Wfloat-conversion] — 13 locations, all Lua lua_Number→int
  
  All are the same pattern: lua_tonumber() returns double, assigned to int or uint32_t. All in Lua binding glue code:

  miltertest/miltertest.c:1389   lua_Number → int
  miltertest/miltertest.c:1834   lua_Number → unsigned long
  miltertest/miltertest.c:1872   lua_Number → unsigned long
  miltertest/miltertest.c:1922   lua_Number → uint32_t
  miltertest/miltertest.c:1927   lua_Number → uint32_t
  miltertest/miltertest.c:1932   lua_Number → uint32_t
  miltertest/miltertest.c:2044   lua_Number → int
  miltertest/miltertest.c:3414   lua_Number → int
  miltertest/miltertest.c:3520   lua_Number → int
  miltertest/miltertest.c:3595   lua_Number → int
  miltertest/miltertest.c:3656   lua_Number → int
  miltertest/miltertest.c:4030   lua_Number → int
  opendkim/opendkim.c:3280       lua_Number → int
  Fix pattern everywhere: (int) lua_tointeger(L, n) instead of (int) lua_tonumber(L, n).

  ---
  [-Wconversion] — 157 unique source locations across 23 files
  
  ┌──────────────────────────────────┬──────────────────┐
  │               File               │ Unique locations │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim.c               │ 17               │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/util.c                  │ 16               │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim-test.c          │ 13               │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/opendkim.c              │ 12               │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-test73.c     │ 10               │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/opendkim-dns.c          │ 9                │
  ├──────────────────────────────────┼──────────────────┤
  │ miltertest/miltertest.c          │ 9                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim-util.c          │ 8                │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/opendkim-genzone.c      │ 7                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/base64.c             │ 7                │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/opendkim-db.c           │ 6                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/util.c               │ 5                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim-canon.c         │ 5                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim-dns.c           │ 4                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-verifyperf.c │ 3                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-test57.c     │ 3                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-signperf.c   │ 3                │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/test.c                  │ 2                │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/opendkim-testkey.c      │ 1                │
  ├──────────────────────────────────┼──────────────────┤
  │ opendkim/config.c                │ 1                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-test136.c    │ 1                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/tests/t-test113.c    │ 1                │
  ├──────────────────────────────────┼──────────────────┤
  │ libopendkim/dkim-keys.c          │ 1                │
  └──────────────────────────────────┴──────────────────┘

  ---
  [-Wsign-conversion] — 293 unique source locations across 24 files

  ┌──────────────────────────────────┬───────────────────────────────────────────────────────────────────┐
  │               File               │                         Unique locations                          │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim.c               │ 74                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim.c              │ 54                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim-canon.c         │ 32                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/util.c                  │ 19                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ miltertest/miltertest.c          │ 17                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim-util.c          │ 16                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-db.c           │ 15                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim-test.c          │ 11                                                                │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-testmsg.c      │ 6                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-dns.c          │ 5                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-testkey.c      │ 3                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-test73.c     │ 3                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/dkim-mailparse.c     │ 3                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/test.c                  │ 2                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-genzone.c      │ 2                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-lua.c          │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ opendkim/opendkim-db.h:28        │ 1 ← macro in header: DKIMF_DB_TYPE_UNKNOWN (-1) assigned to u_int │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-verifyperf.c │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-test87.c     │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-test57.c     │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-test158.c    │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-test114.c    │ 1                                                                 │
  ├──────────────────────────────────┼───────────────────────────────────────────────────────────────────┤
  │ libopendkim/tests/t-signperf.c   │ 1                                                                 │
  └──────────────────────────────────┴───────────────────────────────────────────────────────────────────┘

  Notable standout: opendkim-db.h:28 — a macro DKIMF_DB_TYPE_UNKNOWN (-1) being used where u_int is expected fires at every use site. Changing the macro to ((u_int)-1) or changing the field
   type would silence all instances from that macro.
