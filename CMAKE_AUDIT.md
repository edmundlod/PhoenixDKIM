# CMake Build System Gap Analysis

**Date:** 2026-05-07  
**Branch:** master  
**Autotools baseline:** `configure.ac` + `*/Makefile.am`  
**CMake baseline:** `CMakeLists.txt`, `libopendkim/CMakeLists.txt`, `opendkim/CMakeLists.txt`  
**Scope authority:** `SCOPE.md`

---

## Summary Table

| Feature | Autotools | CMake | Gap? |
|---------|-----------|-------|------|
| **A. Libraries** | | | |
| libopendkim (shared) | `lib_LTLIBRARIES` | ✅ shared + static | — |
| libar (async DNS) | In scope; dir deleted | ❌ not built | **CRITICAL** |
| libut (utility) | `lib_LTLIBRARIES` in `libut/` | ❌ not built | **HIGH** |
| libvbr / librbl / librepute / libreprrd | Conditional | N/A — out of scope | — |
| **B. Executables** | | | |
| opendkim daemon | `sbin_PROGRAMS` | ✅ | — |
| opendkim-genzone | `sbin_PROGRAMS` | ✅ | — |
| opendkim-testkey | `sbin_PROGRAMS` | ✅ | — |
| opendkim-testmsg | `sbin_PROGRAMS` | ✅ | — |
| opendkim-genkey (script) | `dist_sbin_SCRIPTS` | ✅ configure_file | — |
| miltertest | `bin_PROGRAMS` (if Lua) | ❌ not built | **HIGH** |
| **C. Feature detection** | | | |
| OpenSSL 3 | PKG_CHECK_MODULES | ✅ find_package | — |
| libmilter | manual search | ✅ find_library | — |
| LMDB | AC_CHECK_LIB | ✅ pkg_check_modules | — |
| libunbound | manual search | ✅ pkg_check_modules | — |
| pthreads | AX_PTHREAD | ✅ find_package(Threads) | — |
| libresolv | AC_SEARCH_LIBS | ✅ find_library | — |
| Lua 5.4 | PKG_CHECK_MODULES lua5.1 | ✅ find_package(Lua 5.4) | — |
| strlcpy/strlcat | AC_CHECK_FUNCS + search | ✅ check_function_exists | — |
| inet_pton / inet_ntop / getaddrinfo | AC_SEARCH_LIBS | ✅ check_function_exists | — |
| res_ninit / res_setservers | AC_SEARCH_LIBS | ✅ check_symbol_exists | — |
| smfi_version | AC_CHECK_FUNC | ✅ check_symbol_exists | — |
| smfi_insheader | AC_CHECK_FUNC | ❌ not checked | **MEDIUM** |
| smfi_opensocket | AC_CHECK_FUNC | ❌ not checked | **MEDIUM** |
| smfi_progress | AC_CHECK_FUNC | ❌ not checked | **MEDIUM** |
| smfi_setsymlist | AC_CHECK_FUNC | ❌ not checked | **MEDIUM** |
| sockaddr_un.sun_len | AC_CHECK_MEMBER | ❌ not checked | **MEDIUM** |
| sockaddr_in.sin_len | AC_CHECK_MEMBER | ❌ not checked | **MEDIUM** |
| sockaddr_in6.sin6_len | AC_CHECK_MEMBER | ❌ not checked | **MEDIUM** |
| GnuTLS | PKG_CHECK_MODULES | N/A — out of scope | — |
| BerkeleyDB / OpenDBX / LDAP / TRE | various | N/A — out of scope | — |
| **D. Compile-time defines** | | | |
| VERSION / PACKAGE_VERSION | AC_INIT | ✅ configure_file | — |
| LIBOPENDKIM_FEATURE_STRING | AC_DEFINE_UNQUOTED | ✅ configure_file | — |
| HAVE_SHA256 | AC_CHECK_DECL | ✅ hardcoded (OpenSSL 3 guarantee) | — |
| USE_MDB | AC_DEFINE | ✅ hardcoded | — |
| _FFR_RESIGN / _FFR_IDENTITY_HEADER / _FFR_SENDER_MACRO | FFR_FEATURE | ✅ hardcoded | — |
| HAVE_RES_NINIT / HAVE_RES_SETSERVERS | AC_DEFINE | ✅ | — |
| HAVE_INET_PTON / INET_NTOP / GETADDRINFO | AC_DEFINE | ✅ | — |
| HAVE_LIMITS_H / HAVE_STDBOOL_H | AC_CHECK_HEADERS | ✅ | — |
| HAVE_SYS_PARAM_H / SYS_FILE_H / PATHS_H | AC_CHECK_HEADERS | ✅ | — |
| USE_BSD_H / USE_STRL_H | AC_DEFINE | ✅ | — |
| SENDMAIL_PATH / CONFIG_BASE | AC_PATH_PROG / CPPFLAGS | ✅ | — |
| HAVE_SMFI_VERSION | AC_CHECK_FUNC | ✅ | — |
| USE_UNBOUND / HAVE_UNBOUND_H | AC_DEFINE | ✅ | — |
| USE_LUA (source) vs WITH_LUA (config) | AC_DEFINE USE_LUA | ⚠️ inconsistency | **MEDIUM** |
| HAVE_SMFI_INSHEADER/OPENSOCKET/PROGRESS/SETSYMLIST | AC_CHECK_FUNC | ❌ not defined | **MEDIUM** |
| HAVE_SUN_LEN / HAVE_SIN_LEN / HAVE_SIN6_LEN | AC_CHECK_MEMBER | ❌ not defined | **MEDIUM** |
| BIND_8_COMPAT / DARWIN | case $host_os | N/A — macOS not a target | — |
| **E. Installation targets** | | | |
| dkim.h | pkginclude_HEADERS | ✅ | — |
| libopendkim.so | lib_LTLIBRARIES | ✅ | — |
| libopendkim.a | not in autotools | ✅ (extra) | — |
| opendkim / opendkim-gen* / testkey / testmsg | sbin_PROGRAMS | ✅ all | — |
| opendkim-genkey (script) | dist_sbin_SCRIPTS | ✅ | — |
| opendkim.8 + genkey/genzone/testkey/testmsg.8 | man_MANS | ✅ | — |
| opendkim.conf.5 | man_MANS | ✅ | — |
| opendkim-lua.3 (if Lua) | man_MANS | ❌ not installed | **LOW** |
| miltertest.8 (if Lua) | man_MANS | ❌ not installed | **LOW** |
| opendkim.conf.sample | dist_doc_DATA | ❌ not installed | LOW |
| setup/screen/final.lua.sample (if Lua) | dist_doc_DATA | ❌ not installed | LOW |
| libopendkim.pc | pkgconfig_DATA | ❌ not generated | **HIGH** |
| libut.so + ut.h | lib_LTLIBRARIES | ❌ not built | HIGH (see A) |
| **F. pkg-config .pc file** | | | |
| opendkim.pc | ✅ from opendkim.pc.in | ❌ not generated | **HIGH** |
| **G. Integration tests** | | | |
| libopendkim unit tests | libopendkim/tests/Makefile.am | ✅ 100+ via CTest | — |
| miltertest daemon integration tests | opendkim/tests/Makefile.am (25+ scripts) | ❌ not in CTest | **HIGH** |
| **H. Platform-specific** | | | |
| macOS: BIND_8_COMPAT / DARWIN / require unbound | case $host_os darwin | N/A — not a target | — |
| BSD: sin_len / sun_len / sin6_len | AC_CHECK_MEMBER | ❌ not checked | **MEDIUM** |
| BSD: libunbound required (error if missing) | macOS only | Partial (warning only) | LOW |

---

## Prioritised Gap List

### Priority 1 — CRITICAL: libar directory deleted

**Finding:** `SCOPE.md` explicitly keeps `libar/` ("Async DNS resolver. Solves real operational
timeout problems. Keep.") and lists `libresolv / libar: Required` in the final dependencies.
The `libar/` directory no longer exists in the repository — it was silently deleted during
subsystem removal.

**Impact:** The async DNS resolver is absent from both the CMake build and the source tree.
Without it, the daemon uses only the synchronous resolver (libresolv), which can block the
milter worker threads during slow or failing DNS lookups — a known operational problem.

**Action required:** Restore `libar/` from git history, add `libar/CMakeLists.txt`, link
`opendkim_daemon` against it.

---

### Priority 2 — HIGH: libut not built by CMake

**Finding:** `SCOPE.md` keeps `libut/` ("Internal utility library used by libopendkim. Keep.").
Source files `libut/ut.c` and `libut/ut.h` exist. There is no `libut/CMakeLists.txt` and no
`add_subdirectory(libut)` in the root `CMakeLists.txt`.

**Impact:** If `libopendkim` calls into `libut`, those calls will link against nothing.
Whether it currently links is undetected because the CMake build has not added the dependency.

**Action required:** Add `libut/CMakeLists.txt`, add `add_subdirectory(libut)` to root
`CMakeLists.txt`, and link `opendkim` (shared) against it.

---

### Priority 3 — HIGH: miltertest not built by CMake

**Finding:** `SCOPE.md` keeps `miltertest/` ("Lua-based milter testing framework. Keep for
integration tests."). Source `miltertest/miltertest.c` and `miltertest/miltertest.8` exist.
There is no `miltertest/CMakeLists.txt` and no `add_subdirectory(miltertest)` in the root
`CMakeLists.txt`.

**Impact:** Without miltertest, the 25+ miltertest-based daemon integration tests
in `opendkim/tests/` cannot run. The CTest suite only covers the libopendkim unit tests,
leaving the full milter protocol path untested.

**Action required:** Add `miltertest/CMakeLists.txt` (builds miltertest, installs to bindir),
add `add_subdirectory(miltertest)` under `if(WITH_LUA)` in root `CMakeLists.txt`, then add
`add_subdirectory(tests)` in `opendkim/CMakeLists.txt` to register the integration tests with CTest.

---

### Priority 4 — HIGH: opendkim daemon integration tests not in CTest

**Finding:** `opendkim/tests/Makefile.am` defines 25+ shell-script tests
(t-sign-ss, t-verify-ss, t-sign-rs, t-verify-revoked, etc.) that run the full milter daemon
via miltertest. There is no `add_subdirectory(tests)` in `opendkim/CMakeLists.txt`. These
tests are entirely absent from the CTest suite.

**Impact:** `ctest` runs only libopendkim unit tests. The live signing/verification pipeline
through the milter protocol is never exercised by the automated test suite.

**Action required:** After miltertest is built (Priority 3), add `opendkim/tests/CMakeLists.txt`
registering the shell scripts as CTest tests with `add_test(... COMMAND bash ${script})`.
Requires the test socket and the `opendkim_daemon` to be available.

---

### Priority 5 — HIGH: pkg-config .pc file not generated

**Finding:** `libopendkim/Makefile.am` installs `opendkim.pc` (generated from
`libopendkim/opendkim.pc.in`) to `$(libdir)/pkgconfig`. CMake generates no `.pc` file.

**Impact:** Packages and build systems that use `pkg-config --libs opendkim` to link against
libopendkim will fail to find it after a CMake-based installation.

**Action required:** Add a `configure_file(opendkim.pc.cmake.in ...)` step in
`libopendkim/CMakeLists.txt` and an `install(FILES ...)` for the generated `.pc` file.
The source template `libopendkim/opendkim.pc.in` can be adapted (replace `@VAR@` with
CMake `${VAR}` forms or keep `@ONLY`).

---

### Priority 6 — MEDIUM: USE_LUA / WITH_LUA naming inconsistency

**Finding:** Autotools defines `USE_LUA` (`AC_DEFINE([USE_LUA], 1, ...)`).

In CMake:
- `libopendkim/CMakeLists.txt` `configure_opendkim_target()` sets `WITH_LUA=1`
- `opendkim/CMakeLists.txt` `configure_daemon_target()` sets `USE_LUA=1`  
- `build-config.h.cmake.in` has `#cmakedefine WITH_LUA 1`

Any source file that includes `build-config.h` and checks `#ifdef USE_LUA` will not
see the define; only `WITH_LUA` is in the header. Code in `opendkim/` gets `USE_LUA=1`
via a direct `-D` flag, bypassing the header — but this is fragile and inconsistent.

**Action required:** Pick one name. `USE_LUA` is the existing autotools name and what the
source code checks. Change `WITH_LUA=1` in `configure_opendkim_target()` to `USE_LUA=1`
and update `build-config.h.cmake.in` to `#cmakedefine USE_LUA 1`.

---

### Priority 7 — MEDIUM: Milter capability checks missing from CMake

**Finding:** `configure.ac` checks four milter functions via `AC_CHECK_FUNC` and defines:
- `HAVE_SMFI_INSHEADER` — inserts header at position (vs append)
- `HAVE_SMFI_OPENSOCKET` — opens the milter socket manually
- `HAVE_SMFI_PROGRESS` — sends progress heartbeats
- `HAVE_SMFI_SETSYMLIST` — requests specific MTA macros

None of these are checked in CMake or present in `build-config.h.cmake.in`.

**Impact:** The daemon will compile without these guards, defaulting to whichever code path
the `#ifdef` guards surround. On a libmilter that lacks one of these functions, this may
produce a compile error or silent misbehaviour.

**Action required:** Add four `check_symbol_exists()` calls (or `check_function_exists()`)
for these milter functions in `opendkim/CMakeLists.txt` and add the corresponding
`#cmakedefine` entries to `build-config.h.cmake.in`.

---

### Priority 8 — MEDIUM: BSD socket structure member checks missing

**Finding:** `configure.ac` checks three BSD-specific struct members:
- `sockaddr_un.sun_len` → `HAVE_SUN_LEN`
- `sockaddr_in.sin_len` → `HAVE_SIN_LEN`
- `sockaddr_in6.sin6_len` → `HAVE_SIN6_LEN`

FreeBSD and OpenBSD populate these fields; Linux does not. The daemon's socket handling
code uses these defines to set the length field on BSD. CMake checks neither.

**Impact:** Builds on FreeBSD 13+ and OpenBSD 7+ (both in-scope per `SCOPE.md`) will
miss the `sin_len` population, producing broken Unix socket connections.

**Action required:** Add three `check_struct_has_member()` calls in
`libopendkim/CMakeLists.txt` (or a shared detection file) and add the three
`#cmakedefine` entries to `build-config.h.cmake.in`. The module `CheckStructHasMember`
is already included in `libopendkim/CMakeLists.txt`.

---

### Priority 9 — LOW: opendkim-lua.3 man page not installed

**Finding:** `opendkim/Makefile.am` installs `opendkim-lua.3` when `LUA` is enabled.
`opendkim/CMakeLists.txt` installs man8 pages and `opendkim.conf.5` but not `opendkim-lua.3`.

**Action required:** Add to the `if(WITH_LUA)` block in `opendkim/CMakeLists.txt`:
```cmake
install(FILES opendkim-lua.3 DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
```

---

### Priority 10 — LOW: Sample and documentation files not installed

**Finding:** The following files are installed by autotools as `dist_doc_DATA` but not by CMake:
- `opendkim/opendkim.conf.sample`
- `opendkim/opendkim.conf.simple` (generated from `.in`)
- `opendkim/opendkim.conf.simple-verify` (generated from `.in`)
- `opendkim/setup.lua.sample`, `screen.lua.sample`, `final.lua.sample` (if Lua)

**Impact:** A CMake-based system install does not deploy any example config, making it
harder for administrators to set up the daemon. The Debian package currently ships the
sample via `debian/*.install` entries, but a vanilla `cmake --install` does not.

**Action required:** Add `install(FILES ...)` entries for sample configs and, under
`if(WITH_LUA)`, for the three Lua sample scripts.

---

## Autotools Files Safe to Delete Once CMake Is Complete

The following files are autotools-specific and serve no purpose once the CMake build
covers all gaps above. Delete only after all gaps are resolved and the CMake build is
verified on Linux, FreeBSD, and OpenBSD.

### Build system machinery
```
configure.ac
aclocal.m4          # generated
configure           # generated
m4/                 # autoconf macro directory
build-aux/          # auxiliary scripts (install-sh, missing, etc.)
```

### Top-level makefiles
```
Makefile.am
Makefile.in         # generated
```

### Per-subdirectory makefiles
```
libopendkim/Makefile.am
libopendkim/Makefile.in
libopendkim/docs/Makefile.am
libopendkim/tests/Makefile.am    # CMakeLists.txt already exists
libut/Makefile.am                # once libut/CMakeLists.txt is written
miltertest/Makefile.am           # once miltertest/CMakeLists.txt is written
opendkim/Makefile.am
opendkim/tests/Makefile.am       # once opendkim/tests/CMakeLists.txt is written
docs/Makefile.am
```

### .in files whose CMake equivalents exist or will exist
```
opendkim/opendkim-genkey.in           # already used by CMake (configure_file)
opendkim/opendkim.conf.simple.in      # once CMake installs sample configs
opendkim/opendkim.conf.simple-verify.in
libopendkim/opendkim.pc.in            # once CMake generates opendkim.pc
libut/ut.pc.in                        # once libut gap is fixed
```

### Out-of-scope files (can be deleted now, already removed from builds)
```
contrib/           # out of scope per SCOPE.md (archive to separate branch)
libvbr/            # deleted/out of scope
librbl/            # deleted/out of scope
reprrd/            # deleted/out of scope
reputation/        # deleted/out of scope
stats/             # deleted/out of scope
www/               # deleted/out of scope
autobuild/         # stats/jansson tooling, out of scope
```

### Keep (needed by CMake build or informational)
```
libopendkim/opendkim.pc.in      # adapt to cmake configure_file template
libut/ut.pc.in                  # adapt to cmake configure_file template
opendkim/opendkim-genkey.in     # already used by cmake configure_file
SCOPE.md                        # authoritative project scope
```

---

## Notes on Intentional Divergences from Autotools

The following differences between the autotools and CMake builds are **intentional** per
`SCOPE.md` and are **not** gaps:

1. **Static library added.** CMake builds both `libopendkim.so` and `libopendkim.a`.
   Autotools builds only the shared library. The static variant is useful for
   static-analysis and test builds.

2. **Lua version pinned to 5.4.** Autotools searched for Lua 5.1+. CMake requires
   exactly Lua 5.4 (`find_package(Lua 5.4 EXACT)`). This is deliberate: `SCOPE.md`
   targets Lua 5.4 and the C embedding code has been updated for the 5.4 API.

3. **GnuTLS detection removed.** Autotools had a full parallel `--with-gnutls` path.
   CMake requires only OpenSSL 3. This is an explicit scope decision in `SCOPE.md`.

4. **BerkeleyDB, OpenDBX, LDAP, TRE, memcached, curl, jansson, Erlang removed.**
   All removed per `SCOPE.md`. No CMake equivalents needed.

5. **All dropped FFR features.** `atps`, `diffheaders`, `replace_rules`, `rate_limit`,
   `rbl`, `vbr`, `stats`, `statsext`, `socketdb`, `db_handle_pools`, `ldap_caching`,
   `postgres_reconnect_hack`, `reprrd`, `reputation`, `default_sender` — all removed
   per `SCOPE.md`. The promoted FFR features (`resign`, `identity_header`,
   `sender_macro`) are hardcoded ON in CMake, which is correct.

6. **macOS not a target.** The `BIND_8_COMPAT` and `DARWIN` defines from the
   `case $host_os in *-darwin*)` block have no CMake equivalent. `SCOPE.md` targets
   Linux, FreeBSD 13+, and OpenBSD 7+ only.
