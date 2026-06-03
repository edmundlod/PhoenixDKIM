# cmake/Reproducible.cmake
#
# Reproducible-build support: make the compiled artefacts bit-for-bit identical
# regardless of WHERE and WHEN they are built, so a third party can rebuild from
# source and verify the shipped binaries were not tampered with.
#
# Two classes of non-determinism are addressed here:
#
#   1. Build PATHS leaking into the output.  __FILE__, assert() strings, and
#      DWARF debug info record the absolute source/build directory.  Build the
#      same tree in /home/alice vs /build and the objects differ.
#      Fixed with -ffile-prefix-map (rewrites the recorded prefix to ".").
#
#   2. Build TIMES leaking into the output.  __DATE__/__TIME__/__TIMESTAMP__ and
#      non-deterministic ar(1) timestamps embed the wall clock.  This codebase
#      uses none of those macros today; -Wdate-time makes that a build-visible
#      warning if anyone introduces one, and deterministic-ar zeroes the archive
#      member timestamps in libphoenixdkim.a.
#
# CMake's own configure_file() substitutions are version strings and paths only
# (no timestamps), and SOURCE_DATE_EPOCH needs no clamping here because nothing
# in the build reads the clock — it is honoured automatically by the toolchain
# for anything that would.
#
# Everything is behind PHOENIXDKIM_ENABLE_REPRODUCIBLE (default ON).  The flags
# are near-zero cost and graceful: each is probed and silently skipped if the
# toolchain does not support it, never fatal.  Distro packaging (dpkg-buildflags
# reproducible=+all, rpm macros) injects -ffile-prefix-map of its own; applying
# ours on top is harmless (identical mapping target).
#
# Include this module from the top-level CMakeLists BEFORE add_subdirectory():
# add_compile_options() is directory-scoped and only affects targets defined
# after the call.

include(CheckCCompilerFlag)
include(CMakePushCheckState)

option(PHOENIXDKIM_ENABLE_REPRODUCIBLE
    "Strip build paths from objects (-ffile-prefix-map), warn on \
__DATE__/__TIME__ use (-Wdate-time), and force deterministic static archives so \
builds are bit-for-bit reproducible across machines. Near-zero cost. Default ON."
    ON)

if(NOT PHOENIXDKIM_ENABLE_REPRODUCIBLE)
    message(STATUS "Reproducible builds: disabled (PHOENIXDKIM_ENABLE_REPRODUCIBLE=OFF)")
    return()
endif()

# ── SOURCE_DATE_EPOCH (informational) ─────────────────────────────────────────
# Reported only for transparency; nothing in this build embeds the clock, so
# there is no value to clamp.  The toolchain honours it automatically if a
# date-bearing construct is ever added (and -Wdate-time below flags that case).
if(DEFINED ENV{SOURCE_DATE_EPOCH})
    message(STATUS "Reproducible builds: SOURCE_DATE_EPOCH=$ENV{SOURCE_DATE_EPOCH}")
endif()

# ── Build-path canonicalisation ───────────────────────────────────────────────
# -ffile-prefix-map (GCC 8+/Clang 10+) covers both __FILE__/macro strings AND
# DWARF paths in one flag.  Older toolchains get the two narrower flags it
# subsumes: -fdebug-prefix-map (debug info) and -fmacro-prefix-map (__FILE__).
#
# Probe with a throwaway map — support is independent of the path — then apply
# the real mappings for the source and binary trees.  Mapping both keeps
# generated headers (build-config.h, dkim.h, under CMAKE_BINARY_DIR) clean even
# for out-of-tree builds located outside the source directory.
cmake_push_check_state(RESET)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    # Clang warns rather than errors on flags it does not implement; turn that
    # into a probe failure (same rationale as Hardening.cmake).
    set(CMAKE_REQUIRED_FLAGS "-Werror=unused-command-line-argument")
endif()

check_c_compiler_flag("-ffile-prefix-map=/a=b"  REPRO_CC_FILE_PREFIX_MAP)
if(NOT REPRO_CC_FILE_PREFIX_MAP)
    check_c_compiler_flag("-fdebug-prefix-map=/a=b" REPRO_CC_DEBUG_PREFIX_MAP)
    check_c_compiler_flag("-fmacro-prefix-map=/a=b" REPRO_CC_MACRO_PREFIX_MAP)
endif()
cmake_pop_check_state()

if(REPRO_CC_FILE_PREFIX_MAP)
    add_compile_options(
        "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
        "-ffile-prefix-map=${CMAKE_BINARY_DIR}=."
    )
    message(STATUS "Reproducible builds: -ffile-prefix-map (source and binary dirs -> .)")
else()
    if(REPRO_CC_DEBUG_PREFIX_MAP)
        add_compile_options(
            "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=."
            "-fdebug-prefix-map=${CMAKE_BINARY_DIR}=."
        )
    endif()
    if(REPRO_CC_MACRO_PREFIX_MAP)
        add_compile_options(
            "-fmacro-prefix-map=${CMAKE_SOURCE_DIR}=."
            "-fmacro-prefix-map=${CMAKE_BINARY_DIR}=."
        )
    endif()
    if(REPRO_CC_DEBUG_PREFIX_MAP OR REPRO_CC_MACRO_PREFIX_MAP)
        message(STATUS "Reproducible builds: -fdebug/-fmacro-prefix-map "
                       "(no unified -ffile-prefix-map on this toolchain)")
    else()
        message(STATUS "Reproducible builds: toolchain has no *-prefix-map flag; "
                       "build paths may leak into debug info")
    endif()
endif()

# ── Date/time-macro guard ─────────────────────────────────────────────────────
# -Wdate-time warns on __DATE__/__TIME__/__TIMESTAMP__.  Applied globally (not
# fatal) so introducing one shows up in the build log and gets caught in review.
check_c_compiler_flag(-Wdate-time REPRO_CC_WDATE_TIME)
if(REPRO_CC_WDATE_TIME)
    add_compile_options(-Wdate-time)
endif()

# ── Deterministic static archives ─────────────────────────────────────────────
# libphoenixdkim.a ships in the -dev package.  ar(1) records each member's mtime
# and uid/gid by default; the GNU "D" modifier zeroes them.  Debian's binutils
# is built --enable-deterministic-archives so this is already the default there,
# but standalone builds on other systems may not be — set it explicitly.
#
# Guarded to GNU ar only: the "D" modifier is GNU-specific, and the BSD ar on
# the FreeBSD/OpenBSD targets does not understand it.  ${CMAKE_AR} is resolved
# by project()/enable_language before any module runs, so it is available here.
if(CMAKE_AR)
    execute_process(
        COMMAND "${CMAKE_AR}" --version
        OUTPUT_VARIABLE _repro_ar_version
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(_repro_ar_version MATCHES "GNU ar|GNU Binutils|LLVM")
        # qcD: quick-append, create, deterministic.  Mirror CMake's default
        # archive rules with the D modifier added.  LLVM's llvm-ar also accepts
        # the D modifier (and defaults to deterministic), so it is safe there too.
        set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>"
            CACHE INTERNAL "Deterministic ar create rule" FORCE)
        set(CMAKE_C_ARCHIVE_APPEND "<CMAKE_AR> qD  <TARGET> <LINK_FLAGS> <OBJECTS>"
            CACHE INTERNAL "Deterministic ar append rule" FORCE)
        if(CMAKE_RANLIB)
            set(CMAKE_C_ARCHIVE_FINISH "<CMAKE_RANLIB> -D <TARGET>"
                CACHE INTERNAL "Deterministic ranlib rule" FORCE)
        endif()
        message(STATUS "Reproducible builds: deterministic static archives (ar D)")
    endif()
endif()
