# cmake/Sanitizers.cmake
#
# AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, and
# MemorySanitizer.
#
# These are development and CI tools — never enable in production builds.
# Runtime overhead is 2-10x and memory layout is altered.
#
# Include this module BEFORE Hardening.cmake in the top-level CMakeLists.txt.
# Hardening.cmake reads the OPENDKIM_ENABLE_ASAN, OPENDKIM_ENABLE_UBSAN, and
# OPENDKIM_ENABLE_MSAN options to suppress _FORTIFY_SOURCE when any sanitizer
# is active (ASAN/UBSAN/MSan intercept glibc memory functions; FORTIFY_SOURCE
# on top causes false positives).
#
# Call apply_sanitizers(<target>) on every target that also gets apply_hardening().
# Both functions are no-ops when all sanitizer options are OFF.

include(CheckCSourceCompiles)
include(CMakePushCheckState)

# ── Helper: probe a sanitizer flag at compile AND link time ───────────────────
#
# check_c_compiler_flag() passes the flag only at compile time (via
# CMAKE_REQUIRED_FLAGS).  Sanitizer flags must also appear on the link command
# so the compiler driver can inject the runtime library (libasan, libubsan, …).
# Without the flag on the link line GCC 16 / CMake 4.x emit undefined-reference
# errors for __asan_init etc. even though the compiler itself supports the flag.
#
# This macro passes the flag via both CMAKE_REQUIRED_FLAGS (compile) and
# CMAKE_REQUIRED_LINK_OPTIONS (link), which is the correct approach for any
# flag that affects both the object file and the final binary.

macro(_check_sanitizer_flag _san_flag _san_result)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_FLAGS        "${_san_flag}")
    set(CMAKE_REQUIRED_LINK_OPTIONS "${_san_flag}")
    check_c_source_compiles("int main(void){return 0;}" ${_san_result})
    cmake_pop_check_state()
endmacro()

# ── Options ───────────────────────────────────────────────────────────────────

option(OPENDKIM_ENABLE_ASAN
    "Enable AddressSanitizer: heap/stack overflows, UAF, double-free. \
Implies -fno-omit-frame-pointer for readable stack traces. \
Never use in production."
    OFF)

option(OPENDKIM_ENABLE_UBSAN
    "Enable UndefinedBehaviorSanitizer: null deref, misaligned access, \
invalid bool/enum, signed overflow (via -fsanitize=undefined). \
Never use in production."
    OFF)

option(OPENDKIM_ENABLE_UBSAN_INTEGER
    "Add -fsanitize=integer to UBSAN. Catches integer overflow and truncation \
but is very noisy in legacy C codebases — many implicit promotions and casts \
will fire. Enable separately once the basic UBSAN pass is clean. \
Requires OPENDKIM_ENABLE_UBSAN=ON. Default OFF."
    OFF)

option(OPENDKIM_ENABLE_LSAN
    "Enable standalone LeakSanitizer. On Linux, ASAN already bundles LSAN — \
enable this option only when ASAN is OFF. Never use in production."
    OFF)

option(OPENDKIM_ENABLE_MSAN
    "Enable MemorySanitizer: detects reads from uninitialised memory. \
Clang-only; GCC does not support -fsanitize=memory. \
CRITICAL: ALL linked libraries (libc, libssl, libmilter, …) must themselves \
be compiled with -fsanitize=memory, or the run will generate large numbers of \
false positives. Build a fully-instrumented sysroot before enabling this. \
Mutually exclusive with ASAN and LSAN. Never use in production."
    OFF)

# ── Validate flag availability ────────────────────────────────────────────────

if(OPENDKIM_ENABLE_ASAN)
    _check_sanitizer_flag(-fsanitize=address HARDEN_SAN_HAVE_ASAN)
    if(NOT HARDEN_SAN_HAVE_ASAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_ASAN=ON but -fsanitize=address is not supported. "
            "Use GCC or Clang built with sanitizer support.")
    endif()
endif()

if(OPENDKIM_ENABLE_UBSAN)
    _check_sanitizer_flag(-fsanitize=undefined HARDEN_SAN_HAVE_UBSAN)
    if(NOT HARDEN_SAN_HAVE_UBSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_UBSAN=ON but -fsanitize=undefined is not supported. "
            "Use GCC or Clang built with sanitizer support.")
    endif()
    if(OPENDKIM_ENABLE_UBSAN_INTEGER)
        _check_sanitizer_flag(-fsanitize=integer HARDEN_SAN_HAVE_UBSAN_INTEGER)
        if(NOT HARDEN_SAN_HAVE_UBSAN_INTEGER)
            message(WARNING
                "OPENDKIM_ENABLE_UBSAN_INTEGER=ON but -fsanitize=integer is not "
                "supported (GCC does not have this flag; use Clang). Ignored.")
        endif()
    endif()
    # -fsanitize=nullability is Clang-only; probe unconditionally, apply if found
    _check_sanitizer_flag(-fsanitize=nullability HARDEN_SAN_HAVE_UBSAN_NULLABILITY)
endif()

if(OPENDKIM_ENABLE_UBSAN_INTEGER AND NOT OPENDKIM_ENABLE_UBSAN)
    message(WARNING
        "OPENDKIM_ENABLE_UBSAN_INTEGER=ON has no effect unless "
        "OPENDKIM_ENABLE_UBSAN=ON.")
endif()

if(OPENDKIM_ENABLE_LSAN)
    _check_sanitizer_flag(-fsanitize=leak HARDEN_SAN_HAVE_LSAN)
    if(NOT HARDEN_SAN_HAVE_LSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_LSAN=ON but -fsanitize=leak is not supported.")
    endif()
endif()

if(OPENDKIM_ENABLE_MSAN)
    # MSan is Clang-only; give an early, clear error if the compiler lacks it.
    _check_sanitizer_flag(-fsanitize=memory HARDEN_SAN_HAVE_MSAN)
    if(NOT HARDEN_SAN_HAVE_MSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_MSAN=ON but -fsanitize=memory is not supported. "
            "MemorySanitizer requires Clang; GCC does not implement it.")
    endif()

    # MSan and ASAN instrument the same memory functions; running both together
    # is not supported by any compiler and will produce link errors or crashes.
    if(OPENDKIM_ENABLE_ASAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_MSAN and OPENDKIM_ENABLE_ASAN cannot both be ON. "
            "AddressSanitizer and MemorySanitizer instrument overlapping "
            "runtime functions and cannot be combined in a single build.")
    endif()

    # LSAN is bundled inside ASAN on Linux; standalone LSAN conflicts with MSan
    # for the same reason.
    if(OPENDKIM_ENABLE_LSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_MSAN and OPENDKIM_ENABLE_LSAN cannot both be ON.")
    endif()
endif()

# ── Warn on non-Debug build types (single-config generators only) ─────────────

if((OPENDKIM_ENABLE_ASAN OR OPENDKIM_ENABLE_UBSAN OR OPENDKIM_ENABLE_LSAN
        OR OPENDKIM_ENABLE_MSAN)
        AND DEFINED CMAKE_BUILD_TYPE
        AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug"
        AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(WARNING
        "Sanitizers are active with CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}. "
        "Stack traces are most readable with Debug or RelWithDebInfo. "
        "Release optimisations may inline or eliminate frames.")
endif()

# ── apply_sanitizers(<target>) ────────────────────────────────────────────────

function(apply_sanitizers tgt)

    # -fno-omit-frame-pointer: required for readable stack traces under any
    # sanitizer.  Emitted once here rather than duplicated per-sanitizer block.
    if(OPENDKIM_ENABLE_ASAN OR OPENDKIM_ENABLE_UBSAN OR OPENDKIM_ENABLE_LSAN
            OR OPENDKIM_ENABLE_MSAN)
        target_compile_options(${tgt} PRIVATE -fno-omit-frame-pointer)
    endif()

    # ── ASAN ─────────────────────────────────────────────────────────────────
    # On Linux, ASAN already includes LSAN; no separate -fsanitize=leak needed.

    if(OPENDKIM_ENABLE_ASAN)
        target_compile_options(${tgt} PRIVATE -fsanitize=address)
        target_link_options(${tgt} PRIVATE -fsanitize=address)
    endif()

    # ── UBSAN ─────────────────────────────────────────────────────────────────
    # -fsanitize=undefined: the standard set (null deref, misalignment, etc.).
    # -fsanitize=integer: opt-in via OPENDKIM_ENABLE_UBSAN_INTEGER because it
    #   is extremely noisy in legacy C; enable only after the base UBSAN pass
    #   is clean.
    # -fsanitize=nullability: Clang-only; applied if available.

    if(OPENDKIM_ENABLE_UBSAN)
        set(_ubsan_flags -fsanitize=undefined)

        if(OPENDKIM_ENABLE_UBSAN_INTEGER AND HARDEN_SAN_HAVE_UBSAN_INTEGER)
            list(APPEND _ubsan_flags -fsanitize=integer)
        endif()

        if(HARDEN_SAN_HAVE_UBSAN_NULLABILITY)
            list(APPEND _ubsan_flags -fsanitize=nullability)
        endif()

        target_compile_options(${tgt} PRIVATE ${_ubsan_flags})
        target_link_options(${tgt} PRIVATE ${_ubsan_flags})
    endif()

    # ── Standalone LSAN ───────────────────────────────────────────────────────
    # Only applied when ASAN is OFF; ASAN on Linux already bundles LSAN.

    if(OPENDKIM_ENABLE_LSAN AND NOT OPENDKIM_ENABLE_ASAN)
        target_compile_options(${tgt} PRIVATE -fsanitize=leak)
        target_link_options(${tgt} PRIVATE -fsanitize=leak)
    endif()

    # ── MSan ──────────────────────────────────────────────────────────────────
    # -fsanitize=memory: detect reads from uninitialised memory.
    # Clang-only; mutually exclusive with ASAN and LSAN (checked at configure
    # time above).  Requires a fully MSan-instrumented build of every linked
    # library — without it, false positives on libc internals flood the output.
    # -fsanitize-memory-track-origins=2: record the allocation/store site for
    #   each uninitialised byte so the report shows WHERE the bad value came
    #   from, not just WHERE it was read.  Level 2 is the most precise (and
    #   most expensive — ~2.5× overhead on top of the baseline ~3×).
    #   Level 1 tracks origins at a lower cost if 2 is too slow in practice.

    if(OPENDKIM_ENABLE_MSAN)
        target_compile_options(${tgt} PRIVATE
            -fsanitize=memory
            -fsanitize-memory-track-origins=2)
        target_link_options(${tgt} PRIVATE -fsanitize=memory)
    endif()

endfunction()
