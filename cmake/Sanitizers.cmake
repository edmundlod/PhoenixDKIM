# cmake/Sanitizers.cmake
#
# AddressSanitizer, UndefinedBehaviorSanitizer, and LeakSanitizer.
#
# These are development and CI tools — never enable in production builds.
# Runtime overhead is 2-10x and memory layout is altered.
#
# Include this module BEFORE Hardening.cmake in the top-level CMakeLists.txt.
# Hardening.cmake reads the OPENDKIM_ENABLE_ASAN and OPENDKIM_ENABLE_UBSAN
# options to suppress _FORTIFY_SOURCE when any sanitizer is active (ASAN/UBSAN
# intercept glibc memory functions; FORTIFY_SOURCE on top causes false positives).
#
# Call apply_sanitizers(<target>) on every target that also gets apply_hardening().
# Both functions are no-ops when all sanitizer options are OFF.

include(CheckCCompilerFlag)

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

# ── Validate flag availability ────────────────────────────────────────────────

if(OPENDKIM_ENABLE_ASAN)
    check_c_compiler_flag(-fsanitize=address HARDEN_SAN_HAVE_ASAN)
    if(NOT HARDEN_SAN_HAVE_ASAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_ASAN=ON but -fsanitize=address is not supported. "
            "Use GCC or Clang built with sanitizer support.")
    endif()
endif()

if(OPENDKIM_ENABLE_UBSAN)
    check_c_compiler_flag(-fsanitize=undefined HARDEN_SAN_HAVE_UBSAN)
    if(NOT HARDEN_SAN_HAVE_UBSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_UBSAN=ON but -fsanitize=undefined is not supported. "
            "Use GCC or Clang built with sanitizer support.")
    endif()
    if(OPENDKIM_ENABLE_UBSAN_INTEGER)
        check_c_compiler_flag(-fsanitize=integer HARDEN_SAN_HAVE_UBSAN_INTEGER)
        if(NOT HARDEN_SAN_HAVE_UBSAN_INTEGER)
            message(WARNING
                "OPENDKIM_ENABLE_UBSAN_INTEGER=ON but -fsanitize=integer is not "
                "supported (GCC does not have this flag; use Clang). Ignored.")
        endif()
    endif()
    # -fsanitize=nullability is Clang-only; probe unconditionally, apply if found
    check_c_compiler_flag(-fsanitize=nullability HARDEN_SAN_HAVE_UBSAN_NULLABILITY)
endif()

if(OPENDKIM_ENABLE_UBSAN_INTEGER AND NOT OPENDKIM_ENABLE_UBSAN)
    message(WARNING
        "OPENDKIM_ENABLE_UBSAN_INTEGER=ON has no effect unless "
        "OPENDKIM_ENABLE_UBSAN=ON.")
endif()

if(OPENDKIM_ENABLE_LSAN)
    check_c_compiler_flag(-fsanitize=leak HARDEN_SAN_HAVE_LSAN)
    if(NOT HARDEN_SAN_HAVE_LSAN)
        message(FATAL_ERROR
            "OPENDKIM_ENABLE_LSAN=ON but -fsanitize=leak is not supported.")
    endif()
endif()

# ── Warn on non-Debug build types (single-config generators only) ─────────────

if((OPENDKIM_ENABLE_ASAN OR OPENDKIM_ENABLE_UBSAN OR OPENDKIM_ENABLE_LSAN)
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
    if(OPENDKIM_ENABLE_ASAN OR OPENDKIM_ENABLE_UBSAN OR OPENDKIM_ENABLE_LSAN)
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

endfunction()
