# cmake/Hardening.cmake
#
# Compile-time security hardening for all targets (runtime, tools, and tests).
#
# Usage: call apply_hardening(<target>) on every C target.
#
# Link-hardening flags (PIE, RELRO, BIND_NOW) are behind OPENDKIM_ENABLE_LINK_HARDENING
# (default OFF).  Distro build infrastructure (dpkg-buildflags, rpm hardening macros,
# FreeBSD/OpenBSD ports frameworks) injects these already.  Enabling them here on top
# causes duplicate-flag warnings and conflicts with downstream maintainers.  Set ON only
# when building completely outside a distro environment.
#
# -z noexecstack is split into its own option (OPENDKIM_ENABLE_NOEXECSTACK, default ON)
# because it has essentially no downside and is not part of the PIE/RELRO policy debate.
#
# Extra high-noise conversion/alignment warnings (OPENDKIM_ENABLE_EXTRA_WARNINGS, default
# OFF) are provided for targeted cleanup sessions.
#
# Sanitizers live in Sanitizers.cmake.  Include that module BEFORE this one so its
# option variables are defined when the FORTIFY_SOURCE suppression guard runs.

include(CheckCCompilerFlag)
include(CheckLinkerFlag)
include(CheckCSourceCompiles)
include(CMakePushCheckState)

# ── _FORTIFY_SOURCE level ─────────────────────────────────────────────────────
#
# Level 3 (GCC 12+ / Clang 14+ + glibc 2.35+) adds runtime-size checks for
# dynamically-sized buffers.  Level 2 is the safe baseline everywhere else.
# Probe with -Werror -O1 so any compatibility warning from the compiler or libc
# becomes a hard error and we fall back to 2.
#
# apply_hardening() prepends -U_FORTIFY_SOURCE before setting the level so distro
# compiler wrappers that already inject -D_FORTIFY_SOURCE=2 do not conflict.

cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_FLAGS "-O1 -Werror")
check_c_source_compiles([[
#undef  _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 3
#include <string.h>
int main(void) { return 0; }
]] HARDEN_FORTIFY_SOURCE_3_OK)
cmake_pop_check_state()

if(HARDEN_FORTIFY_SOURCE_3_OK)
    set(HARDEN_FORTIFY_LEVEL 3)
else()
    set(HARDEN_FORTIFY_LEVEL 2)
endif()
message(STATUS "Hardening: _FORTIFY_SOURCE=${HARDEN_FORTIFY_LEVEL}")

# ── Compile flag probes ───────────────────────────────────────────────────────

# Code-generation / correctness
check_c_compiler_flag(-fstack-protector-strong   HARDEN_CC_STACK_PROTECTOR_STRONG)
check_c_compiler_flag(-fstack-clash-protection   HARDEN_CC_STACK_CLASH_PROTECTION)
check_c_compiler_flag(-fcf-protection=full       HARDEN_CC_CF_PROTECTION)
check_c_compiler_flag(-fno-strict-aliasing       HARDEN_CC_NO_STRICT_ALIASING)
check_c_compiler_flag(-fwrapv                    HARDEN_CC_WRAPV)
check_c_compiler_flag(-fno-omit-frame-pointer    HARDEN_CC_NO_OMIT_FRAME_POINTER)

# Warnings — simple -Wfoo flags (no =N suffix; handled via loop in apply_hardening)
check_c_compiler_flag(-Wshadow                   HARDEN_CC_WSHADOW)
check_c_compiler_flag(-Wimplicit-fallthrough     HARDEN_CC_WIMPLICIT_FALLTHROUGH)
check_c_compiler_flag(-Wmissing-prototypes       HARDEN_CC_WMISSING_PROTOTYPES)
check_c_compiler_flag(-Wstrict-prototypes        HARDEN_CC_WSTRICT_PROTOTYPES)
check_c_compiler_flag(-Wmissing-declarations     HARDEN_CC_WMISSING_DECLARATIONS)
check_c_compiler_flag(-Wwrite-strings            HARDEN_CC_WWRITE_STRINGS)
check_c_compiler_flag(-Wpointer-arith            HARDEN_CC_WPOINTER_ARITH)
check_c_compiler_flag(-Wcast-qual                HARDEN_CC_WCAST_QUAL)
check_c_compiler_flag(-Wundef                    HARDEN_CC_WUNDEF)

# Warnings — =N suffix flags (must be applied explicitly, NOT via the loop below,
# because the loop cannot reconstruct the =N suffix from the variable name)
check_c_compiler_flag(-Wformat-truncation=2      HARDEN_CC_WFORMAT_TRUNCATION2)
check_c_compiler_flag(-Wformat-overflow=2        HARDEN_CC_WFORMAT_OVERFLOW2)
check_c_compiler_flag(-Wstringop-overflow=4      HARDEN_CC_WSTRINGOP_OVERFLOW4)

# Extra high-noise warnings (optional, default OFF)
option(OPENDKIM_ENABLE_EXTRA_WARNINGS
    "Enable -Wconversion, -Wsign-conversion, and -Wcast-align. These fire \
frequently in legacy C code and are best used during targeted cleanup sessions, \
not as part of normal CI. Default OFF."
    OFF)

if(OPENDKIM_ENABLE_EXTRA_WARNINGS)
    check_c_compiler_flag(-Wconversion      HARDEN_CC_WCONVERSION)
    check_c_compiler_flag(-Wsign-conversion HARDEN_CC_WSIGN_CONVERSION)
    check_c_compiler_flag(-Wcast-align      HARDEN_CC_WCAST_ALIGN)
endif()

# ── Non-executable stack (independent of PIE/RELRO policy) ────────────────────
#
# -z noexecstack marks the ELF PT_GNU_STACK segment non-executable.
# Almost no legitimate code needs an executable stack in 2026; the downside is
# effectively zero.  Distros generally do NOT inject this automatically (unlike
# PIE/RELRO), making it the right default to set in the build system.

option(OPENDKIM_ENABLE_NOEXECSTACK
    "Mark the stack segment non-executable (-z noexecstack). \
Near-zero cost; prevents accidental or JIT-injected executable stacks. \
Default ON."
    ON)

if(OPENDKIM_ENABLE_NOEXECSTACK)
    check_linker_flag(C "-Wl,-z,noexecstack" HARDEN_LD_NOEXECSTACK)
endif()

# ── PIE + RELRO + BIND_NOW (optional, default OFF) ────────────────────────────

option(OPENDKIM_ENABLE_LINK_HARDENING
    "Add -pie, -z relro, and -z now to runtime targets. \
Distro packaging infrastructure (dpkg-buildflags, rpm macros, ports frameworks) \
typically injects these already. Enable only when building outside a distro \
environment. Default OFF."
    OFF)

if(OPENDKIM_ENABLE_LINK_HARDENING)
    check_linker_flag(C "-Wl,-z,relro"  HARDEN_LD_RELRO)
    check_linker_flag(C "-Wl,-z,now"    HARDEN_LD_BINDNOW)
    check_c_compiler_flag(-pie          HARDEN_LD_PIE)
    if(HARDEN_LD_RELRO)
        message(STATUS "Hardening: link hardening ON (PIE, RELRO, BIND_NOW)")
    else()
        message(WARNING "Hardening: OPENDKIM_ENABLE_LINK_HARDENING=ON but the "
                        "linker does not support -z relro. Link hardening disabled.")
    endif()
endif()

# ── apply_hardening(<target>) ─────────────────────────────────────────────────

function(apply_hardening tgt)

    # ── Baseline warnings ─────────────────────────────────────────────────────
    #
    # -Wformat-security: flag printf-family calls with a non-literal format string.
    # -Werror=format-security: make that warning a hard error.  Format strings are
    #   an exploitable bug class; this is the one case where we treat the warning
    #   as fatal without enabling global -Werror, which would break on legacy noise.

    target_compile_options(${tgt} PRIVATE
        -Wall
        -Wextra
        -Wformat
        -Wformat-security
        -Werror=format-security
    )

    # ── Optional warnings — simple -Wfoo flags ────────────────────────────────
    #
    # These variable names map cleanly to flag names via lower-case + underscore→hyphen.
    # Flags with a =N level suffix are handled explicitly below — they cannot be
    # reconstructed correctly by this loop (WFORMAT_TRUNCATION2 → -Wformat-truncation2
    # is wrong; -Wformat-truncation=2 is the real flag).
    #
    # -Wshadow: variable shadowing; caught a real bug in this codebase (Lua hook).
    # -Wimplicit-fallthrough: switch fall-through must be deliberate.
    # -Wmissing-prototypes: global function without prior prototype.
    # -Wstrict-prototypes: K&R-style (no-prototype) function definitions.
    # -Wmissing-declarations: global function defined without a prior declaration.
    # -Wwrite-strings: string literals typed as const char[]; catches char* aliasing.
    # -Wpointer-arith: pointer arithmetic on void* or function pointers.
    # -Wcast-qual: casting away const or volatile qualifier.
    # -Wundef: undefined macro used in #if (catches macro typos).
    #
    # NOTE: -Wstrict-overflow is deliberately absent.  With -fwrapv in effect,
    # signed overflow is well-defined and the compiler does not perform the
    # optimisations that -Wstrict-overflow warns about.  Enabling it would
    # generate immediate noise with no actionable signal.

    foreach(_probe_var
        SHADOW
        IMPLICIT_FALLTHROUGH
        MISSING_PROTOTYPES
        STRICT_PROTOTYPES
        MISSING_DECLARATIONS
        WRITE_STRINGS
        POINTER_ARITH
        CAST_QUAL
        UNDEF
    )
        if(HARDEN_CC_W${_probe_var})
            string(TOLOWER "${_probe_var}" _flag)
            string(REPLACE "_" "-" _flag "${_flag}")
            target_compile_options(${tgt} PRIVATE "-W${_flag}")
        endif()
    endforeach()

    # ── Optional warnings — =N level flags (explicit) ─────────────────────────
    #
    # -Wformat-truncation=2: snprintf output truncation (GCC). Known instance at
    #   opendkim.c:12408; this flag makes it visible on every build.
    # -Wformat-overflow=2: format string writing past its destination (GCC).
    #   Complements -Wformat-truncation; both catch bounds errors in *printf calls.
    # -Wstringop-overflow=4: memcpy/snprintf writing past the destination (GCC).
    #   Level 4 is the widest heuristic set; especially valuable in mail-parsing
    #   code with many bounded copy operations.

    if(HARDEN_CC_WFORMAT_TRUNCATION2)
        target_compile_options(${tgt} PRIVATE -Wformat-truncation=2)
    endif()
    if(HARDEN_CC_WFORMAT_OVERFLOW2)
        target_compile_options(${tgt} PRIVATE -Wformat-overflow=2)
    endif()
    if(HARDEN_CC_WSTRINGOP_OVERFLOW4)
        target_compile_options(${tgt} PRIVATE -Wstringop-overflow=4)
    endif()

    # ── Extra high-noise warnings (optional) ──────────────────────────────────
    #
    # -Wconversion: implicit type conversions that may change value.
    # -Wsign-conversion: implicit signed↔unsigned conversions.
    # -Wcast-align: cast increases required alignment of the target type.
    #
    # Enabled only under OPENDKIM_ENABLE_EXTRA_WARNINGS.

    if(OPENDKIM_ENABLE_EXTRA_WARNINGS)
        foreach(_xw WCONVERSION WSIGN_CONVERSION WCAST_ALIGN)
            if(HARDEN_CC_${_xw})
                string(TOLOWER "${_xw}" _xf)
                string(REPLACE "_" "-" _xf "${_xf}")
                target_compile_options(${tgt} PRIVATE "-W${_xf}")
            endif()
        endforeach()
    endif()

    # ── Correctness flags ─────────────────────────────────────────────────────
    #
    # -fno-strict-aliasing: the codebase casts between char*/u_char* and the
    #   sockaddr* family throughout; strict aliasing conformance is not guaranteed.
    # -fwrapv: signed integer overflow wraps (two's complement) instead of being
    #   undefined behaviour.  Without this the compiler may delete overflow-detecting
    #   guards like (a + b < a).  With -fwrapv enabled, the compiler no longer
    #   treats signed overflow as undefined behaviour for optimisation purposes.
    # -fno-omit-frame-pointer: keeps frame pointers for crash reports, perf/gprof
    #   profiling, and sanitizer stack unwinding.

    if(HARDEN_CC_NO_STRICT_ALIASING)
        target_compile_options(${tgt} PRIVATE -fno-strict-aliasing)
    endif()
    if(HARDEN_CC_WRAPV)
        target_compile_options(${tgt} PRIVATE -fwrapv)
    endif()
    if(HARDEN_CC_NO_OMIT_FRAME_POINTER)
        target_compile_options(${tgt} PRIVATE -fno-omit-frame-pointer)
    endif()

    # ── _FORTIFY_SOURCE ───────────────────────────────────────────────────────
    #
    # Skipped when any sanitizer is active: ASAN/UBSAN intercept memory functions
    # themselves and FORTIFY_SOURCE can trigger false positives against that layer.
    # Sanitizers.cmake defines OPENDKIM_ENABLE_ASAN / _UBSAN; include it before
    # this module so those variables are defined here.

    set(_san_active FALSE)
    if(DEFINED OPENDKIM_ENABLE_ASAN  AND OPENDKIM_ENABLE_ASAN)
        set(_san_active TRUE)
    endif()
    if(DEFINED OPENDKIM_ENABLE_UBSAN AND OPENDKIM_ENABLE_UBSAN)
        set(_san_active TRUE)
    endif()

    if(NOT _san_active)
        target_compile_options(${tgt} PRIVATE
            $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
            $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=${HARDEN_FORTIFY_LEVEL}>
        )
    endif()

    # ── Stack protection ──────────────────────────────────────────────────────
    #
    # -fstack-protector-strong: canaries on frames with arrays, alloca, or
    #   address-taken locals — the high-risk subset without the ~8% overhead of
    #   --all.
    # -fstack-clash-protection: allocate stack pages one-at-a-time to prevent
    #   stack-clash attacks that skip the guard page. GCC 8+ / Clang 11+.
    # -fcf-protection=full: Intel CET (IBT + SHSTK), x86/x86-64 only; probe
    #   returns FALSE on ARM/RISC-V so this is a no-op on those targets.

    if(HARDEN_CC_STACK_PROTECTOR_STRONG)
        target_compile_options(${tgt} PRIVATE -fstack-protector-strong)
    endif()
    if(HARDEN_CC_STACK_CLASH_PROTECTION)
        target_compile_options(${tgt} PRIVATE -fstack-clash-protection)
    endif()
    if(HARDEN_CC_CF_PROTECTION)
        target_compile_options(${tgt} PRIVATE -fcf-protection=full)
    endif()

    # ── PIE / PIC ─────────────────────────────────────────────────────────────
    # Always set POSITION_INDEPENDENT_CODE so compiled objects are compatible
    # with PIE executables or shared libraries even when link hardening is OFF.
    # For SHARED libraries CMake already sets -fPIC; for executables this enables
    # -fPIE on GCC/Clang ELF targets.  Negligible overhead on modern architectures.

    set_target_properties(${tgt} PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

    # ── Non-executable stack ──────────────────────────────────────────────────

    if(OPENDKIM_ENABLE_NOEXECSTACK AND HARDEN_LD_NOEXECSTACK)
        target_link_options(${tgt} PRIVATE "LINKER:-z,noexecstack")
    endif()

    # ── PIE + RELRO + BIND_NOW (optional) ────────────────────────────────────

    if(OPENDKIM_ENABLE_LINK_HARDENING)
        get_target_property(_tgt_type ${tgt} TYPE)
        if(_tgt_type STREQUAL "EXECUTABLE" AND HARDEN_LD_PIE)
            target_link_options(${tgt} PRIVATE -pie)
        endif()
        if(HARDEN_LD_RELRO)
            target_link_options(${tgt} PRIVATE "LINKER:-z,relro")
        endif()
        if(HARDEN_LD_BINDNOW)
            target_link_options(${tgt} PRIVATE "LINKER:-z,now")
        endif()
    endif()

endfunction()
