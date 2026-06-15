# cmake/Fuzzers.cmake
#
# libFuzzer coverage-guided fuzz targets for PhoenixDKIM's untrusted-input
# parsers.  These are development/CI tools — never built into a release.
#
# Include this module AFTER Sanitizers.cmake in the top-level CMakeLists.txt:
# fuzzing is only meaningful when the library under test is also instrumented
# with AddressSanitizer (and ideally UBSan), so this module hard-requires
# PHOENIXDKIM_ENABLE_ASAN and errors out otherwise rather than silently building
# a blind fuzzer.
#
# libFuzzer ships with Clang's compiler-rt; GCC has no -fsanitize=fuzzer, so
# this option requires a Clang toolchain.
#
# Typical use:
#   cmake -B build-fuzz -DPHOENIXDKIM_ENABLE_FUZZERS=ON \
#         -DPHOENIXDKIM_ENABLE_ASAN=ON -DPHOENIXDKIM_ENABLE_UBSAN=ON \
#         -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build-fuzz
#   ./build-fuzz/libphoenixdkim/fuzz/fuzz-sig    -max_total_time=120
#   ./build-fuzz/libphoenixdkim/fuzz/fuzz-key    -max_total_time=120

option(PHOENIXDKIM_ENABLE_FUZZERS
    "Build libFuzzer fuzz targets for the tag-list parsers. Clang-only; \
requires PHOENIXDKIM_ENABLE_ASAN=ON. Never use in production."
    OFF)

if(NOT PHOENIXDKIM_ENABLE_FUZZERS)
    return()
endif()

# ── Prerequisite validation (deliberate enable must fail loudly, not degrade) ──

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "PHOENIXDKIM_ENABLE_FUZZERS=ON requires a Clang toolchain: libFuzzer "
        "(-fsanitize=fuzzer) ships with Clang's compiler-rt and has no GCC "
        "equivalent. Re-run with -DCMAKE_C_COMPILER=clang.")
endif()

if(NOT PHOENIXDKIM_ENABLE_ASAN)
    message(FATAL_ERROR
        "PHOENIXDKIM_ENABLE_FUZZERS=ON requires PHOENIXDKIM_ENABLE_ASAN=ON. "
        "A fuzzer that runs against an uninstrumented library cannot see the "
        "memory-safety bugs it exists to find. Add -DPHOENIXDKIM_ENABLE_ASAN=ON "
        "(and ideally -DPHOENIXDKIM_ENABLE_UBSAN=ON).")
endif()

include(CMakePushCheckState)
include(CheckCSourceCompiles)

cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_FLAGS        "-fsanitize=fuzzer")
set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=fuzzer")
check_c_source_compiles(
    "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}"
    PHOENIXDKIM_HAVE_LIBFUZZER)
cmake_pop_check_state()

if(NOT PHOENIXDKIM_HAVE_LIBFUZZER)
    message(FATAL_ERROR
        "PHOENIXDKIM_ENABLE_FUZZERS=ON but -fsanitize=fuzzer does not link. "
        "Install the Clang compiler-rt fuzzer runtime.")
endif()

# ── apply_fuzzer(<target>) ─────────────────────────────────────────────────────
# Adds the libFuzzer entry point/driver. ASan/UBSan come from apply_sanitizers()
# which the caller invokes separately, mirroring the test targets.

function(apply_fuzzer tgt)
    target_compile_options(${tgt} PRIVATE -fsanitize=fuzzer)
    target_link_options(${tgt}    PRIVATE -fsanitize=fuzzer)
endfunction()

message(STATUS "Fuzzers: libFuzzer targets enabled (Clang + ASan)")
