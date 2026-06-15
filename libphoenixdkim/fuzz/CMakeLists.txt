# libphoenixdkim fuzz targets — built only when PHOENIXDKIM_ENABLE_FUZZERS=ON
# (validated in cmake/Fuzzers.cmake, which also requires Clang + ASan).
#
# One source, two targets, selected by the FUZZ_SETTYPE compile definition:
#   fuzz-sig  parses the DKIM-Signature tag-list  (attacker = message sender)
#   fuzz-key  parses the public-key TXT tag-list   (attacker = signing-domain DNS)

set(_fuzz_src ${CMAKE_CURRENT_SOURCE_DIR}/fuzz-process-set.c)

# target_name  ->  set-type macro
set(_fuzz_targets
    "fuzz-sig=DKIM_SETTYPE_SIGNATURE"
    "fuzz-key=DKIM_SETTYPE_KEY"
)

foreach(spec IN LISTS _fuzz_targets)
    string(REPLACE "=" ";" parts "${spec}")
    list(GET parts 0 fz_name)
    list(GET parts 1 fz_type)

    add_executable(${fz_name} ${_fuzz_src})

    target_include_directories(${fz_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/libphoenixdkim
        ${CMAKE_BINARY_DIR}/libphoenixdkim    # build-config.h
    )

    target_compile_definitions(${fz_name} PRIVATE FUZZ_SETTYPE=${fz_type})

    # Link the static library: it is the one instrumented with
    # -fsanitize=fuzzer-no-link (see libphoenixdkim/CMakeLists.txt), and as a
    # STATIC target it propagates its own transitive deps (OpenSSL, resolv,
    # threads, …) to the fuzz executable.
    target_link_libraries(${fz_name} PRIVATE phoenixdkim_static)

    target_compile_options(${fz_name} PRIVATE
        -Wno-pointer-sign
        -Wno-unused-parameter
        -UNDEBUG)             # keep the parser's asserts live under fuzzing

    apply_hardening(${fz_name})
    apply_sanitizers(${fz_name})   # ASan/UBSan from the build configuration
    apply_fuzzer(${fz_name})       # libFuzzer driver

    # A short self-test so CTest exercises the harness wiring (not a real
    # fuzzing run): -runs=0 builds the engine, replays nothing, exits 0.
    add_test(
        NAME ${fz_name}-smoke
        COMMAND ${fz_name} -runs=0
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(${fz_name}-smoke PROPERTIES LABELS "fuzz")
endforeach()
