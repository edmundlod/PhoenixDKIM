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

# ── DKIM2 parser fuzz targets (only when WITH_DKIM2) ──────────────────────────
# One source, five targets selected by FUZZ_DKIM2_TARGET; same wiring as above.
if(WITH_DKIM2)
    set(_dkim2_fuzz_src ${CMAKE_CURRENT_SOURCE_DIR}/fuzz-dkim2.c)
    set(_dkim2_fuzz_targets
        "fuzz-dkim2-tags=1"
        "fuzz-dkim2-sig=2"
        "fuzz-dkim2-mi=3"
        "fuzz-dkim2-key=4"
        "fuzz-dkim2-json=5"
    )

    foreach(spec IN LISTS _dkim2_fuzz_targets)
        string(REPLACE "=" ";" parts "${spec}")
        list(GET parts 0 fz_name)
        list(GET parts 1 fz_type)

        add_executable(${fz_name} ${_dkim2_fuzz_src})

        target_include_directories(${fz_name} PRIVATE
            ${CMAKE_SOURCE_DIR}/libphoenixdkim
            ${CMAKE_BINARY_DIR}/libphoenixdkim)

        target_compile_definitions(${fz_name} PRIVATE FUZZ_DKIM2_TARGET=${fz_type})

        # phoenixdkim_static carries the DKIM2 objects (instrumented with
        # fuzzer-no-link); PkgConfig::CJSON supplies the cJSON include path the
        # json target needs and its library.
        target_link_libraries(${fz_name} PRIVATE phoenixdkim_static PkgConfig::CJSON)

        target_compile_options(${fz_name} PRIVATE
            -Wno-pointer-sign
            -Wno-unused-parameter
            -UNDEBUG)

        apply_hardening(${fz_name})
        apply_sanitizers(${fz_name})
        apply_fuzzer(${fz_name})

        add_test(
            NAME ${fz_name}-smoke
            COMMAND ${fz_name} -runs=0
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        set_tests_properties(${fz_name}-smoke PROPERTIES LABELS "fuzz")
    endforeach()
endif()
