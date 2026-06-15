# libphoenixdkim test suite — registered with CTest.
#
# Test list derived from libphoenixdkim/tests/Makefile.am.  Tests t-test00 through
# t-test15 listed in Makefile.am are not yet present on disk; add them here as
# their .c files are written.  Tests skipped by Makefile.am itself (t-test75,
# t-test95, t-test124) remain skipped.

# ── Setup / teardown / perf ───────────────────────────────────────────────────

set(LIBPHOENIXDKIM_TEST_PROGRAMS
    t-setup
    t-cleanup
    t-conformance
    t-signperf
    t-verifyperf
    # PhoenixDKIM-modified fork of upstream's t-test209 (RFC 8616 EAI); named
    # rather than numbered to mark the divergence from upstream.
    t-test209-phoenixdkim
    # PhoenixDKIM addition: DNS failure-mode classification matrix (transient
    # vs permanent key-lookup verdicts), driven through a mock resolver.
    t-dns-failures
)

# ── Numbered conformance tests (t-test16 … t-test154) ─────────────────────────

set(LIBPHOENIXDKIM_NUMBERED_TESTS
    16  17  18  19  20  21  22  23  24  25
    26  27  28  29  30  31  32  33  34  35
    36  37  38  39  40  41  42  43  44  45
    46  47  48      50  51  52  53  54  55
    56  57  58  59  60  61  62  63  64  65
    66  67  68  69  70  71  72  73  74
    76  77  78  79  80  81  82  83  84  85
    86  87  88  89  90  91  92  93  94
    96  97  98  99
    100 101 102 103 104 105 106 107 108 109
    110 111 112 113 114 115 116 117 118 119
    120 121 122 123
    125 126 127 128 129
    130 131 132 133 134 135 136 137 138 139
    140 141 142 143 144 145 146 147 148 149
    150 151 152 153 154
    158 159
    200 201 202 203 204 205 206 207 208
)

foreach(num IN LISTS LIBPHOENIXDKIM_NUMBERED_TESTS)
    list(APPEND LIBPHOENIXDKIM_TEST_PROGRAMS "t-test${num}")
endforeach()

# ── Build and register each test ──────────────────────────────────────────────

foreach(test_name IN LISTS LIBPHOENIXDKIM_TEST_PROGRAMS)
    set(test_src "${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c")
    if(NOT EXISTS "${test_src}")
        message(WARNING "Skipping ${test_name}: ${test_src} does not exist")
        continue()
    endif()

    add_executable(${test_name} ${test_name}.c)

    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/libphoenixdkim
        ${CMAKE_BINARY_DIR}/libphoenixdkim    # build-config.h
    )

    target_link_libraries(${test_name} PRIVATE
        phoenixdkim
        OpenSSL::Crypto
    )

    if(RESOLV_LIBRARY)
        target_link_libraries(${test_name} PRIVATE ${RESOLV_LIBRARY})
    endif()

    if(STRL_LIBRARY)
        target_link_libraries(${test_name} PRIVATE ${STRL_LIBRARY})
    endif()

    apply_hardening(${test_name})
    apply_sanitizers(${test_name})

    # These suppressions must come AFTER apply_hardening() because -Wextra
    # (added by apply_hardening) re-enables -Wunused-parameter on Clang,
    # overriding any earlier -Wno-unused-parameter on the command line.
    target_compile_options(${test_name} PRIVATE
        -Wno-pointer-sign
        -Wno-unused-parameter
        -UNDEBUG)

    add_test(
        NAME ${test_name}
        COMMAND ${test_name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endforeach()

# ── Ordering: t-setup must run before, t-cleanup after, all numbered tests ───

if(TARGET t-setup)
    set_tests_properties(t-setup PROPERTIES FIXTURES_SETUP libphoenixdkim_fixtures)
endif()
if(TARGET t-cleanup)
    set_tests_properties(t-cleanup PROPERTIES FIXTURES_CLEANUP libphoenixdkim_fixtures)
endif()

# Apply the fixture requirement to EVERYTHING in LIBPHOENIXDKIM_TEST_PROGRAMS
# EXCEPT for setup and cleanup themselves.
foreach(test_name IN LISTS LIBPHOENIXDKIM_TEST_PROGRAMS)
    if(TARGET ${test_name} AND NOT "${test_name}" STREQUAL "t-setup" AND NOT "${test_name}" STREQUAL "t-cleanup")
        set_tests_properties(${test_name} PROPERTIES
            FIXTURES_REQUIRED libphoenixdkim_fixtures
        )
    endif()
endforeach()

# ── ed25519 perf wrapper scripts ──────────────────────────────────────────────
# These are shell scripts (not compiled) that invoke the t-signperf / t-verifyperf
# binaries with "-s ed25519-sha256".  Register them directly with CTest.
foreach(script t-signperf-ed25519 t-verifyperf-ed25519)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${script}")
        add_test(
            NAME ${script}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/${script}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        )
        set_tests_properties(${script} PROPERTIES
            FIXTURES_REQUIRED libphoenixdkim_fixtures
        )
    endif()
endforeach()
