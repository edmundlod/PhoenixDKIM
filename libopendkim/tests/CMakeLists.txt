# libopendkim test suite — registered with CTest.
#
# Test list derived from libopendkim/tests/Makefile.am.  Tests t-test00 through
# t-test15 listed in Makefile.am are not yet present on disk; add them here as
# their .c files are written.  Tests skipped by Makefile.am itself (t-test75,
# t-test95, t-test124) remain skipped.

enable_testing()

# ── Setup / teardown / perf ───────────────────────────────────────────────────

set(LIBOPENDKIM_TEST_PROGRAMS
    t-setup
    t-cleanup
    t-conformance
    t-signperf
    t-verifyperf
)

# ── Numbered conformance tests (t-test16 … t-test154) ─────────────────────────

set(LIBOPENDKIM_NUMBERED_TESTS
    16  17  18  19  20  21  22  23  24  25
    26  27  28  29  30  31  32  33  34  35
    36  37  38  39  40  41  42  43  44  45
    46  47  48  49  50  51  52  53  54  55
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
)

foreach(num IN LISTS LIBOPENDKIM_NUMBERED_TESTS)
    list(APPEND LIBOPENDKIM_TEST_PROGRAMS "t-test${num}")
endforeach()

# ── Build and register each test ──────────────────────────────────────────────

foreach(test_name IN LISTS LIBOPENDKIM_TEST_PROGRAMS)
    set(test_src "${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.c")
    if(NOT EXISTS "${test_src}")
        message(WARNING "Skipping ${test_name}: ${test_src} does not exist")
        continue()
    endif()

    add_executable(${test_name} ${test_name}.c)

    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/libopendkim
        ${CMAKE_BINARY_DIR}/libopendkim    # build-config.h
    )

    target_link_libraries(${test_name} PRIVATE
        opendkim
        OpenSSL::Crypto
    )

    if(RESOLV_LIBRARY)
        target_link_libraries(${test_name} PRIVATE ${RESOLV_LIBRARY})
    endif()

    add_test(
        NAME ${test_name}
        COMMAND ${test_name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endforeach()

# ── Ordering: t-setup must run before, t-cleanup after, all numbered tests ───

if(TARGET t-setup)
    set_tests_properties(t-setup PROPERTIES FIXTURES_SETUP libopendkim_fixtures)
endif()
if(TARGET t-cleanup)
    set_tests_properties(t-cleanup PROPERTIES FIXTURES_CLEANUP libopendkim_fixtures)
endif()

foreach(num IN LISTS LIBOPENDKIM_NUMBERED_TESTS)
    if(TARGET "t-test${num}")
        set_tests_properties("t-test${num}" PROPERTIES
            FIXTURES_REQUIRED libopendkim_fixtures
        )
    endif()
endforeach()
