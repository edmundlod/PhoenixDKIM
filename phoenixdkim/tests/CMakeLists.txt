# Copyright (c) 2026 PhoenixDKIM contributors
#   All rights reserved.

# ── Valgrind integration-test configuration ───────────────────────────────────
# When either Valgrind tool is enabled, phoenixdkim/tests/CMakeLists.txt redirects
# PHOENIXDKIM_BINPATH to the cmake/Valgrind.cmake-generated wrapper directory so
# the Lua scripts launch the daemon under Valgrind rather than directly.
# Timeouts are stretched by 10× to accommodate Valgrind's overhead (~20-50× on
# memcheck, ~15-30× on helgrind vs native execution).
if(PHOENIXDKIM_ENABLE_VALGRIND OR PHOENIXDKIM_ENABLE_HELGRIND)
    # PHOENIXDKIM_VALGRIND_BIN_DIR is set by cmake/Valgrind.cmake (included from
    # the top-level CMakeLists.txt before this subdirectory is processed).
    set(_int_binpath "${PHOENIXDKIM_VALGRIND_BIN_DIR}")
    set(_int_timeout 300)
else()
    set(_int_binpath "${CMAKE_BINARY_DIR}/phoenixdkim")
    set(_int_timeout 30)
endif()

# Collect bare test names — files matching t-* with no extension
file(GLOB _all_files
    LIST_DIRECTORIES false
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    t-*
)

set(TEST_DRIVERS "")
foreach(f ${_all_files})
    if(NOT f MATCHES "\\.")
        list(APPEND TEST_DRIVERS ${f})
    endif()
endforeach()

# DKIM2 integration tests exercise config keys that only exist when the
# experimental DKIM2 support is compiled in; drop them otherwise.  WITH_DKIM2
# is a cache option declared in libphoenixdkim/CMakeLists.txt, visible here.
if(NOT WITH_DKIM2)
    list(REMOVE_ITEM TEST_DRIVERS t-dkim2-sign)
    list(REMOVE_ITEM TEST_DRIVERS t-dkim2-resign)
    list(REMOVE_ITEM TEST_DRIVERS t-dkim2-modify)
endif()

foreach(test_name ${TEST_DRIVERS})
    set(_lua ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.lua)
    if(NOT EXISTS ${_lua})
        continue()
    endif()

    add_test(
        NAME integration/${test_name}
        COMMAND $<TARGET_FILE:miltertest> -s ${_lua}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    # LSAN_OPTIONS points LeakSanitizer at the suppression file for the benign
    # system-liblua leaks surfaced by the daemon's and miltertest's embedded Lua
    # (see cmake/lsan-suppressions.txt).  Harmless when not built with a
    # sanitizer (the variable is simply ignored).
    set_tests_properties("integration/${test_name}" PROPERTIES
        ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR};PHOENIXDKIM_BINPATH=${_int_binpath};LSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/cmake/lsan-suppressions.txt"
        TIMEOUT ${_int_timeout}
    )
endforeach()

set(_expected_failures
    t-lua-rbl
    t-sign-atps
    t-verify-ss-atps
    t-verify-ss-rep
    t-sign-ss-replace
)
foreach(t ${_expected_failures})
    if("${t}" IN_LIST TEST_DRIVERS)
        set_tests_properties("integration/${t}" PROPERTIES DISABLED TRUE)
    endif()
endforeach()

