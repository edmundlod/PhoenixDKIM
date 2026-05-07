# Copyright (c) 2026 OpenDKIM contributors
#   All rights reserved.

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

    set_tests_properties(integration/${test_name} PROPERTIES
        ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}"
        TIMEOUT     30
    )
endforeach()
