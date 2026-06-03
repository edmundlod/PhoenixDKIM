# Copyright (c) 2026 PhoenixDKIM contributors
#   All rights reserved.

include(GNUInstallDirs)

if(NOT WITH_LUA)
    return()
endif()

find_package(Lua 5.4 REQUIRED)

add_executable(miltertest miltertest.c)

target_include_directories(miltertest PRIVATE
    ${CMAKE_SOURCE_DIR}/libphoenixdkim
    ${CMAKE_BINARY_DIR}/libphoenixdkim
    ${LUA_INCLUDE_DIR}
    ${MILTER_INCLUDE_DIR}
)

target_link_libraries(miltertest PRIVATE
    phoenixdkim
    ${LUA_LIBRARIES}
)

if(BSD_LIBRARY)
    target_link_libraries(miltertest PRIVATE ${BSD_LIBRARY})
endif()

apply_hardening(miltertest)
apply_sanitizers(miltertest)

install(TARGETS miltertest DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES miltertest.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
