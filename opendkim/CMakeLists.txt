include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# ── OpenSSL 3 ─────────────────────────────────────────────────────────────────

find_package(OpenSSL 3.0 REQUIRED)

# ── LMDB ──────────────────────────────────────────────────────────────────────
# find_library/find_path calls return cached results from the libopendkim pass.
# The PkgConfig::LMDB imported target is global if pkg-config found it there.

find_package(PkgConfig QUIET)

if(TARGET PkgConfig::LMDB)
    set(LMDB_TARGET PkgConfig::LMDB)
else()
    find_library(LMDB_LIBRARY NAMES lmdb)
    find_path(LMDB_INCLUDE_DIR NAMES lmdb.h)
    if(LMDB_LIBRARY AND LMDB_INCLUDE_DIR)
        if(NOT TARGET lmdb_imported)
            add_library(lmdb_imported UNKNOWN IMPORTED)
            set_target_properties(lmdb_imported PROPERTIES
                IMPORTED_LOCATION "${LMDB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LMDB_INCLUDE_DIR}"
            )
        endif()
        set(LMDB_TARGET lmdb_imported)
    else()
        message(FATAL_ERROR "LMDB not found. Install liblmdb-dev / lmdb-devel.")
    endif()
endif()

# ── libmilter (required for daemon) ──────────────────────────────────────────

find_library(MILTER_LIB NAMES milter)
if(NOT MILTER_LIB)
    message(FATAL_ERROR "libmilter not found. Install libmilter-dev / sendmail-devel.")
endif()

find_path(MILTER_INCLUDE_DIR NAMES libmilter/mfapi.h)

# ── Lua 5.4 (optional) ────────────────────────────────────────────────────────

option(WITH_LUA "Build with Lua 5.4 scripting support" OFF)

if(WITH_LUA)
    find_package(Lua 5.4 EXACT REQUIRED)
endif()

# ── pthreads ──────────────────────────────────────────────────────────────────

find_package(Threads REQUIRED)

# ── libresolv ─────────────────────────────────────────────────────────────────

find_library(RESOLV_LIBRARY NAMES resolv)

# ── strlcpy / strlcat ─────────────────────────────────────────────────────────

check_function_exists(strlcpy HAVE_STRLCPY_IN_LIBC)
check_function_exists(strlcat HAVE_STRLCAT_IN_LIBC)

set(STRL_LIBRARY "")
set(USE_BSD_H FALSE)

if(NOT (HAVE_STRLCPY_IN_LIBC AND HAVE_STRLCAT_IN_LIBC))
    find_library(BSD_LIBRARY NAMES bsd)
    if(BSD_LIBRARY)
        check_include_file("bsd/string.h" HAVE_BSD_STRING_H)
        if(HAVE_BSD_STRING_H)
            set(STRL_LIBRARY "${BSD_LIBRARY}")
            set(USE_BSD_H TRUE)
        endif()
    endif()
endif()

# ── Common configuration for daemon-side targets ──────────────────────────────
# Mirrors configure_opendkim_target() from libopendkim/CMakeLists.txt.

function(configure_daemon_target tgt)
    target_include_directories(${tgt} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}/libopendkim
    )

    target_compile_definitions(${tgt} PRIVATE
        HAVE_SHA256=1
        USE_MDB=1
        _FFR_RESIGN=1
        _FFR_IDENTITY_HEADER=1
        _FFR_SENDER_MACRO=1
    )

    if(HAVE_RES_NINIT)
        target_compile_definitions(${tgt} PRIVATE HAVE_RES_NINIT=1)
    endif()
    if(HAVE_RES_SETSERVERS)
        target_compile_definitions(${tgt} PRIVATE HAVE_RES_SETSERVERS=1)
    endif()
    if(HAVE_LIMITS_H)
        target_compile_definitions(${tgt} PRIVATE HAVE_LIMITS_H=1)
    endif()
    if(HAVE_STDBOOL_H)
        target_compile_definitions(${tgt} PRIVATE HAVE_STDBOOL_H=1)
    endif()
    if(USE_BSD_H)
        target_compile_definitions(${tgt} PRIVATE USE_BSD_H=1)
    endif()

    target_link_libraries(${tgt} PRIVATE
        opendkim
        OpenSSL::Crypto
        ${LMDB_TARGET}
        Threads::Threads
    )

    if(RESOLV_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${RESOLV_LIBRARY})
    endif()

    if(STRL_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${STRL_LIBRARY})
    endif()

    if(WITH_LUA)
        target_compile_definitions(${tgt} PRIVATE USE_LUA=1)
        target_include_directories(${tgt} PRIVATE ${LUA_INCLUDE_DIR})
        target_link_libraries(${tgt} PRIVATE ${LUA_LIBRARIES})
    endif()
endfunction()

# ── opendkim daemon ───────────────────────────────────────────────────────────
# Source list from opendkim/Makefile.am opendkim_SOURCES.
#
# CMake target name is opendkim_daemon because the shared library in
# libopendkim/ already owns the "opendkim" target name.  OUTPUT_NAME
# ensures the installed binary is still called "opendkim".

add_executable(opendkim_daemon
    opendkim.c
    opendkim-ar.c
    opendkim-arf.c
    opendkim-crypto.c
    opendkim-db.c
    opendkim-dns.c
    opendkim-lua.c
    config.c
    flowrate.c
    test.c
    util.c
)

set_target_properties(opendkim_daemon PROPERTIES OUTPUT_NAME opendkim)

configure_daemon_target(opendkim_daemon)

target_link_libraries(opendkim_daemon PRIVATE ${MILTER_LIB})

if(WITH_LUA)
    target_compile_definitions(opendkim_daemon PRIVATE DKIMF_LUA_CONTEXT_HOOKS=1)
    if(MILTER_INCLUDE_DIR)
        target_include_directories(opendkim_daemon PRIVATE ${MILTER_INCLUDE_DIR})
    endif()
endif()

install(TARGETS opendkim_daemon
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── opendkim-testkey ──────────────────────────────────────────────────────────
# Source list from opendkim/Makefile.am opendkim_testkey_SOURCES.

add_executable(opendkim-testkey
    config.c
    opendkim-crypto.c
    opendkim-db.c
    opendkim-dns.c
    opendkim-lua.c
    opendkim-testkey.c
    util.c
)

configure_daemon_target(opendkim-testkey)

if(WITH_LUA AND MILTER_INCLUDE_DIR)
    target_include_directories(opendkim-testkey PRIVATE ${MILTER_INCLUDE_DIR})
endif()

install(TARGETS opendkim-testkey
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── opendkim-genzone ──────────────────────────────────────────────────────────
# Source list from opendkim/Makefile.am opendkim_genzone_SOURCES.

add_executable(opendkim-genzone
    config.c
    opendkim-db.c
    opendkim-genzone.c
    opendkim-lua.c
    util.c
)

configure_daemon_target(opendkim-genzone)

install(TARGETS opendkim-genzone
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── opendkim-testmsg ──────────────────────────────────────────────────────────
# Source list from opendkim/Makefile.am opendkim_testmsg_SOURCES.

add_executable(opendkim-testmsg
    opendkim-testmsg.c
)

configure_daemon_target(opendkim-testmsg)

install(TARGETS opendkim-testmsg
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── opendkim-genkey (Perl script) ─────────────────────────────────────────────
# Listed in Makefile.am as dist_sbin_SCRIPTS — it is a Perl script generated
# from opendkim-genkey.in via autoconf-style @VAR@ substitution.
# configure_file runs at cmake configure time; the custom target makes
# "make opendkim-genkey" a valid build target.

set(DOMAIN "" CACHE STRING "Default domain for opendkim-genkey")
set(VERSION "${PROJECT_VERSION}")

configure_file(
    opendkim-genkey.in
    ${CMAKE_CURRENT_BINARY_DIR}/opendkim-genkey
    @ONLY
)

add_custom_target(opendkim-genkey
    COMMENT "opendkim-genkey Perl script (generated at configure time)"
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/opendkim-genkey
    DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
