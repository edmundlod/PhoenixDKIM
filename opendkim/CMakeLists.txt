# Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# ── OpenSSL 3+ / LibreSSL 3.7+ ────────────────────────────────────────────────
# Do not pass a version to find_package: OpenSSL 4's config file marks itself
# as incompatible with any major-version < 4 request, causing CMake to silently
# fall back to system OpenSSL.  CheckCryptoProvider enforces the per-provider
# minimum (OpenSSL >= 3.0, LibreSSL >= 3.7) instead.

find_package(OpenSSL REQUIRED)
include(CheckCryptoProvider)

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
    set(USE_LUA 1)
endif()

# ── Redis / Valkey — hiredis or libvalkey (optional) ─────────────────────────

option(WITH_REDIS "Build with Redis/Valkey (hiredis or libvalkey) backend support" OFF)

if(WITH_REDIS)
    find_library(HIREDIS_LIBRARY NAMES hiredis valkey)
    find_path(HIREDIS_INCLUDE_DIR NAMES hiredis/hiredis.h valkey/valkey.h)
    if(NOT HIREDIS_LIBRARY OR NOT HIREDIS_INCLUDE_DIR)
        message(FATAL_ERROR
            "hiredis or libvalkey not found. "
            "Install libhiredis-dev / hiredis-devel, or libvalkey-dev / valkey-devel.")
    endif()
    if(EXISTS "${HIREDIS_INCLUDE_DIR}/valkey/valkey.h" AND
       NOT EXISTS "${HIREDIS_INCLUDE_DIR}/hiredis/hiredis.h")
        set(REDIS_IMPL_VALKEY TRUE)
        message(STATUS "Redis backend: using libvalkey")
    else()
        set(REDIS_IMPL_VALKEY FALSE)
        message(STATUS "Redis backend: using hiredis")
    endif()
    set(WITH_REDIS 1)
endif()

# ── libcurl (optional, default OFF) ───────────────────────────────────────────
# Enables SMTP report delivery via the SMTPURI config option.

option(WITH_CURL "Enable libcurl SMTP report delivery (SMTPURI config option)" OFF)

if(WITH_CURL)
    find_package(CURL REQUIRED)
    if(CURL_VERSION_STRING VERSION_LESS "7.20.0")
        message(FATAL_ERROR
            "libcurl >= 7.20.0 required (CURLOPT_MAIL_FROM/MAIL_RCPT); "
            "found ${CURL_VERSION_STRING}")
    endif()
    set(HAVE_LIBCURL 1)
endif()

# ── systemd sd_notify (optional) ──────────────────────────────────────────────
# Enables Type=notify readiness signalling and the watchdog keep-alive.
# Tri-state, because a plain boolean cannot tell a deliberate request apart from
# the inherited default:
#   ON   -- require it; FATAL if libsystemd is missing (a deliberate request
#           must not silently produce a binary that can't honour Type=notify).
#   OFF  -- skip it; build without sd_notify.
#   AUTO -- detect; if libsystemd is missing, warn and build without it.  Safe
#           default for non-systemd platforms (BSD/macOS), where the search is
#           simply a no-op.
set(WITH_SYSTEMD "AUTO" CACHE STRING
    "systemd sd_notify integration: AUTO (detect), ON (require), OFF (disable)")
set_property(CACHE WITH_SYSTEMD PROPERTY STRINGS AUTO ON OFF)

# Normalise: accept the usual boolean spellings as ON/OFF so existing
# -DWITH_SYSTEMD=ON / =OFF / =1 / =0 invocations keep working.
string(TOUPPER "${WITH_SYSTEMD}" _sd_req)
if(_sd_req MATCHES "^(OFF|0|NO|FALSE|N)$")
    set(_sd_req OFF)
elseif(_sd_req MATCHES "^(ON|1|YES|TRUE|Y)$")
    set(_sd_req ON)
elseif(NOT _sd_req STREQUAL "AUTO")
    message(FATAL_ERROR "WITH_SYSTEMD must be AUTO, ON, or OFF (got '${WITH_SYSTEMD}')")
endif()

if(NOT _sd_req STREQUAL "OFF")
    pkg_check_modules(LIBSYSTEMD QUIET libsystemd)
    if(LIBSYSTEMD_FOUND)
        set(HAVE_LIBSYSTEMD 1)
        message(STATUS "systemd integration: enabled (libsystemd ${LIBSYSTEMD_VERSION})")
    elseif(_sd_req STREQUAL "ON")
        # Deliberately requested but unsatisfiable: fail hard rather than ship a
        # Type=notify unit backed by a daemon that never sends READY=1 (which
        # makes "systemctl start" hang until the timeout).
        message(FATAL_ERROR
            "WITH_SYSTEMD=ON was requested but libsystemd was not found. "
            "Install libsystemd-dev / systemd-devel, or configure with "
            "-DWITH_SYSTEMD=OFF (or AUTO) to build without sd_notify.")
    else()
        # AUTO: degrade, but loudly — the generated unit will fall back to
        # Type=simple so it still starts, yet anyone expecting notify support
        # should see why it is absent.
        message(WARNING
            "libsystemd not found: building without sd_notify "
            "(Type=notify/watchdog unavailable). Install libsystemd-dev / "
            "systemd-devel, or pass -DWITH_SYSTEMD=ON to require it.")
    endif()
endif()

# ── systemd unit install (tarball/source builds) ──────────────────────────────
# Distro packaging ships its own unit, so default this OFF off-Linux and let
# packagers turn it off explicitly (Debian does, via debian/rules).  The unit
# itself is generated from the build so its Type=/WatchdogSec match what was
# actually compiled (see opendkim.service.in below).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(INSTALL_SYSTEMD_UNIT "Install the generated systemd service unit" ON)
else()
    option(INSTALL_SYSTEMD_UNIT "Install the generated systemd service unit" OFF)
endif()

if(INSTALL_SYSTEMD_UNIT)
    # systemdsystemunitdir is an absolute, distro-defined path (e.g.
    # /usr/lib/systemd/system) and intentionally ignores CMAKE_INSTALL_PREFIX.
    # Query it from the systemd .pc (note: the 'systemd' module, not
    # 'libsystemd'); fall back under the prefix when systemd.pc is absent.
    pkg_get_variable(_sd_unitdir systemd systemdsystemunitdir)
    if(NOT _sd_unitdir)
        set(_sd_unitdir "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
    endif()
    set(SYSTEMD_UNIT_DIR "${_sd_unitdir}" CACHE PATH
        "Directory in which to install the systemd service unit")
endif()

# ── Version string + build configuration for -V / -v diagnostics ─────────────
# DKIMF_VERSION reports the project version, plus the git commit on untagged
# development builds (issue #350).

set(DKIMF_VERSION "${PROJECT_VERSION}")

find_program(GIT_EXECUTABLE git)
if(GIT_EXECUTABLE AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE _git_hash
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _git_rc
    )
    if(_git_rc EQUAL 0 AND _git_hash)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} status --porcelain --untracked-files=no
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _git_dirty
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(_git_dirty)
            set(_git_hash "${_git_hash}-dirty")
        endif()
        set(DKIMF_VERSION "${PROJECT_VERSION}-g${_git_hash}")
    endif()
    # Refresh the version header automatically when HEAD or the index moves,
    # so a rebuild after a commit reports the new hash without reconfiguring.
    foreach(_gitfile HEAD index)
        if(EXISTS "${CMAKE_SOURCE_DIR}/.git/${_gitfile}")
            set_property(DIRECTORY APPEND PROPERTY
                         CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/.git/${_gitfile}")
        endif()
    endforeach()
endif()

# CONFIGURE_ARGS records the build options needed to reproduce this build
# (issue #357).  CMake has no literal equivalent of autoconf's
# $ac_configure_args, so reconstruct the meaningful -D flags from the resolved
# option values.  Normalise each toggle to ON/OFF: a value passed as
# -DWITH_X=1 is stored verbatim as "1", while an option left at its default
# carries "ON"/"OFF", so emit a consistent boolean rather than the raw value.
set(CONFIGURE_ARGS
    "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}")
foreach(_opt WITH_LUA WITH_REDIS WITH_CURL WITH_UNBOUND)
    if(${_opt})
        string(APPEND CONFIGURE_ARGS " -D${_opt}=ON")
    else()
        string(APPEND CONFIGURE_ARGS " -D${_opt}=OFF")
    endif()
endforeach()
# WITH_SYSTEMD is tri-state (AUTO/ON/OFF); report what was actually compiled,
# not the request, so -V never claims systemd support the binary lacks.
if(HAVE_LIBSYSTEMD)
    string(APPEND CONFIGURE_ARGS " -DWITH_SYSTEMD=ON")
else()
    string(APPEND CONFIGURE_ARGS " -DWITH_SYSTEMD=OFF")
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/build-version.h.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/build-version.h
    @ONLY
)

# ── pthreads ──────────────────────────────────────────────────────────────────

find_package(Threads REQUIRED)

# ── libresolv ─────────────────────────────────────────────────────────────────

find_library(RESOLV_LIBRARY NAMES resolv)
find_library(UNBOUND_LIBRARY NAMES unbound)

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
        ${CMAKE_CURRENT_BINARY_DIR}        # build-version.h
        ${CMAKE_BINARY_DIR}/libopendkim
    )

    target_compile_definitions(${tgt} PRIVATE
        HAVE_SHA256=1
        USE_MDB=1
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
    if(UNBOUND_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${UNBOUND_LIBRARY})
    endif()

    if(STRL_LIBRARY)
        target_link_libraries(${tgt} PRIVATE ${STRL_LIBRARY})
    endif()

    if(WITH_LUA)
        target_include_directories(${tgt} PRIVATE ${LUA_INCLUDE_DIR})
        target_link_libraries(${tgt} PRIVATE ${LUA_LIBRARIES})
    endif()

    if(WITH_REDIS)
        target_compile_definitions(${tgt} PRIVATE USE_REDIS=1)
        if(REDIS_IMPL_VALKEY)
            target_compile_definitions(${tgt} PRIVATE USE_LIBVALKEY=1)
        endif()
        target_include_directories(${tgt} PRIVATE ${HIREDIS_INCLUDE_DIR})
        target_link_libraries(${tgt} PRIVATE ${HIREDIS_LIBRARY})
    endif()

    if(WITH_CURL AND HAVE_LIBCURL)
        target_compile_definitions(${tgt} PRIVATE HAVE_LIBCURL=1)
        target_link_libraries(${tgt} PRIVATE CURL::libcurl)
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
    test.c
    util.c
)

set_target_properties(opendkim_daemon PROPERTIES OUTPUT_NAME opendkim)

configure_daemon_target(opendkim_daemon)
apply_hardening(opendkim_daemon)
apply_sanitizers(opendkim_daemon)

target_link_libraries(opendkim_daemon PRIVATE ${MILTER_LIB})

# systemd sd_notify is daemon-only; the helper binaries never talk to an init
# manager, so the linkage is attached here rather than in configure_daemon_target().
if(HAVE_LIBSYSTEMD)
    target_compile_definitions(opendkim_daemon PRIVATE HAVE_LIBSYSTEMD=1)
    target_include_directories(opendkim_daemon PRIVATE ${LIBSYSTEMD_INCLUDE_DIRS})
    target_link_libraries(opendkim_daemon PRIVATE ${LIBSYSTEMD_LIBRARIES})
endif()

if(WITH_LUA)
    target_compile_definitions(opendkim_daemon PRIVATE DKIMF_LUA_CONTEXT_HOOKS=1)
    if(MILTER_INCLUDE_DIR)
        target_include_directories(opendkim_daemon PRIVATE ${MILTER_INCLUDE_DIR})
    endif()
endif()

install(TARGETS opendkim_daemon
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── systemd unit (generated to match the build) ───────────────────────────────
# Type/WatchdogSec follow what was actually compiled: a build without sd_notify
# gets Type=simple so the unit still starts, instead of a Type=notify unit that
# would hang waiting for a READY=1 the daemon can never send.  Distro packaging
# ships its own unit and disables this (see -DINSTALL_SYSTEMD_UNIT=OFF).
if(INSTALL_SYSTEMD_UNIT)
    if(HAVE_LIBSYSTEMD)
        set(SD_TYPE "notify")
        set(SD_WATCHDOG_BLOCK
"# opendkim feeds this watchdog from a dedicated thread at half the interval
# below (i.e. every 15s).  systemd restarts the service if no keep-alive
# arrives within WatchdogSec, catching a wholly hung process.
WatchdogSec=30")
    else()
        set(SD_TYPE "simple")
        set(SD_WATCHDOG_BLOCK
"# Built without libsystemd: sd_notify()/watchdog are unavailable, so this unit
# uses Type=simple and omits WatchdogSec.")
    endif()
    configure_file(
        ${CMAKE_SOURCE_DIR}/contrib/systemd/opendkim.service.in
        ${CMAKE_CURRENT_BINARY_DIR}/opendkim.service
        @ONLY
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/opendkim.service
        DESTINATION ${SYSTEMD_UNIT_DIR}
    )
endif()

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
apply_hardening(opendkim-testkey)
apply_sanitizers(opendkim-testkey)

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
apply_hardening(opendkim-genzone)
apply_sanitizers(opendkim-genzone)

install(TARGETS opendkim-genzone
    RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)

# ── opendkim-testmsg ──────────────────────────────────────────────────────────
# Source list from opendkim/Makefile.am opendkim_testmsg_SOURCES.

add_executable(opendkim-testmsg
    opendkim-testmsg.c
)

configure_daemon_target(opendkim-testmsg)
apply_hardening(opendkim-testmsg)
apply_sanitizers(opendkim-testmsg)

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

# ── Man pages ─────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(FILES
    opendkim.8
    opendkim-genkey.8
    opendkim-genzone.8
    opendkim-testkey.8
    opendkim-testmsg.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)
install(FILES opendkim.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5)
install(FILES opendkim-lua.3 DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)

# ── Test ──────────────────────────────────────────────────────────────────────

if(WITH_LUA)
    add_subdirectory(tests)
endif()

# ── Redis/Valkey DB unit test ─────────────────────────────────────────────────

if(WITH_REDIS)
    add_executable(t-db-redis
        tests/t-db-redis.c
        opendkim-db.c
        opendkim-lua.c
        util.c
    )
    configure_daemon_target(t-db-redis)
    apply_hardening(t-db-redis)
    apply_sanitizers(t-db-redis)
    add_test(
        NAME t-db-redis
        COMMAND t-db-redis
    )
    set_tests_properties(t-db-redis PROPERTIES
        TIMEOUT 10
        SKIP_RETURN_CODE 77
    )
endif()
