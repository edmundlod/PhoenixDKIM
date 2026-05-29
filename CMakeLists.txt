cmake_minimum_required(VERSION 3.20)

project(opendkim
    VERSION 3.0.0
    DESCRIPTION "PhoenixDKIM — modernised OpenDKIM fork with OpenSSL3 and Ed25519"
    LANGUAGES C
)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_definitions(_GNU_SOURCE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ── BSD package prefix ────────────────────────────────────────────────────────
# On FreeBSD and OpenBSD, packages install under /usr/local, which CMake does
# not search by default.  Appending it to CMAKE_PREFIX_PATH makes find_package,
# find_path, and find_library pick up installed packages without requiring
# manual -D flags.
if(CMAKE_SYSTEM_NAME MATCHES "FreeBSD|OpenBSD")
    list(APPEND CMAKE_PREFIX_PATH /usr/local)
endif()

include(Sanitizers)   # must precede Hardening — defines options checked there
include(Hardening)
include(Valgrind)     # must follow Sanitizers — checks for conflicting asan/ubsan options

enable_testing()

# ── Build-system consistency check ────────────────────────────────────────────
# Verify every HAVE_* macro referenced in C sources has a corresponding CMake
# probe.  Catches porting gaps like the HAVE_REALPATH incident (commit 6f9e571f).
add_test(
    NAME check-have-macro-coverage
    COMMAND sh "${CMAKE_SOURCE_DIR}/cmake/check-have-macros.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
set_tests_properties(check-have-macro-coverage PROPERTIES
    LABELS "buildsys"
)

# ── Crypto provider selection ─────────────────────────────────────────────────
# PhoenixDKIM builds against either OpenSSL 3 or LibreSSL 3.7+; both implement
# the OpenSSL 3 EVP API this code uses.  SSL_PROVIDER selects/validates which:
#   auto      use whatever the system provides -- OpenSSL on Linux, LibreSSL on
#             OpenBSD base (the default; the right choice for most builds)
#   openssl   require OpenSSL; fail the configure if LibreSSL is what's found
#   libressl  require LibreSSL; fail the configure if OpenSSL is what's found
# Detection, per-provider minimum-version enforcement, and this validation live
# in cmake/CheckCryptoProvider.cmake, run after find_package(OpenSSL).
set(SSL_PROVIDER "auto" CACHE STRING
    "Crypto provider to build against: auto, openssl, or libressl")
set_property(CACHE SSL_PROVIDER PROPERTY STRINGS auto openssl libressl)

# SSL_ROOT_DIR: provider-neutral path to a non-default OpenSSL *or* LibreSSL
# install -- e.g. -DSSL_ROOT_DIR=/usr/local to build against a LibreSSL on a
# Linux box whose system libcrypto is OpenSSL.  CMake's built-in FindOpenSSL
# only understands the OPENSSL_ROOT_DIR spelling, which -- despite its name --
# is equally how you point the build at LibreSSL.  Forward ours into it; an
# explicitly-set OPENSSL_ROOT_DIR is respected and takes precedence.
set(SSL_ROOT_DIR "" CACHE PATH
    "Path to a non-default OpenSSL or LibreSSL install (forwarded to OPENSSL_ROOT_DIR)")
if(SSL_ROOT_DIR AND NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "${SSL_ROOT_DIR}")
endif()

add_subdirectory(libopendkim)
add_subdirectory(opendkim)
add_subdirectory(miltertest)

# Probe SHA1 RSA verify support after OpenSSL has been found by the
# subdirectories, so OpenSSL::Crypto is available to the check.
include(CheckSHA1Verify)

# CPack for creating .deb files
set(CPACK_PACKAGE_NAME "opendkim")
set(CPACK_PACKAGE_VENDOR "Edmund Lodewijks")
set(CPACK_PACKAGE_VERSION "3.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PhoenixDKIM — modernised OpenDKIM fork with OpenSSL3 and Ed25519")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Edmund Lodewijks <edmund@proteamail.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libmilter1.0.1, libssl3, libc6")
set(CPACK_DEBIAN_PACKAGE_SECTION "mail")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

include(CPack)
