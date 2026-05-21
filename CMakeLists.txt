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
include(Sanitizers)   # must precede Hardening — defines options checked there
include(Hardening)

enable_testing()

# ── Build-system consistency check ────────────────────────────────────────────
# Verify every HAVE_* macro referenced in C sources has a corresponding CMake
# probe.  Catches porting gaps like the HAVE_REALPATH incident (commit 6f9e571f).
add_test(
    NAME check-have-macro-coverage
    COMMAND bash "${CMAKE_SOURCE_DIR}/cmake/check-have-macros.sh"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
set_tests_properties(check-have-macro-coverage PROPERTIES
    LABELS "buildsys"
)

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
