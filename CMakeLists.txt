cmake_minimum_required(VERSION 3.20)

project(opendkim
    VERSION 3.0.0
    DESCRIPTION "Modernised OpenDKIM fork with OpenSSL3 and Ed25519"
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

enable_testing()

add_subdirectory(libopendkim)
add_subdirectory(opendkim)
add_subdirectory(miltertest)

# CPack for creating .deb files
set(CPACK_PACKAGE_NAME "opendkim")
set(CPACK_PACKAGE_VENDOR "Edmund Lodewijks")
set(CPACK_PACKAGE_VERSION "3.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Modernised OpenDKIM fork with OpenSSL3 and Ed25519")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Edmund Lodewijks <edmund@proteamail.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libmilter1.0.1, libssl3, libc6")
set(CPACK_DEBIAN_PACKAGE_SECTION "mail")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")

include(CPack)
