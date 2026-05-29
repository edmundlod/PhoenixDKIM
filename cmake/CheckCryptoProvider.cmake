# cmake/CheckCryptoProvider.cmake
#
# Identify the crypto provider behind find_package(OpenSSL) and enforce the
# correct minimum version for it.
#
# PhoenixDKIM targets the OpenSSL 3 EVP API exclusively (see SCOPE.md).  Two
# providers implement that API and are supported:
#
#   * OpenSSL  >= 3.0.0  -- the primary provider on Linux.
#   * LibreSSL >= 3.7.0  -- the base-system libcrypto on OpenBSD (a declared
#                           platform target).  3.7.0 is the floor because
#                           Ed25519 (RFC 8463, mandatory in this fork) needs
#                           EVP_PKEY_new_raw_public_key(), which LibreSSL gained
#                           in that release.  LibreSSL has no FIPS mode and is
#                           not subject to update-crypto-policies; the RHEL
#                           crypto-policy behaviour described in SCOPE.md
#                           applies to the OpenSSL build only.
#
# CMake's FindOpenSSL transparently accepts LibreSSL, but the OPENSSL_VERSION it
# reports for LibreSSL is not comparable to OpenSSL's own version line.  We
# therefore detect LibreSSL from its header macro and gate on
# LIBRESSL_VERSION_NUMBER directly, which is immune to that ambiguity.
#
# Must be include()d after find_package(OpenSSL).

include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CMakePushCheckState)

cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})

if(NOT SSL_PROVIDER MATCHES "^(auto|openssl|libressl)$")
    message(FATAL_ERROR
        "SSL_PROVIDER must be auto, openssl, or libressl (got '${SSL_PROVIDER}').")
endif()

check_symbol_exists(LIBRESSL_VERSION_NUMBER "openssl/opensslv.h" OPENSSL_IS_LIBRESSL)

if(OPENSSL_IS_LIBRESSL)
    if(SSL_PROVIDER STREQUAL "openssl")
        message(FATAL_ERROR
            "SSL_PROVIDER=openssl, but the crypto library found is LibreSSL. "
            "Point SSL_ROOT_DIR (or OPENSSL_ROOT_DIR) at an OpenSSL install, or "
            "use SSL_PROVIDER=auto or =libressl.")
    endif()
    # Gate on the real LibreSSL version macro rather than OPENSSL_VERSION.
    check_c_source_compiles("
        #include <openssl/opensslv.h>
        #if LIBRESSL_VERSION_NUMBER < 0x3070000fL
        #error LibreSSL too old
        #endif
        int main(void) { return 0; }
    " LIBRESSL_VERSION_OK)
    if(NOT LIBRESSL_VERSION_OK)
        message(FATAL_ERROR
            "LibreSSL 3.7.0 or newer is required (Ed25519 support via "
            "EVP_PKEY_new_raw_public_key).")
    endif()
    message(STATUS "Crypto provider: LibreSSL (>= 3.7.0)")
else()
    if(SSL_PROVIDER STREQUAL "libressl")
        message(FATAL_ERROR
            "SSL_PROVIDER=libressl, but the crypto library found is OpenSSL "
            "${OPENSSL_VERSION}. Point SSL_ROOT_DIR (or OPENSSL_ROOT_DIR) at a "
            "LibreSSL install, or use SSL_PROVIDER=auto or =openssl.")
    endif()
    if(OPENSSL_VERSION VERSION_LESS "3.0")
        message(FATAL_ERROR "OpenSSL 3.0 or newer required; found ${OPENSSL_VERSION}")
    endif()
    # OpenSSL 4.x is supported; tested with 4.0.0.
    message(STATUS "Crypto provider: OpenSSL ${OPENSSL_VERSION}")
endif()

cmake_pop_check_state()
