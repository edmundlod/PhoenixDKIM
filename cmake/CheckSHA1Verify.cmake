# cmake/CheckSHA1Verify.cmake
#
# Probe whether the current OpenSSL build (honouring any active system
# crypto policy) permits SHA1 to be used as the digest for RSA signature
# VERIFICATION.
#
# Result variable (BOOL, cached):
#   OPENDKIM_SHA1_VERIFY_OK
#
# Effect: if the probe fails, a CMake WARNING is emitted that explains the
# situation and gives platform-specific instructions for enabling SHA1.
#
# Background: PhoenixDKIM retains RSA-SHA1 VERIFICATION for interoperability
# with legacy signed mail but drops RSA-SHA1 SIGNING.  Some distributions
# (RHEL 9+, Fedora 38+, and derivatives) disable SHA1 for signature
# operations in their DEFAULT crypto policy.  This does not indicate a
# build defect; it is a local system policy decision.  See
# docs/crypto-policy.md for a full explanation.

include(CheckCSourceRuns)
include(CMakePushCheckState)

# Ensure OPENSSL_LIBRARIES / OPENSSL_INCLUDE_DIR are populated.
# find_package is idempotent; if the subdirectories already ran it this is a
# no-op that just retrieves the cached result.
find_package(OpenSSL QUIET)

cmake_push_check_state(RESET)
# Use the plain path variables, not the imported target: try_compile builds a
# fresh CMake project that cannot see imported targets from the parent scope.
set(CMAKE_REQUIRED_LIBRARIES    ${OPENSSL_LIBRARIES})
set(CMAKE_REQUIRED_INCLUDES     ${OPENSSL_INCLUDE_DIR})

# The test key is the RSA-1024 public key used by the libopendkim test suite,
# DER-encoded (SubjectPublicKeyInfo, 162 bytes).  Embedding it avoids any
# dependency on key files that may not exist at configure time.
check_c_source_runs([[
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static const unsigned char rsa_pub_der[] = {
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81,
    0x89, 0x02, 0x81, 0x81, 0x00, 0xb8, 0x19, 0x41, 0xab, 0xf9, 0xdf, 0xfa,
    0x48, 0x53, 0x73, 0x54, 0xb6, 0x29, 0xa6, 0x19, 0xd1, 0x77, 0x44, 0x0f,
    0x18, 0xac, 0xf6, 0xb9, 0x69, 0xd5, 0xeb, 0x94, 0x40, 0xc5, 0xad, 0x4f,
    0xc3, 0x7e, 0x76, 0x06, 0xa8, 0xb3, 0xaa, 0x22, 0x8e, 0x06, 0x38, 0x18,
    0x1b, 0x38, 0xfc, 0xa4, 0x94, 0x12, 0xb3, 0xcb, 0x4e, 0xbe, 0xff, 0xf6,
    0x93, 0xa8, 0xe9, 0x23, 0xcd, 0x3d, 0x46, 0x71, 0x12, 0xa8, 0xe1, 0x60,
    0x17, 0x48, 0x2e, 0xdd, 0x42, 0x5b, 0x36, 0x7b, 0xb7, 0xf9, 0xc7, 0x7c,
    0x93, 0xf9, 0x22, 0x42, 0x3f, 0xaa, 0xe1, 0xc2, 0x8a, 0x46, 0x90, 0x13,
    0xf7, 0x67, 0x1c, 0xc5, 0xce, 0xec, 0xbe, 0x10, 0x8d, 0x80, 0xdd, 0x6c,
    0x04, 0x69, 0x91, 0x39, 0x86, 0x6e, 0xca, 0xc1, 0xb7, 0x56, 0xed, 0xc3,
    0xc9, 0xcd, 0x3b, 0xf6, 0x04, 0x8b, 0xb6, 0x74, 0xab, 0x81, 0x76, 0xfe,
    0x81, 0x02, 0x03, 0x01, 0x00, 0x01
};

int main(void) {
    BIO *bio;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pctx;
    int ret = 1;

    bio = BIO_new_mem_buf(rsa_pub_der, (int)sizeof rsa_pub_der);
    if (!bio) return 1;
    pkey = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
    if (!pkey) return 1;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx) { EVP_PKEY_free(pkey); return 1; }

    if (EVP_PKEY_verify_init(pctx) != 1)                          goto done;
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) goto done;
    if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1()) != 1)    goto done;

    ret = 0; /* SHA1 RSA verify is available */
done:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    return ret;
}
]] OPENDKIM_SHA1_VERIFY_OK)

cmake_pop_check_state()

if(NOT OPENDKIM_SHA1_VERIFY_OK)
    if(EXISTS "/etc/crypto-policies/config")
        file(READ "/etc/crypto-policies/config" _sha1_cp_content)
        string(STRIP "${_sha1_cp_content}" _sha1_cp_content)
        set(_sha1_platform_hint
            "System crypto policy is '${_sha1_cp_content}' (RHEL/Fedora family).\n"
            "To allow SHA1 for the test run only, use a subpolicy:\n"
            "    sudo update-crypto-policies --set DEFAULT:SHA1\n"
            "    cmake -B build   # must reconfigure to clear the cached probe\n"
            "    ctest --test-dir build\n"
            "Restore the default afterwards:\n"
            "    sudo update-crypto-policies --set DEFAULT\n")
    else()
        set(_sha1_platform_hint
            "Check your OpenSSL configuration (MinProtocol, CipherString, or an\n"
            "openssl.cnf [system_default_sect] block). You may need to set\n"
            "    RSA.MinProtocol = TLSv1\n"
            "or equivalent to permit SHA1 for legacy signature verification.\n")
    endif()

    message(WARNING
        "SHA1 RSA signature verification is disabled by the current OpenSSL/system "
        "configuration.  PhoenixDKIM retains RSA-SHA1 VERIFICATION (not signing) "
        "for interoperability with legacy DKIM-signed mail; this is not a build "
        "defect.\n\n"
        "Consequences:\n"
        "  - Approximately 26 libopendkim tests that verify SHA1-signed test "
        "messages will FAIL.\n"
        "  - In production, incoming mail signed with RSA-SHA1 will be reported "
        "as having a key-decode error rather than a bad signature.\n\n"
        "${_sha1_platform_hint}"
        "See docs/crypto-policy.md for a full explanation.")
endif()
