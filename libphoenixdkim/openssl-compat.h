/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  openssl-compat.h -- thin compatibility shims for building against LibreSSL.
**
**  PhoenixDKIM targets the OpenSSL 3 EVP API exclusively (see SCOPE.md).
**  LibreSSL -- the base-system libcrypto on OpenBSD, a declared platform
**  target -- implements that API, but being a 1.0.1-era fork it retains the
**  pre-3.0 spellings of a couple of EVP accessors instead of the OpenSSL 3
**  "_get_" names this code base uses.  The macros below map the OpenSSL 3
**  names onto the legacy spellings, which are present in every LibreSSL
**  release.  Under real OpenSSL this header expands to nothing.
**
**  Ed25519 (RFC 8463) is mandatory in this fork and needs
**  EVP_PKEY_new_raw_public_key(), which LibreSSL gained in 3.7.0; that is the
**  minimum supported LibreSSL version (enforced in cmake/CheckCryptoProvider).
**
**  Include this AFTER <openssl/evp.h>.  dkim-types.h does so for the whole
**  library, so every crypto translation unit picks the shims up through it.
*/

#ifndef OPENSSL_COMPAT_H_
#define OPENSSL_COMPAT_H_

#include <openssl/opensslv.h>

#ifdef LIBRESSL_VERSION_NUMBER
/*
**  LibreSSL keeps EVP_PKEY_size()/EVP_PKEY_bits() as the canonical spellings.
**  EVP_PKEY_get_size/EVP_PKEY_get_bits are the OpenSSL 3 renames.  Map ours
**  onto the legacy names, which exist in every LibreSSL.  The guards keep this
**  inert should a future LibreSSL define the new spellings as macros itself.
*/
# ifndef EVP_PKEY_get_size
#  define EVP_PKEY_get_size(pkey)  EVP_PKEY_size((pkey))
# endif
# ifndef EVP_PKEY_get_bits
#  define EVP_PKEY_get_bits(pkey)  EVP_PKEY_bits((pkey))
# endif
#endif /* LIBRESSL_VERSION_NUMBER */

/*
**  DKIMF_SSL_VERSION_NUMBER -- the crypto provider's own version constant.
**
**  Used to verify that the libopendkim shared object and the opendkim binary
**  were built against the same crypto ABI.  Under LibreSSL the OpenSSL-compat
**  OPENSSL_VERSION_NUMBER is a frozen sentinel (0x2000000fL today) that says
**  nothing about the actual LibreSSL release and could be changed upstream,
**  so use LibreSSL's own LIBRESSL_VERSION_NUMBER there instead.  This keeps a
**  pure-LibreSSL build comparing like with like, independent of whatever the
**  sentinel happens to be.
*/
#ifdef LIBRESSL_VERSION_NUMBER
# define DKIMF_SSL_VERSION_NUMBER  LIBRESSL_VERSION_NUMBER
#else
# define DKIMF_SSL_VERSION_NUMBER  OPENSSL_VERSION_NUMBER
#endif

/*
**  DKIMF_SSL_PROVIDER_STR -- human-readable "<provider> <version>" for the -V
**  output's option list.
**
**  Each provider reports its real version under a different macro: OpenSSL's
**  OPENSSL_VERSION_STR is the frozen "2.0.0" sentinel under LibreSSL and an
**  OpenSSL-1.1.1 compatibility value under AWS-LC, so it cannot be used for
**  the other two.  Pick each provider's own canonical version string instead.
*/
/*
**  Only OpenSSL and LibreSSL are supported providers.  Other OpenSSL-compatible
**  libraries (BoringSSL, AWS-LC) explicitly disclaim API/ABI stability and are
**  not targets, so they are not detected here; should one ever be built
**  against, the OPENSSL_VERSION_STR guard and final fallback keep this from
**  misreporting a bogus version (LibreSSL's frozen "2.0.0" sentinel was the
**  original symptom) or failing to compile where OPENSSL_VERSION_STR is absent.
*/
#if defined(LIBRESSL_VERSION_NUMBER)
# define DKIMF_SSL_PROVIDER_STR  LIBRESSL_VERSION_TEXT        /* e.g. "LibreSSL 4.3.2" */
#elif defined(OPENSSL_VERSION_STR)
# define DKIMF_SSL_PROVIDER_STR  "OpenSSL " OPENSSL_VERSION_STR
#else
# define DKIMF_SSL_PROVIDER_STR  "OpenSSL (unknown version)"
#endif

#endif /* OPENSSL_COMPAT_H_ */
