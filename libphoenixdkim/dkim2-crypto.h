/*
**  dkim2-crypto.h -- DKIM2 signature primitives (draft-ietf-dkim-dkim2-spec
**  Sections 3.2, 3.3).
**
**  DKIM2 defines two mandatory algorithms, both of which SHA-256 the signing
**  input (the concatenated Message-Instance and DKIM2-Signature header fields
**  assembled per Section 8.5) and then sign that:
**
**    rsa-sha256      RSA PKCS#1 v1.5 over the SHA-256 hash
**    ed25519-sha256  PureEdDSA Ed25519 over the SHA-256 hash (RFC 8463 style)
**
**  This module signs and verifies a caller-supplied byte string; constructing
**  that byte string is the sign/verify modules' job.  Keys are OpenSSL
**  EVP_PKEYs: a private key from PEM (signing) or a public key from the DNS p=
**  value (verifying).
*/

#ifndef PHOENIXDKIM_DKIM2_CRYPTO_H
#define PHOENIXDKIM_DKIM2_CRYPTO_H

#include <stddef.h>

#include <openssl/evp.h>
#include "openssl-compat.h"

typedef enum
{
	DKIM2_ALG_UNKNOWN = 0,
	DKIM2_ALG_RSA_SHA256,
	DKIM2_ALG_ED25519_SHA256
} dkim2_alg_t;

/* Map between the spec's algorithm strings and the enum. */
extern dkim2_alg_t dkim2_alg_from_name(const char *name);
extern const char *dkim2_alg_name(dkim2_alg_t alg);

/*
**  DKIM2_PRIVKEY_LOAD_PEM -- load a PEM private key (RSA or Ed25519).
**  Returns an EVP_PKEY (free with EVP_PKEY_free()) or NULL.
*/
extern EVP_PKEY *dkim2_privkey_load_pem(const char *pem, size_t pemlen);

/*
**  DKIM2_PKEY_ALG -- the DKIM2 algorithm implied by a key's type, or
**  DKIM2_ALG_UNKNOWN.
*/
extern dkim2_alg_t dkim2_pkey_alg(const EVP_PKEY *key);

/*
**  DKIM2_PUBKEY_LOAD -- build a public key from a DNS p= base64 value.
**
**  For rsa-sha256 the value is base64 of the DER SubjectPublicKeyInfo (RFC
**  6376); for ed25519-sha256 it is base64 of the 32-byte raw key (RFC 8463).
**  Returns an EVP_PKEY (free with EVP_PKEY_free()) or NULL.
*/
extern EVP_PKEY *dkim2_pubkey_load(dkim2_alg_t alg, const char *p_b64);

/*
**  DKIM2_SIGN_DATA -- sign data with key under alg.
**  Returns a base64 signature (heap, free()) or NULL on error.
*/
extern char *dkim2_sign_data(dkim2_alg_t alg, EVP_PKEY *key,
                             const unsigned char *data, size_t datalen);

/*
**  DKIM2_VERIFY_DATA -- verify a base64 signature over data with key under alg.
**  Returns 1 (valid), 0 (invalid), or -1 (error).
*/
extern int dkim2_verify_data(dkim2_alg_t alg, EVP_PKEY *key,
                             const unsigned char *data, size_t datalen,
                             const char *sig_b64);

#endif /* PHOENIXDKIM_DKIM2_CRYPTO_H */
