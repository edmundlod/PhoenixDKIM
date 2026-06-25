/*
**  dkim2-crypto.c -- DKIM2 signature primitives.  See dkim2-crypto.h.
*/

#include "dkim2-crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* libphoenixdkim includes */
#include "base64.h"

/* ── algorithm names ─────────────────────────────────────────────────────── */

dkim2_alg_t
dkim2_alg_from_name(const char *name)
{
	if (name == NULL)
		return DKIM2_ALG_UNKNOWN;
	if (strcmp(name, "rsa-sha256") == 0)
		return DKIM2_ALG_RSA_SHA256;
	if (strcmp(name, "ed25519-sha256") == 0)
		return DKIM2_ALG_ED25519_SHA256;
	return DKIM2_ALG_UNKNOWN;
}

const char *
dkim2_alg_name(dkim2_alg_t alg)
{
	switch (alg)
	{
	  case DKIM2_ALG_RSA_SHA256:
		return "rsa-sha256";
	  case DKIM2_ALG_ED25519_SHA256:
		return "ed25519-sha256";
	  default:
		return NULL;
	}
}

/* ── key loading ─────────────────────────────────────────────────────────── */

EVP_PKEY *
dkim2_privkey_load_pem(const char *pem, size_t pemlen)
{
	BIO *bio;
	EVP_PKEY *key;

	if (pem == NULL || pemlen > INT_MAX)
		return NULL;

	bio = BIO_new_mem_buf(pem, (int) pemlen);
	if (bio == NULL)
		return NULL;

	key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	return key;
}

dkim2_alg_t
dkim2_pkey_alg(const EVP_PKEY *key)
{
	if (key == NULL)
		return DKIM2_ALG_UNKNOWN;

	switch (EVP_PKEY_base_id(key))
	{
	  case EVP_PKEY_RSA:
		return DKIM2_ALG_RSA_SHA256;
	  case EVP_PKEY_ED25519:
		return DKIM2_ALG_ED25519_SHA256;
	  default:
		return DKIM2_ALG_UNKNOWN;
	}
}

EVP_PKEY *
dkim2_pubkey_load(dkim2_alg_t alg, const char *p_b64)
{
	unsigned char *der;
	int derlen;
	EVP_PKEY *key = NULL;
	size_t b64len;

	if (p_b64 == NULL || *p_b64 == '\0')
		return NULL;	/* empty p= is a revoked key */

	b64len = strlen(p_b64);
	der = malloc(b64len + 1);
	if (der == NULL)
		return NULL;

	derlen = dkim_base64_decode((const u_char *) p_b64, der, b64len + 1);
	if (derlen <= 0)
	{
		free(der);
		return NULL;
	}

	switch (alg)
	{
	  case DKIM2_ALG_RSA_SHA256:
	  {
		const unsigned char *q = der;

		/* p= is a DER SubjectPublicKeyInfo for RSA (RFC 6376). */
		key = d2i_PUBKEY(NULL, &q, (long) derlen);
		break;
	  }
	  case DKIM2_ALG_ED25519_SHA256:
		/* RFC 8463 publishes the raw 32-byte key in p=, but some signers
		** publish a DER SubjectPublicKeyInfo instead (as RSA does, and as
		** anything piping "openssl pkey -pubout" produces). The DKIM2
		** reference verifier accepts either form, so we do too. */
		if (derlen == 32)
		{
			key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,
			                                  NULL, der,
			                                  (size_t) derlen);
		}
		else
		{
			const unsigned char *q = der;

			key = d2i_PUBKEY(NULL, &q, (long) derlen);
			/* a non-Ed25519 SPKI must not masquerade as one */
			if (key != NULL &&
			    EVP_PKEY_base_id(key) != EVP_PKEY_ED25519)
			{
				EVP_PKEY_free(key);
				key = NULL;
			}
		}
		break;
	  default:
		break;
	}

	free(der);
	return key;
}

/* ── sign / verify ───────────────────────────────────────────────────────── */

/* SHA-256 a buffer into out[32]; returns 0 / -1. */
static int
dkim2_sha256(const unsigned char *data, size_t datalen, unsigned char out[32])
{
	unsigned int outlen = 0;

	if (EVP_Digest(data, datalen, out, &outlen, EVP_sha256(), NULL) != 1)
		return -1;
	return outlen == 32 ? 0 : -1;
}

char *
dkim2_sign_data(dkim2_alg_t alg, EVP_PKEY *key,
                const unsigned char *data, size_t datalen)
{
	EVP_MD_CTX *ctx;
	unsigned char hash[32];
	unsigned char *sig = NULL;
	size_t siglen = 0;
	char *b64 = NULL;
	int ok = 0;

	if (key == NULL || data == NULL)
		return NULL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return NULL;

	if (alg == DKIM2_ALG_RSA_SHA256)
	{
		/* DigestSign with SHA-256 hashes the input then RSA-signs it. */
		if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1)
			goto done;
		if (EVP_DigestSign(ctx, NULL, &siglen, data, datalen) != 1)
			goto done;
		sig = malloc(siglen);
		if (sig == NULL)
			goto done;
		if (EVP_DigestSign(ctx, sig, &siglen, data, datalen) != 1)
			goto done;
	}
	else if (alg == DKIM2_ALG_ED25519_SHA256)
	{
		/* Ed25519 is pure: hash first, then sign the 32-byte digest. */
		if (dkim2_sha256(data, datalen, hash) != 0)
			goto done;
		if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1)
			goto done;
		if (EVP_DigestSign(ctx, NULL, &siglen, hash, sizeof hash) != 1)
			goto done;
		sig = malloc(siglen);
		if (sig == NULL)
			goto done;
		if (EVP_DigestSign(ctx, sig, &siglen, hash, sizeof hash) != 1)
			goto done;
	}
	else
	{
		goto done;
	}

	/* base64-encode the signature; 4 chars per 3 bytes, rounded up, plus NUL */
	{
		size_t b64cap = 4 * ((siglen + 2) / 3) + 1;
		int enc;

		b64 = malloc(b64cap);
		if (b64 == NULL)
			goto done;
		enc = dkim_base64_encode(sig, siglen, (u_char *) b64, b64cap);
		if (enc < 0)
		{
			free(b64);
			b64 = NULL;
			goto done;
		}
		b64[(size_t) enc] = '\0';
		ok = 1;
	}

  done:
	EVP_MD_CTX_free(ctx);
	free(sig);
	return ok ? b64 : NULL;
}

int
dkim2_verify_data(dkim2_alg_t alg, EVP_PKEY *key,
                  const unsigned char *data, size_t datalen,
                  const char *sig_b64)
{
	EVP_MD_CTX *ctx;
	unsigned char hash[32];
	unsigned char *sig;
	int siglen;
	size_t b64len;
	int rc = -1;

	if (key == NULL || data == NULL || sig_b64 == NULL)
		return -1;

	b64len = strlen(sig_b64);
	sig = malloc(b64len + 1);
	if (sig == NULL)
		return -1;
	siglen = dkim_base64_decode((const u_char *) sig_b64, sig, b64len + 1);
	if (siglen <= 0)
	{
		free(sig);
		return -1;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		free(sig);
		return -1;
	}

	if (alg == DKIM2_ALG_RSA_SHA256)
	{
		if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1)
			rc = EVP_DigestVerify(ctx, sig, (size_t) siglen,
			                      data, datalen);
	}
	else if (alg == DKIM2_ALG_ED25519_SHA256)
	{
		if (dkim2_sha256(data, datalen, hash) == 0 &&
		    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1)
			rc = EVP_DigestVerify(ctx, sig, (size_t) siglen,
			                      hash, sizeof hash);
	}

	EVP_MD_CTX_free(ctx);
	free(sig);

	/* EVP_DigestVerify: 1 = valid, 0 = invalid, <0 = error. Normalize. */
	if (rc == 1)
		return 1;
	if (rc == 0)
		return 0;
	return -1;
}
