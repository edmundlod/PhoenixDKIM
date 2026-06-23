/*
**  t-dkim2-unit.c -- DKIM2-core unit and round-trip tests.
**
**  Self-contained: it generates its own RSA and Ed25519 keys and verifies the
**  chain against an in-process DNS fixture, so it needs no external key files
**  or vendored message vectors.  Cross-implementation interop is exercised
**  separately by running phoenixdkim2-sign / phoenixdkim2-verify against the
**  live IETF interop harness.
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "base64.h"
#include "dkim2-crypto.h"
#include "dkim2-dns.h"
#include "dkim2-hash.h"
#include "dkim2-header.h"
#include "dkim2-sign.h"
#include "dkim2-tags.h"
#include "dkim2-verify.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static EVP_PKEY *
genkey(int id, int bits)
{
	EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(id, NULL);
	EVP_PKEY *k = NULL;

	assert(c != NULL);
	assert(EVP_PKEY_keygen_init(c) == 1);
	if (bits != 0)
		assert(EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits) > 0);
	assert(EVP_PKEY_keygen(c, &k) == 1);
	EVP_PKEY_CTX_free(c);
	return k;
}

static char *
b64(const unsigned char *d, size_t n)
{
	size_t cap = 4 * ((n + 2) / 3) + 1;
	char *o = malloc(cap);
	int e = dkim_base64_encode((u_char *) d, n, (u_char *) o, cap);

	assert(e >= 0);
	o[e] = '\0';
	return o;
}

/* DNS p= value for a key. */
static char *
pubp(EVP_PKEY *k, dkim2_alg_t a)
{
	if (a == DKIM2_ALG_RSA_SHA256)
	{
		unsigned char *d = NULL;
		int n = i2d_PUBKEY(k, &d);
		char *r;

		assert(n > 0);
		r = b64(d, (size_t) n);
		OPENSSL_free(d);
		return r;
	}
	else
	{
		unsigned char raw[32];
		size_t l = sizeof raw;

		assert(EVP_PKEY_get_raw_public_key(k, raw, &l) == 1 && l == 32);
		return b64(raw, 32);
	}
}

/* a minimal DNS fixture zone */
static struct { char *q; char *rec; } ZONE[8];
static int ZN;

static char *
zone_lookup(const char *q)
{
	int i;

	for (i = 0; i < ZN; i++)
		if (strcmp(ZONE[i].q, q) == 0)
			return strdup(ZONE[i].rec);
	return NULL;
}

static void
zone_add(const char *q, EVP_PKEY *k, dkim2_alg_t a)
{
	char *p = pubp(k, a);
	char rec[4096];

	snprintf(rec, sizeof rec, "v=DKIM1; k=%s; p=%s",
	         a == DKIM2_ALG_RSA_SHA256 ? "rsa" : "ed25519", p);
	ZONE[ZN].q = strdup(q);
	ZONE[ZN].rec = strdup(rec);
	ZN++;
	free(p);
}

/* ── component sanity ────────────────────────────────────────────────────── */

static void
test_components(void)
{
	dkim2_taglist_t *tl;
	dkim2_signature_t *s;
	unsigned char d1[DKIM2_HASH_LEN], d2[DKIM2_HASH_LEN];
	const char *h1[] = { "From: a@b", "Subject: x  y", "Received: z" };
	const char *h2[] = { "Subject: x  y", "From: a@b" };

	/* tag parser */
	tl = dkim2_taglist_parse("i=1; d=ex.com;", 14);
	assert(tl != NULL);
	assert(strcmp(dkim2_taglist_get(tl, "i"), "1") == 0);
	assert(strcmp(dkim2_taglist_get(tl, "d"), "ex.com") == 0);
	dkim2_taglist_free(tl);

	/* header hash ignores Received and is order-independent (alpha sort) */
	assert(dkim2_header_hash(h1, 3, d1) == 0);
	assert(dkim2_header_hash(h2, 2, d2) == 0);
	assert(memcmp(d1, d2, DKIM2_HASH_LEN) == 0);
	assert(dkim2_header_is_signed("From") && !dkim2_header_is_signed("Received"));

	/* signature model rejects a missing required tag */
	s = dkim2_signature_parse("i=1; m=1; t=2; mf=x; d=e;", 25);
	assert(s == NULL);	/* no rt=/s= */
}

/* ── full chain ──────────────────────────────────────────────────────────── */

static void
sign_hop(const char *domain, const char *selector, EVP_PKEY *key,
         dkim2_alg_t alg, const char *mf, const char *const *rt,
         size_t nrt, const char *const *hdrs, size_t nh,
         const char *body, char **mi, char **sig)
{
	dkim2_sign_params_t p;

	memset(&p, 0, sizeof p);
	p.sp_domain = domain;
	p.sp_selector = selector;
	p.sp_key = key;
	p.sp_alg = alg;
	p.sp_mf = mf;
	p.sp_rt = rt;
	p.sp_rt_count = nrt;
	p.sp_t = 0;	/* now */
	assert(dkim2_sign(&p, hdrs, nh, body, strlen(body), mi, sig) == 0);
}

static void
test_chain(dkim2_alg_t alg, int bits)
{
	EVP_PKEY *k1 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	EVP_PKEY *k2 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	const char *hdrs[] = {
		"From: Alice <alice@example.com>",
		"To: bob@dest.example",
		"Subject: chain test",
		"Date: Mon, 23 Jun 2026 00:00:00 +0000",
	};
	const char *body = "Body of the message.\r\n";
	const char *rt1[] = { "<bob@dest.example>" };
	const char *rt2[] = { "<carol@final.example>" };
	char *mi = NULL, *sig = NULL, *mi2 = NULL, *sig2 = NULL;
	dkim2_verify_result_t r;

	ZN = 0;
	zone_add("s1._domainkey.example.com", k1, alg);
	zone_add("s2._domainkey.relay.example", k2, alg);
	dkim2_dns_override = zone_lookup;

	/* hop 1 (originator) */
	sign_hop("example.com", "s1", k1, alg, "<alice@example.com>", rt1, 1,
	         hdrs, 4, body, &mi, &sig);
	assert(mi != NULL && sig != NULL);

	{
		const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(msg, 6, body, strlen(body), NULL, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS);
		dkim2_verify_result_clear(&r);

		/* tampered body fails */
		assert(dkim2_verify(msg, 6, "x\r\n", 3, NULL, &r) == 0);
		assert(r.vr_state == DKIM2_V_FAIL);
		dkim2_verify_result_clear(&r);
	}

	/* hop 2 (relay re-signs; core adds no MI) */
	{
		const char *h2[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig };

		sign_hop("relay.example", "s2", k2, alg, "<bounce@relay.example>",
		         rt2, 1, h2, 6, body, &mi2, &sig2);
		assert(mi2 == NULL && sig2 != NULL);
	}

	{
		const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig, sig2 };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(msg, 7, body, strlen(body), NULL, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS && r.vr_i == 2);
		dkim2_verify_result_clear(&r);

		/* dropping hop 1 leaves an i= gap */
		const char *gap[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig2 };

		assert(dkim2_verify(gap, 6, body, strlen(body), NULL, &r) == 0);
		assert(r.vr_state == DKIM2_V_PERMERROR);
		dkim2_verify_result_clear(&r);
	}

	free(mi);
	free(sig);
	free(sig2);
	EVP_PKEY_free(k1);
	EVP_PKEY_free(k2);
	for (ZN--; ZN >= 0; ZN--)
	{
		free(ZONE[ZN].q);
		free(ZONE[ZN].rec);
	}
	ZN = 0;
}

int
main(void)
{
	test_components();
	test_chain(DKIM2_ALG_RSA_SHA256, 2048);
	test_chain(DKIM2_ALG_ED25519_SHA256, 0);
	printf("t-dkim2-unit: PASS\n");
	return 0;
}
