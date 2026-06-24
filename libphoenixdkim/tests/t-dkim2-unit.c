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
#include "dkim2-recipe.h"
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
	unsigned char *tmp = malloc(n > 0 ? n : 1);
	char *o = malloc(cap);
	int e;

	assert(tmp != NULL && o != NULL);
	memcpy(tmp, d, n);
	e = dkim_base64_encode(tmp, n, (u_char *) o, cap);
	free(tmp);
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
zone_lookup(void *ctx, const char *q, dkim2_dns_status_t *status)
{
	int i;

	(void) ctx;

	for (i = 0; i < ZN; i++)
	{
		if (strcmp(ZONE[i].q, q) == 0)
		{
			*status = DKIM2_DNS_OK;
			return strdup(ZONE[i].rec);
		}
	}
	*status = DKIM2_DNS_NOKEY;
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
	dkim2_verify_opts_t vo;

	ZN = 0;
	zone_add("s1._domainkey.example.com", k1, alg);
	zone_add("s2._domainkey.relay.example", k2, alg);
	memset(&vo, 0, sizeof vo);
	vo.vo_dns_txt = zone_lookup;

	/* hop 1 (originator) */
	sign_hop("example.com", "s1", k1, alg, "<alice@example.com>", rt1, 1,
	         hdrs, 4, body, &mi, &sig);
	assert(mi != NULL && sig != NULL);

	{
		const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(msg, 6, body, strlen(body), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS);
		dkim2_verify_result_clear(&r);

		/* tampered body fails */
		assert(dkim2_verify(msg, 6, "x\r\n", 3, &vo, &r) == 0);
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
		assert(dkim2_verify(msg, 7, body, strlen(body), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS && r.vr_i == 2);
		dkim2_verify_result_clear(&r);

		/* dropping hop 1 leaves an i= gap */
		const char *gap[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, sig2 };

		assert(dkim2_verify(gap, 6, body, strlen(body), &vo, &r) == 0);
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

/* ── recipes (extended profile) ──────────────────────────────────────────── */

static int
hh_eq(const char *const *a, size_t na, const char *const *b, size_t nb)
{
	unsigned char ha[DKIM2_HASH_LEN], hb[DKIM2_HASH_LEN];

	assert(dkim2_header_hash(a, na, ha) == 0);
	assert(dkim2_header_hash(b, nb, hb) == 0);
	return memcmp(ha, hb, DKIM2_HASH_LEN) == 0;
}

static int
bh_eq(const char *a, size_t na, const char *b, size_t nb)
{
	unsigned char ha[DKIM2_HASH_LEN], hb[DKIM2_HASH_LEN];

	assert(dkim2_body_hash(a, na, ha) == 0);
	assert(dkim2_body_hash(b, nb, hb) == 0);
	return memcmp(ha, hb, DKIM2_HASH_LEN) == 0;
}

static void
test_recipe(void)
{
	const char *old_h[] = { "From: a@b", "Subject: Hi", "To: c@d" };
	const char *new_h[] = { "From: a@b", "Subject: [list] Hi", "To: c@d" };
	const char *old_b = "Hello\r\nBye\r\n";
	const char *new_b = "Hello\r\nBye\r\n--\r\nsent via list\r\n";
	dkim2_recipe_t *r, *r2;
	char *b1, *b2;
	char **ph = NULL;
	size_t pnh = 0, i;
	char *pb = NULL;
	size_t pbl = 0;
	dkim2_recipe_t rn;
	char *nb;

	/* generate reconstructs old from new; format round-trips stably */
	r = dkim2_recipe_generate(old_h, 3, old_b, strlen(old_b),
	                          new_h, 3, new_b, strlen(new_b));
	assert(r != NULL);
	b1 = dkim2_recipe_format(r);
	assert(b1 != NULL);
	r2 = dkim2_recipe_parse(b1, strlen(b1));
	assert(r2 != NULL);
	b2 = dkim2_recipe_format(r2);
	assert(b2 != NULL && strcmp(b1, b2) == 0);

	/* inverse property: apply(generate(old,new), new) == old (by hash) */
	assert(dkim2_recipe_apply(r2, new_h, 3, new_b, strlen(new_b),
	                          &ph, &pnh, &pb, &pbl) == 0);
	assert(hh_eq(old_h, 3, (const char *const *) ph, pnh));
	assert(bh_eq(old_b, strlen(old_b), pb, pbl));
	for (i = 0; i < pnh; i++)
		free(ph[i]);
	free(ph);
	free(pb);
	free(b1);
	free(b2);
	dkim2_recipe_free(r);
	dkim2_recipe_free(r2);

	/* an irreversible (null) recipe round-trips and stops apply */
	memset(&rn, 0, sizeof rn);
	rn.re_null = 1;
	nb = dkim2_recipe_format(&rn);
	assert(nb != NULL);
	r2 = dkim2_recipe_parse(nb, strlen(nb));
	assert(r2 != NULL && r2->re_null);
	assert(dkim2_recipe_apply(r2, new_h, 3, new_b, strlen(new_b),
	                          &ph, &pnh, &pb, &pbl) == 1);
	free(nb);
	dkim2_recipe_free(r2);

	/* a null part on either side is irreversible (the dkim2.com redacted
	** reflector sends {"b":null}) */
	{
		const char *bnull = "eyJiIjpudWxsfQ==";	/* base64 {"b":null} */
		const char *hnull = "eyJoIjpudWxsfQ==";	/* base64 {"h":null} */

		r2 = dkim2_recipe_parse(bnull, strlen(bnull));
		assert(r2 != NULL && r2->re_null);
		dkim2_recipe_free(r2);
		r2 = dkim2_recipe_parse(hnull, strlen(hnull));
		assert(r2 != NULL && r2->re_null);
		dkim2_recipe_free(r2);
	}
}

/* Sign a modifying hop: records a recipe reverting (cur) to (orig). */
static void
sign_mod(const char *domain, const char *selector, EVP_PKEY *key,
         dkim2_alg_t alg, const char *mf, const char *const *rt, size_t nrt,
         const char *const *cur_h, size_t cur_nh, const char *cur_b,
         const char *const *orig_h, size_t orig_nh, const char *orig_b,
         char **mi, char **sig)
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
	p.sp_orig_headers = orig_h;
	p.sp_orig_nheaders = orig_nh;
	p.sp_orig_body = orig_b;
	p.sp_orig_bodylen = strlen(orig_b);
	assert(dkim2_sign(&p, cur_h, cur_nh, cur_b, strlen(cur_b), mi, sig) == 0);
}

static void
test_extended(dkim2_alg_t alg, int bits)
{
	EVP_PKEY *k1 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	EVP_PKEY *k2 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	const char *from = "From: Alice <alice@example.com>";
	const char *to = "To: bob@dest.example";
	const char *date = "Date: Mon, 23 Jun 2026 00:00:00 +0000";
	const char *subj0 = "Subject: Hi";
	const char *subj1 = "Subject: [list] Hi";
	const char *body0 = "Hello\r\nBye\r\n";
	const char *body1 = "Hello\r\nBye\r\n--\r\nsent via list\r\n";
	const char *rt1[] = { "<bob@dest.example>" };
	const char *rt2[] = { "<list@dest.example>" };
	char *mi1 = NULL, *sig1 = NULL, *mi2 = NULL, *sig2 = NULL;
	dkim2_verify_result_t r;
	dkim2_verify_opts_t vo;

	ZN = 0;
	zone_add("s1._domainkey.example.com", k1, alg);
	zone_add("s2._domainkey.list.example", k2, alg);
	memset(&vo, 0, sizeof vo);
	vo.vo_dns_txt = zone_lookup;

	/* originator signs m=1 over the unmodified message */
	{
		const char *h0[] = { from, to, subj0, date };

		sign_hop("example.com", "s1", k1, alg, "<alice@example.com>",
		         rt1, 1, h0, 4, body0, &mi1, &sig1);
		assert(mi1 != NULL && sig1 != NULL);
	}

	/* a list modifies the subject and appends a footer, then re-signs:
	** the original it received and the modified message it forwards */
	{
		const char *orig[] = { from, to, subj0, date, mi1, sig1 };
		const char *cur[] = { from, to, subj1, date, mi1, sig1 };

		sign_mod("list.example", "s2", k2, alg, "<list@list.example>",
		         rt2, 1, cur, 6, body1, orig, 6, body0, &mi2, &sig2);
		assert(mi2 != NULL && sig2 != NULL);
		/* the new instance carries a recipe */
		assert(strstr(mi2, "r=") != NULL && strstr(mi2, "m=2") != NULL);
	}

	/* full chain verifies, reconstructing m=1 from the recipe */
	{
		const char *full[] = { from, to, subj1, date, mi1, sig1, mi2, sig2 };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(full, 8, body1, strlen(body1), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS && r.vr_i == 2);
		dkim2_verify_result_clear(&r);

		/* tampering a forwarded body line breaks reconstruction */
		assert(dkim2_verify(full, 8, "Hello\r\nGONE\r\n--\r\nsent via list\r\n",
		                    32, &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_FAIL);
		dkim2_verify_result_clear(&r);
	}

	/* an explicit irreversible ("h":null) recipe verifies as PASS: the chain
	** is accepted up to the irreversible hop, which can no longer be reverted */
	{
		dkim2_recipe_t rn;
		char *nullr;
		char *miN = NULL, *sigN = NULL;
		const char *cur[] = { from, to, subj1, date, mi1, sig1 };
		const char *full[8];
		dkim2_sign_params_t p;

		memset(&rn, 0, sizeof rn);
		rn.re_null = 1;
		nullr = dkim2_recipe_format(&rn);
		assert(nullr != NULL);

		memset(&p, 0, sizeof p);
		p.sp_domain = "list.example";
		p.sp_selector = "s2";
		p.sp_key = k2;
		p.sp_alg = alg;
		p.sp_mf = "<list@list.example>";
		p.sp_rt = rt2;
		p.sp_rt_count = 1;
		p.sp_recipe = nullr;	/* explicit irreversible recipe */
		assert(dkim2_sign(&p, cur, 6, body1, strlen(body1),
		                  &miN, &sigN) == 0);
		assert(miN != NULL && sigN != NULL);

		full[0] = from; full[1] = to; full[2] = subj1; full[3] = date;
		full[4] = mi1; full[5] = sig1; full[6] = miN; full[7] = sigN;

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(full, 8, body1, strlen(body1), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS);
		dkim2_verify_result_clear(&r);
		free(nullr);
		free(miN);
		free(sigN);
	}

	free(mi1);
	free(sig1);
	free(mi2);
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
	test_recipe();
	test_extended(DKIM2_ALG_RSA_SHA256, 2048);
	test_extended(DKIM2_ALG_ED25519_SHA256, 0);
	printf("t-dkim2-unit: PASS\n");
	return 0;
}
