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
#include <time.h>

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

/*
**  Body EOL normalization: a bare-LF body (as an MTA like Postfix hands a
**  milter) must produce the same body hash as the on-the-wire CRLF form, since
**  DKIM2 signatures are over CRLF.  Regression test for the verify-time
**  "body hash did not match" against bare-LF inbound bodies.
*/
static void
test_body_eol(void)
{
	const char *crlf = "Hello,\r\n\r\nfooter follows.\r\n-- \r\nsig\r\n";
	const char *lf   = "Hello,\n\nfooter follows.\n-- \nsig\n";
	const char *cr   = "Hello,\r\rfooter follows.\r-- \rsig\r";
	unsigned char want[DKIM2_HASH_LEN], got[DKIM2_HASH_LEN];
	char *norm;
	size_t normlen;

	/* reference hash is over the CRLF form */
	assert(dkim2_body_hash(crlf, strlen(crlf), want) == 0);

	/* bare LF normalizes to the same bytes -> same hash */
	assert(dkim2_body_to_crlf(lf, strlen(lf), &norm, &normlen) == 0);
	assert(normlen == strlen(crlf) && memcmp(norm, crlf, normlen) == 0);
	assert(dkim2_body_hash(norm, normlen, got) == 0);
	assert(memcmp(want, got, DKIM2_HASH_LEN) == 0);
	free(norm);

	/* bare CR is normalized too */
	assert(dkim2_body_to_crlf(cr, strlen(cr), &norm, &normlen) == 0);
	assert(normlen == strlen(crlf) && memcmp(norm, crlf, normlen) == 0);
	free(norm);

	/* idempotent on already-CRLF input */
	assert(dkim2_body_to_crlf(crlf, strlen(crlf), &norm, &normlen) == 0);
	assert(normlen == strlen(crlf) && memcmp(norm, crlf, normlen) == 0);
	free(norm);

	/* empty body is handled */
	assert(dkim2_body_to_crlf(NULL, 0, &norm, &normlen) == 0);
	assert(normlen == 0);
	free(norm);
}

/*
**  A folded Message-Instance h= value (the long base64 hashes wrapped across
**  lines, as a generating MTA emits them) must parse to clean hash components.
**  Regression test for "body hash did not match" caused by fold whitespace
**  surviving inside the parsed body hash and breaking the string comparison.
*/
static void
test_mi_folded(void)
{
	/* same hashes, one inline and one folded mid-base64 with CRLF + WSP */
	const char *flat =
	    "m=2; h=sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
	    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=;";
	const char *folded =
	    "m=2; h=sha256:AAAAAAAAAAAAAAAAAAAA\r\n  AAAAAAAAAAAAAAAAAAAAAAA=:"
	    "BBBBBBBBBBBBBBBB\r\n\tBBBBBBBBBBBBBBBBBBBBBBBBBBB=;";
	dkim2_mi_t *a = dkim2_mi_parse(flat, strlen(flat));
	dkim2_mi_t *b = dkim2_mi_parse(folded, strlen(folded));

	assert(a != NULL && a->mi_h != NULL);
	assert(b != NULL && b->mi_h != NULL);
	/* folding must not leak into the parsed hash strings */
	assert(strcmp(b->mi_h->he_name, "sha256") == 0);
	assert(strcmp(b->mi_h->he_header, a->mi_h->he_header) == 0);
	assert(strcmp(b->mi_h->he_body, a->mi_h->he_body) == 0);
	assert(strchr(b->mi_h->he_body, ' ') == NULL &&
	       strchr(b->mi_h->he_body, '\r') == NULL &&
	       strchr(b->mi_h->he_body, '\n') == NULL &&
	       strchr(b->mi_h->he_body, '\t') == NULL);
	dkim2_mi_free(a);
	dkim2_mi_free(b);
}

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

	/* Section 7.3: a 64-char nonce is accepted; 65 chars or a space is not */
	{
		char buf[256];
		char nonce[80];
		size_t j;

		for (j = 0; j < 64; j++)
			nonce[j] = 'a';
		nonce[64] = '\0';
		snprintf(buf, sizeof buf,
		    "i=1; m=1; t=2; mf=x; rt=y; d=e; s=sel:rsa-sha256:z; n=%s;",
		    nonce);
		s = dkim2_signature_parse(buf, strlen(buf));
		assert(s != NULL && s->sig_n != NULL && strlen(s->sig_n) == 64);
		dkim2_signature_free(s);

		nonce[64] = 'a';	/* 65 chars */
		nonce[65] = '\0';
		snprintf(buf, sizeof buf,
		    "i=1; m=1; t=2; mf=x; rt=y; d=e; s=sel:rsa-sha256:z; n=%s;",
		    nonce);
		assert(dkim2_signature_parse(buf, strlen(buf)) == NULL);

		{
			const char *sp =
			    "i=1; m=1; t=2; mf=x; rt=y; d=e; s=sel:rsa-sha256:z; n=a b;";

			assert(dkim2_signature_parse(sp, strlen(sp)) == NULL);
		}
	}
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

/* Like sign_hop, but emits an imaginary forwarding hop: nd= instead of mf=/rt=
** (spec-03 Section 8.7/9.3).  Exercises the real signing path's nd= emission. */
static char *
sign_hop_nd(const char *domain, const char *selector, EVP_PKEY *key,
            dkim2_alg_t alg, const char *nd, const char *const *hdrs, size_t nh,
            const char *body, uint64_t t, char **mi_out)
{
	dkim2_sign_params_t p;
	char *mi = NULL, *sig = NULL;

	memset(&p, 0, sizeof p);
	p.sp_domain = domain;
	p.sp_selector = selector;
	p.sp_key = key;
	p.sp_alg = alg;
	p.sp_nd = nd;		/* mf=/rt= suppressed by the library */
	p.sp_t = t;
	assert(dkim2_sign(&p, hdrs, nh, body, strlen(body), &mi, &sig) == 0);
	assert(sig != NULL);
	/* the emitted field must carry nd= and omit mf=/rt= */
	assert(strstr(sig, "nd=") != NULL);
	assert(strstr(sig, "mf=") == NULL && strstr(sig, "rt=") == NULL);
	*mi_out = mi;		/* originator's new Message-Instance */
	return sig;
}

/* Like sign_hop, but stamps the DKIM2-Signature with f= flags. */
static void
sign_hop_f(const char *domain, const char *selector, EVP_PKEY *key,
           dkim2_alg_t alg, const char *mf, const char *const *rt,
           size_t nrt, const char *const *hdrs, size_t nh,
           const char *body, const char *flags, char **mi, char **sig)
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
	p.sp_flags = flags;
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

		/*
		**  Section 10.4 live-envelope match tolerates the bracket
		**  convention: the chain here signs the "<addr>" reverse-path,
		**  while a receiving milter supplies the bare SMTP envelope.
		*/
		{
			const char *rcpt_bare[] = { "carol@final.example" };

			vo.vo_mail_from = "bounce@relay.example";
			vo.vo_rcpt_to = rcpt_bare;
			vo.vo_rcpt_count = 1;
			assert(dkim2_verify(msg, 7, body, strlen(body), &vo, &r)
			       == 0);
			assert(r.vr_state == DKIM2_V_PASS);
			dkim2_verify_result_clear(&r);

			/* a genuinely different sender still fails */
			vo.vo_mail_from = "attacker@evil.example";
			assert(dkim2_verify(msg, 7, body, strlen(body), &vo, &r)
			       == 0);
			assert(r.vr_state == DKIM2_V_PERMERROR);
			dkim2_verify_result_clear(&r);

			vo.vo_mail_from = NULL;
			vo.vo_rcpt_to = NULL;
			vo.vo_rcpt_count = 0;
		}

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

	/* a body-null recipe round-trips (formats as {"b":null}) and stops apply */
	memset(&rn, 0, sizeof rn);
	rn.re_body_null = 1;
	nb = dkim2_recipe_format(&rn);
	assert(nb != NULL);
	r2 = dkim2_recipe_parse(nb, strlen(nb));
	assert(r2 != NULL && r2->re_body_null);
	assert(dkim2_recipe_apply(r2, new_h, 3, new_b, strlen(new_b),
	                          &ph, &pnh, &pb, &pbl) == 1);
	free(nb);
	dkim2_recipe_free(r2);

	/* spec-03 Section 5.1: only the body may be destroyed.  {"b":null} is
	** accepted and marks the body irreversible; {"h":null} is rejected. */
	{
		const char *bnull = "eyJiIjpudWxsfQ==";	/* base64 {"b":null} */
		const char *hnull = "eyJoIjpudWxsfQ==";	/* base64 {"h":null} */

		r2 = dkim2_recipe_parse(bnull, strlen(bnull));
		assert(r2 != NULL && r2->re_body_null);
		dkim2_recipe_free(r2);
		/* {"h":null} is invalid and must fail the parse */
		assert(dkim2_recipe_parse(hnull, strlen(hnull)) == NULL);
	}

	/* a concrete header object alongside body-null: {"h":{…},"b":null}.
	** base64 of {"h":{"subject":[{"d":["Old"]}]},"b":null} */
	{
		const char *mixed =
		    "eyJoIjp7InN1YmplY3QiOlt7ImQiOlsiT2xkIl19XX0sImIiOm51bGx9";

		r2 = dkim2_recipe_parse(mixed, strlen(mixed));
		assert(r2 != NULL);
		assert(r2->re_body_null);		/* body destroyed */
		assert(r2->re_hdrs != NULL);		/* header still reversible */
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

	/* an explicit body-null ("b":null) recipe verifies as PASS: the chain
	** is accepted up to the irreversible-body hop, which can no longer be
	** reverted */
	{
		dkim2_recipe_t rn;
		char *nullr;
		char *miN = NULL, *sigN = NULL;
		const char *cur[] = { from, to, subj1, date, mi1, sig1 };
		const char *full[8];
		dkim2_sign_params_t p;

		memset(&rn, 0, sizeof rn);
		rn.re_body_null = 1;
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

/* ── f= flags: donotmodify / donotexplode (Section 10.8) ─────────────────── */

static void
test_flags(dkim2_alg_t alg, int bits)
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

	/* Section 7.3: a caller-supplied nonce is signed in and round-trips; an
	** over-length nonce is refused at signing time. */
	{
		const char *h0[] = { from, to, subj0, date };
		dkim2_sign_params_t pn;
		char *mn = NULL, *sn = NULL;
		char toolong[70];
		size_t j;

		memset(&pn, 0, sizeof pn);
		pn.sp_domain = "example.com";
		pn.sp_selector = "s1";
		pn.sp_key = k1;
		pn.sp_alg = alg;
		pn.sp_mf = "<alice@example.com>";
		pn.sp_rt = rt1;
		pn.sp_rt_count = 1;
		pn.sp_nonce = "dsn-index-42";
		assert(dkim2_sign(&pn, h0, 4, body0, strlen(body0),
		                  &mn, &sn) == 0);
		assert(strstr(sn, "n=dsn-index-42;") != NULL);
		{
			const char *full[] = { from, to, subj0, date, mn, sn };

			memset(&r, 0, sizeof r);
			assert(dkim2_verify(full, 6, body0, strlen(body0),
			    &vo, &r) == 0);
			assert(r.vr_state == DKIM2_V_PASS);
			dkim2_verify_result_clear(&r);
		}
		free(mn); free(sn);

		for (j = 0; j < 65; j++)
			toolong[j] = 'a';
		toolong[65] = '\0';
		pn.sp_nonce = toolong;
		mn = sn = NULL;
		assert(dkim2_sign(&pn, h0, 4, body0, strlen(body0),
		                  &mn, &sn) == -1);
	}

	/* donotmodify: an originator forbids modification; a downstream hop that
	** adds a modifying instance with different hashes must FAIL at i=1. */
	{
		const char *h0[] = { from, to, subj0, date };

		sign_hop_f("example.com", "s1", k1, alg, "<alice@example.com>",
		           rt1, 1, h0, 4, body0, "donotmodify", &mi1, &sig1);
		assert(strstr(sig1, "f=donotmodify") != NULL);
		{
			const char *orig[] = { from, to, subj0, date, mi1, sig1 };
			const char *cur[] = { from, to, subj1, date, mi1, sig1 };

			sign_mod("list.example", "s2", k2, alg,
			         "<list@list.example>", rt2, 1, cur, 6, body1,
			         orig, 6, body0, &mi2, &sig2);
			{
				const char *full[] = { from, to, subj1, date,
				                       mi1, sig1, mi2, sig2 };

				memset(&r, 0, sizeof r);
				assert(dkim2_verify(full, 8, body1,
				    strlen(body1), &vo, &r) == 0);
				assert(r.vr_state == DKIM2_V_FAIL && r.vr_i == 1);
				dkim2_verify_result_clear(&r);
			}
		}
		free(mi1); free(sig1); free(mi2); free(sig2);
		mi1 = sig1 = mi2 = sig2 = NULL;
	}

	/* donotmodify with an unchanged core re-sign (no new instance) stays PASS. */
	{
		const char *h0[] = { from, to, subj0, date };

		sign_hop_f("example.com", "s1", k1, alg, "<alice@example.com>",
		           rt1, 1, h0, 4, body0, "donotmodify", &mi1, &sig1);
		{
			const char *h1[] = { from, to, subj0, date, mi1, sig1 };

			sign_hop("list.example", "s2", k2, alg,
			         "<relay@list.example>", rt2, 1, h1, 6, body0,
			         &mi2, &sig2);
			assert(mi2 == NULL && sig2 != NULL);
			{
				const char *full[] = { from, to, subj0, date,
				                       mi1, sig1, sig2 };

				memset(&r, 0, sizeof r);
				assert(dkim2_verify(full, 7, body0,
				    strlen(body0), &vo, &r) == 0);
				assert(r.vr_state == DKIM2_V_PASS);
				dkim2_verify_result_clear(&r);
			}
		}
		free(mi1); free(sig1); free(sig2);
		mi1 = sig1 = sig2 = NULL;
	}

	/* donotexplode: a later signature flagged 'exploded' must FAIL at i=1. */
	{
		const char *h0[] = { from, to, subj0, date };

		sign_hop_f("example.com", "s1", k1, alg, "<alice@example.com>",
		           rt1, 1, h0, 4, body0, "donotexplode", &mi1, &sig1);
		{
			const char *h1[] = { from, to, subj0, date, mi1, sig1 };

			sign_hop_f("list.example", "s2", k2, alg,
			           "<relay@list.example>", rt2, 1, h1, 6, body0,
			           "exploded", &mi2, &sig2);
			assert(mi2 == NULL && sig2 != NULL);
			{
				const char *full[] = { from, to, subj0, date,
				                       mi1, sig1, sig2 };

				memset(&r, 0, sizeof r);
				assert(dkim2_verify(full, 7, body0,
				    strlen(body0), &vo, &r) == 0);
				assert(r.vr_state == DKIM2_V_FAIL && r.vr_i == 1);
				dkim2_verify_result_clear(&r);
			}
		}
		free(mi1); free(sig1); free(sig2);
		mi1 = sig1 = sig2 = NULL;
	}

	EVP_PKEY_free(k1);
	EVP_PKEY_free(k2);
	for (ZN--; ZN >= 0; ZN--)
	{
		free(ZONE[ZN].q);
		free(ZONE[ZN].rec);
	}
	ZN = 0;
}

/* ── nd= forward-signing tag (spec-03 Section 8.7) ───────────────────────── */

static void
test_nd(dkim2_alg_t alg, int bits)
{
	EVP_PKEY *k1 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	EVP_PKEY *k2 = genkey(alg == DKIM2_ALG_RSA_SHA256 ? EVP_PKEY_RSA
	                                                  : EVP_PKEY_ED25519, bits);
	const char *hdrs[] = {
		"From: Alice <alice@example.com>",
		"To: bob@dest.example",
		"Subject: nd test",
		"Date: Mon, 23 Jun 2026 00:00:00 +0000",
	};
	const char *body = "Body of the message.\r\n";
	const char *rt2[] = { "<carol@final.example>" };
	uint64_t now = (uint64_t) time(NULL);
	char *mi = NULL, *sig2 = NULL;
	char *nd_sig = NULL;
	dkim2_verify_result_t r;
	dkim2_verify_opts_t vo;

	ZN = 0;
	zone_add("s1._domainkey.example.com", k1, alg);
	zone_add("s2._domainkey.esp.example", k2, alg);
	memset(&vo, 0, sizeof vo);
	vo.vo_dns_txt = zone_lookup;

	/* ── parse-level XOR checks (Section 8) ── */
	{
		/* nd= alongside mf=/rt= is rejected */
		const char *both =
		    "i=1; m=1; t=2; nd=esp.example; mf=x; rt=y; d=e; "
		    "s=s1:rsa-sha256:z;";
		dkim2_signature_t *s;

		assert(dkim2_signature_parse(both, strlen(both)) == NULL);

		/* nd= without mf=/rt= parses; mf/rt stay NULL and round-trips */
		s = dkim2_signature_parse(
		    "i=1; m=1; t=2; nd=esp.example; d=e; s=s1:rsa-sha256:z;",
		    strlen("i=1; m=1; t=2; nd=esp.example; d=e; s=s1:rsa-sha256:z;"));
		assert(s != NULL);
		assert(s->sig_nd != NULL && strcmp(s->sig_nd, "esp.example") == 0);
		assert(s->sig_mf == NULL && s->sig_rt == NULL);
		{
			char *fmt = dkim2_signature_format(s);

			assert(fmt != NULL);
			assert(strstr(fmt, "nd=esp.example") != NULL);
			assert(strstr(fmt, "mf=") == NULL);
			free(fmt);
		}
		dkim2_signature_free(s);
	}

	/* The originator itself signs as an imaginary forwarding hop: dkim2_sign
	** emits a new m=1 Message-Instance plus an i=1 DKIM2-Signature carrying nd=
	** (and no mf=/rt=).  This exercises the real nd= emission path. */
	nd_sig = sign_hop_nd("example.com", "s1", k1, alg, "esp.example",
	                     hdrs, 4, body, now, &mi);
	assert(mi != NULL);

	/* hop 2: a real hop signed by esp.example, whose d= the nd= points at */
	{
		const char *h2[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3], mi, nd_sig };
		char *mi2 = NULL;

		sign_hop("esp.example", "s2", k2, alg, "<bounce@esp.example>",
		         rt2, 1, h2, 6, body, &mi2, &sig2);
		assert(mi2 == NULL && sig2 != NULL);	/* core re-sign adds no MI */
	}

	/* ── valid nd= chain verifies ── */
	{
		const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3],
		                      mi, nd_sig, sig2 };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(msg, 7, body, strlen(body), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PASS && r.vr_i == 2);
		dkim2_verify_result_clear(&r);
	}

	/* ── nd= that does not match the next d= → PERMERROR ── */
	{
		/* fails at the chain-of-custody step (before crypto), so a dummy
		** signature value suffices */
		char *bad = NULL;

		assert(asprintf(&bad,
		    "DKIM2-Signature: i=1; m=1; t=%llu; nd=wrong.example; "
		    "d=example.com; s=s1:%s:AAAA",
		    (unsigned long long) now, dkim2_alg_name(alg)) >= 0);
		{
			const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3],
			                      mi, bad, sig2 };

			memset(&r, 0, sizeof r);
			assert(dkim2_verify(msg, 7, body, strlen(body), &vo, &r) == 0);
			assert(r.vr_state == DKIM2_V_PERMERROR);
			assert(strstr(r.vr_message, "nd=") != NULL);
			dkim2_verify_result_clear(&r);
		}
		free(bad);
	}

	/* ── nd= on the highest signature (no real final hop) → PERMERROR ── */
	{
		const char *msg[] = { hdrs[0], hdrs[1], hdrs[2], hdrs[3],
		                      mi, nd_sig };

		memset(&r, 0, sizeof r);
		assert(dkim2_verify(msg, 6, body, strlen(body), &vo, &r) == 0);
		assert(r.vr_state == DKIM2_V_PERMERROR);
		assert(strstr(r.vr_message, "nd=") != NULL);
		dkim2_verify_result_clear(&r);
	}

	free(mi);
	free(nd_sig);
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

/* ── Delivered-To is excluded from the header hash (spec-03 Section 6.2) ──── */
static void
test_delivered_to(void)
{
	unsigned char d1[DKIM2_HASH_LEN], d2[DKIM2_HASH_LEN];
	const char *with[] = {
		"From: a@b", "Subject: x", "Delivered-To: bob@host.example",
	};
	const char *without[] = { "From: a@b", "Subject: x" };

	assert(!dkim2_header_is_signed("Delivered-To"));

	/* a Delivered-To field added in transit must not change the header hash */
	assert(dkim2_header_hash(with, 3, d1) == 0);
	assert(dkim2_header_hash(without, 2, d2) == 0);
	assert(memcmp(d1, d2, DKIM2_HASH_LEN) == 0);
}

int
main(void)
{
	test_body_eol();
	test_mi_folded();
	test_components();
	test_chain(DKIM2_ALG_RSA_SHA256, 2048);
	test_chain(DKIM2_ALG_ED25519_SHA256, 0);
	test_recipe();
	test_extended(DKIM2_ALG_RSA_SHA256, 2048);
	test_extended(DKIM2_ALG_ED25519_SHA256, 0);
	test_flags(DKIM2_ALG_RSA_SHA256, 2048);
	test_flags(DKIM2_ALG_ED25519_SHA256, 0);
	test_nd(DKIM2_ALG_RSA_SHA256, 2048);
	test_nd(DKIM2_ALG_ED25519_SHA256, 0);
	test_delivered_to();
	printf("t-dkim2-unit: PASS\n");
	return 0;
}
