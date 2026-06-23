/*
**  dkim2-verify.c -- DKIM2-core chain verification.  See dkim2-verify.h.
*/

#include "dkim2-verify.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* libphoenixdkim includes */
#include "base64.h"
#include "dkim2-crypto.h"
#include "dkim2-dns.h"
#include "dkim2-hash.h"
#include "dkim2-header.h"
#include "dkim2-sign.h"	/* dkim2_canon_field_85() */

#define DKIM2_MAX_AGE	(14 * 24 * 60 * 60)	/* 14 days, in seconds */

struct dkim2_sigrec
{
	const char		*raw;	/* full "DKIM2-Signature: ..." field */
	dkim2_signature_t	*sig;	/* parsed value */
};

struct dkim2_mirec
{
	const char	*raw;	/* full "Message-Instance: ..." field */
	dkim2_mi_t	*mi;	/* parsed value */
};

/* ── result helpers ──────────────────────────────────────────────────────── */

static int
dkim2_result(dkim2_verify_result_t *out, dkim2_vstate_t state,
             uint64_t i, const char *message)
{
	out->vr_state = state;
	out->vr_i = i;
	out->vr_message = message != NULL ? strdup(message) : NULL;
	return 0;
}

void
dkim2_verify_result_clear(dkim2_verify_result_t *out)
{
	if (out == NULL)
		return;
	free(out->vr_message);
	out->vr_message = NULL;
}

/* ── small helpers ───────────────────────────────────────────────────────── */

static int
dkim2_field_name_is(const char *field, const char *name)
{
	const char *colon = strchr(field, ':');
	size_t nl;

	if (colon == NULL)
		return 0;
	nl = (size_t) (colon - field);
	while (nl > 0 && (field[nl - 1] == ' ' || field[nl - 1] == '\t'))
		nl--;
	return nl == strlen(name) && strncasecmp(field, name, nl) == 0;
}

/* base64-decode into a fresh NUL-terminated string (NULL on error). */
static char *
dkim2_b64_decode_str(const char *b64)
{
	size_t n = strlen(b64);
	unsigned char *out = malloc(n + 1);
	int d;

	if (out == NULL)
		return NULL;
	d = dkim_base64_decode((const u_char *) b64, out, n + 1);
	if (d < 0)
	{
		free(out);
		return NULL;
	}
	out[d] = '\0';
	return (char *) out;
}

/* Lowercased domain of an SMTP path "<local@domain>"; NULL for "<>"/no '@'. */
static char *
dkim2_path_domain(const char *path)
{
	const char *at = strrchr(path, '@');
	const char *end;
	size_t n;
	char *d;
	size_t i;

	if (at == NULL)
		return NULL;
	at++;
	end = at;
	while (*end != '\0' && *end != '>')
		end++;
	n = (size_t) (end - at);
	d = malloc(n + 1);
	if (d == NULL)
		return NULL;
	for (i = 0; i < n; i++)
		d[i] = (char) tolower((unsigned char) at[i]);
	d[n] = '\0';
	return d;
}

/* Relaxed domain match: mf == d, or mf is a subdomain of d (Section 7.7). */
static int
dkim2_domain_match(const char *mf, const char *d)
{
	size_t lm = strlen(mf);
	size_t ld = strlen(d);

	if (lm == ld)
		return strcasecmp(mf, d) == 0;
	if (lm > ld)
		return mf[lm - ld - 1] == '.' && strcasecmp(mf + lm - ld, d) == 0;
	return 0;
}

/* Copy raw with every non-empty s= signature value removed (blank in place). */
static char *
dkim2_blank_sig(const char *raw, const dkim2_signature_t *sig)
{
	char *cur = strdup(raw);
	const dkim2_sigentry_t *e;

	if (cur == NULL)
		return NULL;
	for (e = sig->sig_s; e != NULL; e = e->se_next)
	{
		char *at;

		if (e->se_sig[0] == '\0')
			continue;
		at = strstr(cur, e->se_sig);
		if (at != NULL)
		{
			size_t sl = strlen(e->se_sig);

			memmove(at, at + sl, strlen(at + sl) + 1);
		}
	}
	return cur;
}

static int
dkim2_keyalg_matches(const char *kr_alg, dkim2_alg_t alg)
{
	if (alg == DKIM2_ALG_RSA_SHA256)
		return strcasecmp(kr_alg, "rsa") == 0;
	if (alg == DKIM2_ALG_ED25519_SHA256)
		return strcasecmp(kr_alg, "ed25519") == 0;
	return 0;
}

/* qsort comparators by parsed key */
static int
dkim2_cmp_sig(const void *a, const void *b)
{
	uint64_t ia = ((const struct dkim2_sigrec *) a)->sig->sig_i;
	uint64_t ib = ((const struct dkim2_sigrec *) b)->sig->sig_i;

	return ia < ib ? -1 : (ia > ib ? 1 : 0);
}

static int
dkim2_cmp_mi(const void *a, const void *b)
{
	uint64_t ma = ((const struct dkim2_mirec *) a)->mi->mi_m;
	uint64_t mb = ((const struct dkim2_mirec *) b)->mi->mi_m;

	return ma < mb ? -1 : (ma > mb ? 1 : 0);
}

/*
**  DKIM2_BUILD_INPUT_85 -- assemble the Section 8.5 signing input for the
**  signature at sigs[k]: all Message-Instance fields (ascending m), the
**  DKIM2-Signature fields with a lower i (ascending), then sigs[k] with its
**  signature value(s) blanked.
*/
static char *
dkim2_build_input_85(const struct dkim2_mirec *mis, size_t nmi,
                     const struct dkim2_sigrec *sigs, size_t k,
                     size_t *lenp)
{
	char *buf = NULL;
	size_t buflen = 0;
	FILE *f = open_memstream(&buf, &buflen);
	size_t j;
	int err = 0;
	char *blanked;

	if (f == NULL)
		return NULL;

#define EMIT(FIELD)                                            \
	do {                                                       \
		char *_c = dkim2_canon_field_85(FIELD);                \
		if (_c == NULL) { err = 1; }                           \
		else { fwrite(_c, 1, strlen(_c), f); free(_c); }       \
	} while (0)

	for (j = 0; j < nmi && !err; j++)
		EMIT(mis[j].raw);
	for (j = 0; j < k && !err; j++)
		EMIT(sigs[j].raw);

	blanked = dkim2_blank_sig(sigs[k].raw, sigs[k].sig);
	if (blanked == NULL)
		err = 1;
	else
	{
		EMIT(blanked);
		free(blanked);
	}
#undef EMIT

	if (fclose(f) != 0 || err)
	{
		free(buf);
		return NULL;
	}
	*lenp = buflen;
	return buf;
}

/* ── verification ────────────────────────────────────────────────────────── */

int
dkim2_verify(const char *const *headers, size_t nheaders,
             const char *body, size_t bodylen,
             const dkim2_verify_opts_t *opts,
             dkim2_verify_result_t *out)
{
	static const dkim2_verify_opts_t defopts;
	struct dkim2_mirec *mis = NULL;
	struct dkim2_sigrec *sigs = NULL;
	size_t nmi = 0, nsig = 0;
	size_t i, k;
	unsigned char hh[DKIM2_HASH_LEN], bh[DKIM2_HASH_LEN];
	char *hh_b64 = NULL, *bh_b64 = NULL;
	const dkim2_mi_t *top_mi;
	const dkim2_hashentry_t *he;
	int rc = -1;
	char msg[256];

	if (out == NULL)
		return -1;
	out->vr_state = DKIM2_V_PERMERROR;
	out->vr_i = 0;
	out->vr_message = NULL;
	if (opts == NULL)
		opts = &defopts;

	mis = calloc(nheaders ? nheaders : 1, sizeof *mis);
	sigs = calloc(nheaders ? nheaders : 1, sizeof *sigs);
	if (mis == NULL || sigs == NULL)
		goto cleanup;

	/* 10.2: collect and structurally validate all DKIM2 fields. */
	for (i = 0; i < nheaders; i++)
	{
		const char *field = headers[i];
		const char *value;

		if (field == NULL)
			continue;
		value = strchr(field, ':');
		if (value == NULL)
			continue;
		value++;

		if (dkim2_field_name_is(field, "message-instance"))
		{
			dkim2_mi_t *mi = dkim2_mi_parse(value, strlen(value));

			if (mi == NULL)
			{
				rc = dkim2_result(out, DKIM2_V_PERMERROR, 0,
				    "Message-Instance syntax error");
				goto cleanup;
			}
			mis[nmi].raw = field;
			mis[nmi].mi = mi;
			nmi++;
		}
		else if (dkim2_field_name_is(field, "dkim2-signature"))
		{
			dkim2_signature_t *s =
			    dkim2_signature_parse(value, strlen(value));

			if (s == NULL)
			{
				rc = dkim2_result(out, DKIM2_V_PERMERROR, 0,
				    "DKIM2-Signature syntax error");
				goto cleanup;
			}
			sigs[nsig].raw = field;
			sigs[nsig].sig = s;
			nsig++;
		}
	}

	if (nsig == 0)
	{
		rc = dkim2_result(out, DKIM2_V_NONE, 0, "no DKIM2-Signature");
		goto cleanup;
	}
	if (nmi == 0)
	{
		rc = dkim2_result(out, DKIM2_V_PERMERROR, 0,
		    "Message-Instance m=1 missing");
		goto cleanup;
	}

	qsort(mis, nmi, sizeof *mis, dkim2_cmp_mi);
	qsort(sigs, nsig, sizeof *sigs, dkim2_cmp_sig);

	/* contiguous numbering from 1, no gaps */
	for (k = 0; k < nmi; k++)
	{
		if (mis[k].mi->mi_m != (uint64_t) (k + 1))
		{
			snprintf(msg, sizeof msg,
			    "Message-Instance m=%zu missing", k + 1);
			rc = dkim2_result(out, DKIM2_V_PERMERROR, k + 1, msg);
			goto cleanup;
		}
	}
	for (k = 0; k < nsig; k++)
	{
		if (sigs[k].sig->sig_i != (uint64_t) (k + 1))
		{
			snprintf(msg, sizeof msg,
			    "DKIM2-Signature i=%zu missing", k + 1);
			rc = dkim2_result(out, DKIM2_V_PERMERROR, k + 1, msg);
			goto cleanup;
		}
	}
	/* 10.2 special case: no instance numbered above any signature */
	if (mis[nmi - 1].mi->mi_m > sigs[nsig - 1].sig->sig_i)
	{
		rc = dkim2_result(out, DKIM2_V_PERMERROR, 0,
		    "Message-Instance is not signed");
		goto cleanup;
	}

	/* 10.3: timestamps */
	if (!opts->vo_ignore_timestamps)
	{
		uint64_t now = (uint64_t) time(NULL);

		for (k = 0; k < nsig; k++)
		{
			uint64_t t = sigs[k].sig->sig_t;

			if (t > now || now - t > DKIM2_MAX_AGE)
			{
				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu signature expired",
				    (unsigned long long) sigs[k].sig->sig_i);
				rc = dkim2_result(out, DKIM2_V_PERMERROR,
				    sigs[k].sig->sig_i, msg);
				goto cleanup;
			}
		}
	}

	/* 10.4: chain of custody.  d= must align with mf= on every signature; the
	** live envelope, if supplied, must match the top signature exactly. */
	for (k = 0; k < nsig; k++)
	{
		const dkim2_signature_t *s = sigs[k].sig;
		char *mf = dkim2_b64_decode_str(s->sig_mf);
		char *mfdom;

		if (mf == NULL)
		{
			rc = dkim2_result(out, DKIM2_V_PERMERROR, s->sig_i,
			    "DKIM2-Signature mf= syntax error");
			goto cleanup;
		}
		mfdom = dkim2_path_domain(mf);
		free(mf);
		/* an empty MAIL FROM ("<>") requires no d= match */
		if (mfdom != NULL)
		{
			int ok = dkim2_domain_match(mfdom, s->sig_d);

			free(mfdom);
			if (!ok)
			{
				rc = dkim2_result(out, DKIM2_V_PERMERROR,
				    s->sig_i, "MAIL FROM and d= do not match");
				goto cleanup;
			}
		}
	}

	if (opts->vo_mail_from != NULL)
	{
		const dkim2_signature_t *top = sigs[nsig - 1].sig;
		char *mf = dkim2_b64_decode_str(top->sig_mf);
		int ok = (mf != NULL && strcasecmp(mf, opts->vo_mail_from) == 0);

		free(mf);
		if (!ok)
		{
			rc = dkim2_result(out, DKIM2_V_PERMERROR, top->sig_i,
			    "MAIL FROM did not match");
			goto cleanup;
		}

		for (i = 0; i < opts->vo_rcpt_count; i++)
		{
			int found = 0;
			size_t r;

			for (r = 0; r < top->sig_rt_count && !found; r++)
			{
				char *rt = dkim2_b64_decode_str(top->sig_rt[r]);

				if (rt != NULL &&
				    strcasecmp(rt, opts->vo_rcpt_to[i]) == 0)
					found = 1;
				free(rt);
			}
			if (!found)
			{
				rc = dkim2_result(out, DKIM2_V_PERMERROR,
				    top->sig_i, "RCPT TO did not match");
				goto cleanup;
			}
		}
	}

	/* 10.5 + 10.6: fetch keys and verify every signature value. */
	for (k = 0; k < nsig; k++)
	{
		const dkim2_signature_t *s = sigs[k].sig;
		char *input;
		size_t inputlen;
		const dkim2_sigentry_t *e;
		int checked = 0;

		input = dkim2_build_input_85(mis, nmi, sigs, k, &inputlen);
		if (input == NULL)
			goto cleanup;

		for (e = s->sig_s; e != NULL; e = e->se_next)
		{
			dkim2_alg_t alg = dkim2_alg_from_name(e->se_alg);
			dkim2_dns_status_t st;
			dkim2_keyrecord_t *kr;
			EVP_PKEY *pub;
			int vr;

			if (alg == DKIM2_ALG_UNKNOWN)
				continue;	/* 3.4: ignore unknown algorithms */

			kr = dkim2_dns_getkey(e->se_selector, s->sig_d, &st);
			if (kr == NULL)
			{
				dkim2_vstate_t state =
				    (st == DKIM2_DNS_TEMPFAIL) ? DKIM2_V_TEMPERROR
				                               : DKIM2_V_PERMERROR;

				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu public key %s %s",
				    (unsigned long long) s->sig_i, e->se_selector,
				    st == DKIM2_DNS_TEMPFAIL ? "could not be fetched"
				    : st == DKIM2_DNS_BADKEY ? "has a syntax error"
				                             : "does not exist");
				free(input);
				rc = dkim2_result(out, state, s->sig_i, msg);
				goto cleanup;
			}

			if (kr->kr_p[0] == '\0')
			{
				dkim2_keyrecord_free(kr);
				free(input);
				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu public key %s has been revoked",
				    (unsigned long long) s->sig_i, e->se_selector);
				rc = dkim2_result(out, DKIM2_V_PERMERROR, s->sig_i, msg);
				goto cleanup;
			}
			if (!dkim2_keyalg_matches(kr->kr_alg, alg))
			{
				dkim2_keyrecord_free(kr);
				free(input);
				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu public key %s algorithm mismatch",
				    (unsigned long long) s->sig_i, e->se_selector);
				rc = dkim2_result(out, DKIM2_V_PERMERROR, s->sig_i, msg);
				goto cleanup;
			}

			pub = dkim2_pubkey_load(alg, kr->kr_p);
			dkim2_keyrecord_free(kr);
			if (pub == NULL)
			{
				free(input);
				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu public key %s has a syntax error",
				    (unsigned long long) s->sig_i, e->se_selector);
				rc = dkim2_result(out, DKIM2_V_PERMERROR, s->sig_i, msg);
				goto cleanup;
			}

			vr = dkim2_verify_data(alg, pub,
			    (const unsigned char *) input, inputlen, e->se_sig);
			EVP_PKEY_free(pub);

			if (vr != 1)
			{
				free(input);
				snprintf(msg, sizeof msg,
				    "DKIM2-Signature i=%llu public key %s incorrect signature",
				    (unsigned long long) s->sig_i, e->se_selector);
				rc = dkim2_result(out,
				    vr == 0 ? DKIM2_V_FAIL : DKIM2_V_PERMERROR,
				    s->sig_i, msg);
				goto cleanup;
			}
			checked++;
		}

		free(input);

		if (checked == 0)
		{
			snprintf(msg, sizeof msg,
			    "DKIM2-Signature i=%llu has no verifiable algorithm",
			    (unsigned long long) s->sig_i);
			rc = dkim2_result(out, DKIM2_V_PERMERROR, s->sig_i, msg);
			goto cleanup;
		}
	}

	/* 10.7: body and header hashes must match the highest Message-Instance. */
	if (dkim2_header_hash(headers, nheaders, hh) != 0 ||
	    dkim2_body_hash(body, bodylen, bh) != 0)
		goto cleanup;
	hh_b64 = NULL;
	bh_b64 = NULL;
	{
		size_t cap = 4 * ((sizeof hh + 2) / 3) + 1;

		hh_b64 = malloc(cap);
		bh_b64 = malloc(cap);
		if (hh_b64 == NULL || bh_b64 == NULL)
			goto cleanup;
		hh_b64[dkim_base64_encode(hh, sizeof hh, (u_char *) hh_b64, cap)] = '\0';
		bh_b64[dkim_base64_encode(bh, sizeof bh, (u_char *) bh_b64, cap)] = '\0';
	}

	top_mi = mis[nmi - 1].mi;
	for (he = top_mi->mi_h; he != NULL; he = he->he_next)
	{
		if (strcmp(he->he_name, "sha256") != 0)
			continue;
		if (strcmp(he->he_header, hh_b64) != 0)
		{
			rc = dkim2_result(out, DKIM2_V_FAIL, top_mi->mi_m,
			    "header hash did not match");
			goto cleanup;
		}
		if (strcmp(he->he_body, bh_b64) != 0)
		{
			rc = dkim2_result(out, DKIM2_V_FAIL, top_mi->mi_m,
			    "body hash did not match");
			goto cleanup;
		}
		break;
	}
	if (he == NULL)
	{
		rc = dkim2_result(out, DKIM2_V_PERMERROR, top_mi->mi_m,
		    "Message-Instance has no sha256 hash");
		goto cleanup;
	}

	rc = dkim2_result(out, DKIM2_V_PASS, sigs[nsig - 1].sig->sig_i, NULL);

  cleanup:
	free(hh_b64);
	free(bh_b64);
	for (i = 0; i < nmi; i++)
		dkim2_mi_free(mis[i].mi);
	for (i = 0; i < nsig; i++)
		dkim2_signature_free(sigs[i].sig);
	free(mis);
	free(sigs);
	return rc;
}
