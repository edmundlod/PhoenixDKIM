/*
**  dkim2-sign.c -- DKIM2-core signing.  See dkim2-sign.h.
*/

#include "dkim2-sign.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* libphoenixdkim includes */
#include "base64.h"
#include "dkim2-hash.h"
#include "dkim2-header.h"
#include "dkim2-recipe.h"

/* ── Section 8.5 field canonicalization ──────────────────────────────────── */

char *
dkim2_canon_field_85(const char *field)
{
	const char *colon;
	size_t namelen;
	size_t i;
	char *out;
	size_t outlen;

	if (field == NULL)
		return NULL;
	colon = strchr(field, ':');
	if (colon == NULL)
		return NULL;

	namelen = (size_t) (colon - field);

	/* name (lowercased) + ':' + value-with-no-WSP + CRLF + NUL */
	out = malloc(namelen + 1 + strlen(colon + 1) + 2 + 1);
	if (out == NULL)
		return NULL;

	outlen = 0;
	for (i = 0; i < namelen; i++)
		out[outlen++] = (char) tolower((unsigned char) field[i]);
	out[outlen++] = ':';

	/* delete every WSP/CR/LF from the value */
	for (colon++; *colon != '\0'; colon++)
	{
		char c = *colon;

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			continue;
		out[outlen++] = c;
	}

	out[outlen++] = '\r';
	out[outlen++] = '\n';
	out[outlen] = '\0';

	return out;
}

/* ── small builders ──────────────────────────────────────────────────────── */

/* base64 a byte buffer into a fresh string (NULL on OOM/error).  The bytes are
** copied into a non-const scratch buffer first, since the project base64 codec
** takes a writable pointer and we must not cast away the caller's const. */
static char *
dkim2_b64_bytes(const unsigned char *data, size_t len)
{
	size_t cap = 4 * ((len + 2) / 3) + 1;
	unsigned char *tmp = malloc(len > 0 ? len : 1);
	char *out;
	int n;

	if (tmp == NULL)
		return NULL;
	memcpy(tmp, data, len);

	out = malloc(cap);
	if (out == NULL)
	{
		free(tmp);
		return NULL;
	}
	n = dkim_base64_encode(tmp, len, (u_char *) out, cap);
	free(tmp);
	if (n < 0)
	{
		free(out);
		return NULL;
	}
	out[(size_t) n] = '\0';
	return out;
}

/* base64 a C string. */
static char *
dkim2_b64_str(const char *s)
{
	return dkim2_b64_bytes((const unsigned char *) s, strlen(s));
}

/* Build a DKIM2-Signature value; sig_b64 == "" yields the incomplete form.
** flags, when non-NULL and non-empty, appends an f= tag; it is part of the
** signed bytes, so it must be identical in the incomplete and complete forms. */
static char *
dkim2_build_sig_value(uint64_t i, uint64_t m, uint64_t t,
                      const char *mf_b64, char *const *rt_b64, size_t rt_count,
                      const char *domain, const char *selector,
                      const char *alg, const char *sig_b64,
                      const char *nonce, const char *flags)
{
	char *buf = NULL;
	size_t buflen = 0;
	FILE *f = open_memstream(&buf, &buflen);
	size_t k;

	if (f == NULL)
		return NULL;

	fprintf(f, "i=%llu; m=%llu; t=%llu; mf=%s; rt=",
	        (unsigned long long) i, (unsigned long long) m,
	        (unsigned long long) t, mf_b64);
	for (k = 0; k < rt_count; k++)
		fprintf(f, "%s%s", k ? "," : "", rt_b64[k]);
	fprintf(f, "; d=%s; s=%s:%s:%s;", domain, selector, alg, sig_b64);
	if (nonce != NULL && nonce[0] != '\0')
		fprintf(f, " n=%s;", nonce);
	if (flags != NULL && flags[0] != '\0')
		fprintf(f, " f=%s;", flags);

	if (fclose(f) != 0)
	{
		free(buf);
		return NULL;
	}
	return buf;
}

/* ── existing-chain inspection ───────────────────────────────────────────── */

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

/* An existing chain field plus its ordering key (m= for MI, i= for sigs). */
struct dkim2_chain_field
{
	const char	*cf_field;
	uint64_t	 cf_key;
};

static int
dkim2_chain_cmp(const void *a, const void *b)
{
	uint64_t ka = ((const struct dkim2_chain_field *) a)->cf_key;
	uint64_t kb = ((const struct dkim2_chain_field *) b)->cf_key;

	if (ka != kb)
		return ka < kb ? -1 : 1;
	return 0;
}

/* ── signing ─────────────────────────────────────────────────────────────── */

int
dkim2_sign(const dkim2_sign_params_t *p,
           const char *const *headers, size_t nheaders,
           const char *body, size_t bodylen,
           char **mi_out, char **sig_out)
{
	const char *algname;
	struct dkim2_chain_field *mis = NULL;
	struct dkim2_chain_field *sigs = NULL;
	size_t nmi = 0, nsig = 0;
	size_t idx;
	uint64_t next_i = 1, ref_m = 1;
	int originator;
	int modifying;
	char *mi_value = NULL;
	char *mf_b64 = NULL;
	char **rt_b64 = NULL;
	size_t rt_n = 0;
	char *incomplete = NULL, *complete = NULL;
	char *input = NULL;
	size_t inputlen = 0;
	char *sigval = NULL;
	uint64_t t;
	int rc = -1;

	if (p == NULL || sig_out == NULL || p->sp_key == NULL)
		return -1;
	algname = dkim2_alg_name(p->sp_alg);
	if (algname == NULL)
		return -1;
	/* Section 7.3: refuse to emit an out-of-spec nonce. */
	if (p->sp_nonce != NULL && !dkim2_nonce_valid(p->sp_nonce))
		return -1;
	if (mi_out != NULL)
		*mi_out = NULL;

	/* Collect any existing Message-Instance and DKIM2-Signature fields and
	** their ordering keys. */
	mis = calloc(nheaders ? nheaders : 1, sizeof *mis);
	sigs = calloc(nheaders ? nheaders : 1, sizeof *sigs);
	if (mis == NULL || sigs == NULL)
		goto done;

	for (idx = 0; idx < nheaders; idx++)
	{
		const char *field = headers[idx];
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
				goto done;	/* broken chain: refuse to sign */
			mis[nmi].cf_field = field;
			mis[nmi].cf_key = mi->mi_m;
			nmi++;
			dkim2_mi_free(mi);
		}
		else if (dkim2_field_name_is(field, "dkim2-signature"))
		{
			dkim2_signature_t *s =
			    dkim2_signature_parse(value, strlen(value));

			if (s == NULL)
				goto done;
			sigs[nsig].cf_field = field;
			sigs[nsig].cf_key = s->sig_i;
			if (s->sig_i + 1 > next_i)
				next_i = s->sig_i + 1;
			dkim2_signature_free(s);
			nsig++;
		}
	}

	originator = (nsig == 0);
	/* A re-signer that supplies a pre-modification message or an explicit
	** recipe is recording a reversible modification: it adds a new
	** Message-Instance.  Without either it is a plain core re-sign. */
	modifying = (!originator &&
	    (p->sp_orig_headers != NULL || p->sp_recipe != NULL));

	qsort(mis, nmi, sizeof *mis, dkim2_chain_cmp);
	qsort(sigs, nsig, sizeof *sigs, dkim2_chain_cmp);

	/* The originator adds Message-Instance m=1; a modifying re-signer adds the
	** next instance with the current hashes and a recipe reverting to the
	** previous one; a plain re-signer references the top instance and adds no
	** MI. */
	if (originator || modifying)
	{
		unsigned char hh[DKIM2_HASH_LEN], bh[DKIM2_HASH_LEN];
		char *hh_b64 = NULL, *bh_b64 = NULL;
		uint64_t newm = (originator || nmi == 0) ? 1
		                                         : mis[nmi - 1].cf_key + 1;

		if (dkim2_header_hash(headers, nheaders, hh) != 0 ||
		    dkim2_body_hash(body, bodylen, bh) != 0)
			goto done;
		hh_b64 = dkim2_b64_bytes(hh, sizeof hh);
		bh_b64 = dkim2_b64_bytes(bh, sizeof bh);
		if (hh_b64 == NULL || bh_b64 == NULL)
		{
			free(hh_b64);
			free(bh_b64);
			goto done;
		}

		ref_m = newm;
		if (modifying)
		{
			char *recipe_b64 = NULL;

			if (p->sp_recipe != NULL)
				recipe_b64 = strdup(p->sp_recipe);
			else
			{
				dkim2_recipe_t *rg = dkim2_recipe_generate(
				    p->sp_orig_headers, p->sp_orig_nheaders,
				    p->sp_orig_body, p->sp_orig_bodylen,
				    headers, nheaders, body, bodylen);

				if (rg != NULL)
				{
					recipe_b64 = dkim2_recipe_format(rg);
					dkim2_recipe_free(rg);
				}
			}
			if (recipe_b64 == NULL)
			{
				free(hh_b64);
				free(bh_b64);
				goto done;
			}
			if (asprintf(&mi_value, "m=%llu; h=sha256:%s:%s; r=%s;",
			             (unsigned long long) newm, hh_b64, bh_b64,
			             recipe_b64) < 0)
				mi_value = NULL;
			free(recipe_b64);
		}
		else if (asprintf(&mi_value, "m=%llu; h=sha256:%s:%s;",
		                  (unsigned long long) newm, hh_b64, bh_b64) < 0)
			mi_value = NULL;
		free(hh_b64);
		free(bh_b64);
		if (mi_value == NULL)
			goto done;
	}
	else
	{
		ref_m = nmi > 0 ? mis[nmi - 1].cf_key : 0;
	}

	/* Encode the SMTP envelope. */
	mf_b64 = dkim2_b64_str(p->sp_mf != NULL ? p->sp_mf : "<>");
	if (mf_b64 == NULL)
		goto done;
	rt_b64 = calloc(p->sp_rt_count ? p->sp_rt_count : 1, sizeof *rt_b64);
	if (rt_b64 == NULL)
		goto done;
	for (rt_n = 0; rt_n < p->sp_rt_count; rt_n++)
	{
		rt_b64[rt_n] = dkim2_b64_str(p->sp_rt[rt_n]);
		if (rt_b64[rt_n] == NULL)
			goto done;
	}

	t = p->sp_t != 0 ? p->sp_t : (uint64_t) time(NULL);

	/* Incomplete DKIM2-Signature (empty s= signature). */
	incomplete = dkim2_build_sig_value(next_i, ref_m, t, mf_b64,
	                                   rt_b64, rt_n, p->sp_domain,
	                                   p->sp_selector, algname, "",
	                                   p->sp_nonce, p->sp_flags);
	if (incomplete == NULL)
		goto done;

	/* Assemble the Section 8.5 signing input: MI fields (ascending m), then
	** existing DKIM2-Signature fields (ascending i), then the incomplete one,
	** each canonicalized. */
	{
		FILE *f = open_memstream(&input, &inputlen);
		size_t k;
		int ferr = 0;

		if (f == NULL)
			goto done;

#define EMIT_CANON(FIELD)                                          \
		do {                                                       \
			char *_c = dkim2_canon_field_85(FIELD);                \
			if (_c == NULL) { ferr = 1; }                          \
			else { fwrite(_c, 1, strlen(_c), f); free(_c); }       \
		} while (0)

		if (!originator)
		{
			for (k = 0; k < nmi; k++)
				EMIT_CANON(mis[k].cf_field);
		}
		if (originator || modifying)
		{
			char *mi_field = NULL;

			if (asprintf(&mi_field, "Message-Instance: %s",
			             mi_value) < 0)
				ferr = 1;
			else
			{
				EMIT_CANON(mi_field);
				free(mi_field);
			}
		}

		for (k = 0; k < nsig && !ferr; k++)
			EMIT_CANON(sigs[k].cf_field);

		if (!ferr)
		{
			char *inc_field = NULL;

			if (asprintf(&inc_field, "DKIM2-Signature: %s",
			             incomplete) < 0)
				ferr = 1;
			else
			{
				EMIT_CANON(inc_field);
				free(inc_field);
			}
		}
#undef EMIT_CANON

		if (fclose(f) != 0 || ferr)
			goto done;
	}

	/* Sign and splice the signature into s=. */
	sigval = dkim2_sign_data(p->sp_alg, p->sp_key,
	                         (const unsigned char *) input, inputlen);
	if (sigval == NULL)
		goto done;

	complete = dkim2_build_sig_value(next_i, ref_m, t, mf_b64,
	                                 rt_b64, rt_n, p->sp_domain,
	                                 p->sp_selector, algname, sigval,
	                                 p->sp_nonce, p->sp_flags);
	if (complete == NULL)
		goto done;

	if (asprintf(sig_out, "DKIM2-Signature: %s", complete) < 0)
	{
		*sig_out = NULL;
		goto done;
	}
	if ((originator || modifying) && mi_out != NULL)
	{
		if (asprintf(mi_out, "Message-Instance: %s", mi_value) < 0)
		{
			*mi_out = NULL;
			free(*sig_out);
			*sig_out = NULL;
			goto done;
		}
	}

	rc = 0;

  done:
	for (idx = 0; idx < rt_n; idx++)
		free(rt_b64[idx]);
	free(rt_b64);
	free(mf_b64);
	free(mi_value);
	free(incomplete);
	free(complete);
	free(sigval);
	free(input);
	free(mis);
	free(sigs);
	return rc;
}
