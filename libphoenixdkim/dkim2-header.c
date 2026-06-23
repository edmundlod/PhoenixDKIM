/*
**  dkim2-header.c -- DKIM2-Signature / Message-Instance header model.
**  See dkim2-header.h.
*/

#include "dkim2-header.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libphoenixdkim includes */
#include "dkim2-tags.h"

/* ── small helpers ───────────────────────────────────────────────────────── */

static int
dkim2_is_wsp(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Duplicate s[0..len) with leading/trailing WSP trimmed (NULL on OOM). */
static char *
dkim2_dup_trim(const char *s, size_t len)
{
	char *out;

	while (len > 0 && dkim2_is_wsp(s[0]))
	{
		s++;
		len--;
	}
	while (len > 0 && dkim2_is_wsp(s[len - 1]))
		len--;

	out = malloc(len + 1);
	if (out == NULL)
		return NULL;
	memcpy(out, s, len);
	out[len] = '\0';

	return out;
}

/*
**  DKIM2_PARSE_U64 -- parse a non-empty run of ASCII digits into a uint64_t.
**  Rejects empty input, non-digits, and overflow.  Returns 0 / -1.
*/
static int
dkim2_parse_u64(const char *s, uint64_t *out)
{
	uint64_t v = 0;

	if (s == NULL || *s == '\0')
		return -1;

	for (; *s != '\0'; s++)
	{
		unsigned d;

		if (*s < '0' || *s > '9')
			return -1;
		d = (unsigned) (*s - '0');
		if (v > (UINT64_MAX - d) / 10)
			return -1;	/* overflow */
		v = v * 10 + d;
	}

	*out = v;
	return 0;
}

/*
**  DKIM2_SPLIT -- split s on delimiter `delim` into a NULL-terminated array of
**  trimmed, heap-allocated strings.  *count receives the element count.  Returns
**  NULL on OOM.  An empty string yields a single empty element.
*/
static char **
dkim2_split(const char *s, char delim, size_t *count)
{
	char **out = NULL;
	size_t n = 0;
	const char *start = s;
	const char *p;

	for (p = s; ; p++)
	{
		if (*p == delim || *p == '\0')
		{
			char **grown = realloc(out, (n + 1) * sizeof *out);
			char *piece;

			if (grown == NULL)
				goto fail;
			out = grown;

			piece = dkim2_dup_trim(start, (size_t) (p - start));
			if (piece == NULL)
				goto fail;
			out[n++] = piece;

			if (*p == '\0')
				break;
			start = p + 1;
		}
	}

	*count = n;
	return out;

  fail:
	while (n > 0)
		free(out[--n]);
	free(out);
	return NULL;
}

static void
dkim2_free_array(char **a, size_t n)
{
	size_t i;

	if (a == NULL)
		return;
	for (i = 0; i < n; i++)
		free(a[i]);
	free(a);
}

/* ── DKIM2-Signature ─────────────────────────────────────────────────────── */

static dkim2_sigentry_t *
dkim2_sigentry_parse(const char *s)
{
	dkim2_sigentry_t *head = NULL;
	dkim2_sigentry_t *tail = NULL;
	char **sets;
	size_t nsets = 0;
	size_t i;

	sets = dkim2_split(s, ',', &nsets);
	if (sets == NULL)
		return NULL;

	for (i = 0; i < nsets; i++)
	{
		char **parts;
		size_t nparts = 0;
		dkim2_sigentry_t *e;

		/* selector ":" algorithm ":" signature */
		parts = dkim2_split(sets[i], ':', &nparts);
		if (parts == NULL || nparts != 3)
		{
			dkim2_free_array(parts, nparts);
			goto fail;
		}

		e = calloc(1, sizeof *e);
		if (e == NULL)
		{
			dkim2_free_array(parts, nparts);
			goto fail;
		}
		e->se_selector = parts[0];
		e->se_alg = parts[1];
		e->se_sig = parts[2];
		free(parts);	/* the three strings are now owned by e */

		if (tail == NULL)
			head = e;
		else
			tail->se_next = e;
		tail = e;
	}

	dkim2_free_array(sets, nsets);
	if (head == NULL)
		return NULL;	/* an s= tag with no entries is malformed */
	return head;

  fail:
	dkim2_free_array(sets, nsets);
	while (head != NULL)
	{
		dkim2_sigentry_t *next = head->se_next;

		free(head->se_selector);
		free(head->se_alg);
		free(head->se_sig);
		free(head);
		head = next;
	}
	return NULL;
}

dkim2_signature_t *
dkim2_signature_parse(const char *value, size_t len)
{
	dkim2_taglist_t *tl;
	dkim2_signature_t *sig;
	const char *v;

	tl = dkim2_taglist_parse(value, len);
	if (tl == NULL)
		return NULL;

	sig = calloc(1, sizeof *sig);
	if (sig == NULL)
	{
		dkim2_taglist_free(tl);
		return NULL;
	}

	/* required numeric tags */
	if (dkim2_parse_u64(dkim2_taglist_get(tl, "i"), &sig->sig_i) != 0 ||
	    dkim2_parse_u64(dkim2_taglist_get(tl, "m"), &sig->sig_m) != 0 ||
	    dkim2_parse_u64(dkim2_taglist_get(tl, "t"), &sig->sig_t) != 0)
		goto fail;

	/* required string tags */
	v = dkim2_taglist_get(tl, "mf");
	if (v == NULL)
		goto fail;
	sig->sig_mf = strdup(v);

	v = dkim2_taglist_get(tl, "d");
	if (v == NULL)
		goto fail;
	sig->sig_d = strdup(v);

	v = dkim2_taglist_get(tl, "rt");
	if (v == NULL)
		goto fail;
	sig->sig_rt = dkim2_split(v, ',', &sig->sig_rt_count);

	v = dkim2_taglist_get(tl, "s");
	if (v == NULL)
		goto fail;
	sig->sig_s = dkim2_sigentry_parse(v);

	if (sig->sig_mf == NULL || sig->sig_d == NULL ||
	    sig->sig_rt == NULL || sig->sig_s == NULL)
		goto fail;

	/* optional tags */
	v = dkim2_taglist_get(tl, "n");
	if (v != NULL && (sig->sig_n = strdup(v)) == NULL)
		goto fail;
	v = dkim2_taglist_get(tl, "f");
	if (v != NULL && (sig->sig_f = strdup(v)) == NULL)
		goto fail;

	dkim2_taglist_free(tl);
	return sig;

  fail:
	dkim2_taglist_free(tl);
	dkim2_signature_free(sig);
	return NULL;
}

char *
dkim2_signature_format(const dkim2_signature_t *sig)
{
	char *buf = NULL;
	size_t buflen = 0;
	FILE *f;
	const dkim2_sigentry_t *e;
	size_t i;

	if (sig == NULL)
		return NULL;

	f = open_memstream(&buf, &buflen);
	if (f == NULL)
		return NULL;

	fprintf(f, "i=%llu; m=%llu; t=%llu; mf=%s; rt=",
	        (unsigned long long) sig->sig_i,
	        (unsigned long long) sig->sig_m,
	        (unsigned long long) sig->sig_t,
	        sig->sig_mf ? sig->sig_mf : "");

	for (i = 0; i < sig->sig_rt_count; i++)
		fprintf(f, "%s%s", i ? "," : "", sig->sig_rt[i]);

	fprintf(f, "; d=%s; s=", sig->sig_d ? sig->sig_d : "");

	for (e = sig->sig_s; e != NULL; e = e->se_next)
	{
		fprintf(f, "%s%s:%s:%s", e == sig->sig_s ? "" : ",",
		        e->se_selector, e->se_alg, e->se_sig);
	}

	fputc(';', f);

	if (sig->sig_n != NULL)
		fprintf(f, " n=%s;", sig->sig_n);
	if (sig->sig_f != NULL)
		fprintf(f, " f=%s;", sig->sig_f);

	if (fclose(f) != 0)
	{
		free(buf);
		return NULL;
	}

	return buf;
}

void
dkim2_signature_free(dkim2_signature_t *sig)
{
	dkim2_sigentry_t *e;

	if (sig == NULL)
		return;

	free(sig->sig_mf);
	dkim2_free_array(sig->sig_rt, sig->sig_rt_count);
	free(sig->sig_d);
	free(sig->sig_n);
	free(sig->sig_f);

	e = sig->sig_s;
	while (e != NULL)
	{
		dkim2_sigentry_t *next = e->se_next;

		free(e->se_selector);
		free(e->se_alg);
		free(e->se_sig);
		free(e);
		e = next;
	}

	free(sig);
}

/* ── Message-Instance ────────────────────────────────────────────────────── */

static dkim2_hashentry_t *
dkim2_hashentry_parse(const char *s)
{
	dkim2_hashentry_t *head = NULL;
	dkim2_hashentry_t *tail = NULL;
	char **sets;
	size_t nsets = 0;
	size_t i;

	sets = dkim2_split(s, ',', &nsets);
	if (sets == NULL)
		return NULL;

	for (i = 0; i < nsets; i++)
	{
		char **parts;
		size_t nparts = 0;
		dkim2_hashentry_t *e;

		/* name ":" header-hash ":" body-hash */
		parts = dkim2_split(sets[i], ':', &nparts);
		if (parts == NULL || nparts != 3)
		{
			dkim2_free_array(parts, nparts);
			goto fail;
		}

		e = calloc(1, sizeof *e);
		if (e == NULL)
		{
			dkim2_free_array(parts, nparts);
			goto fail;
		}
		e->he_name = parts[0];
		e->he_header = parts[1];
		e->he_body = parts[2];
		free(parts);

		if (tail == NULL)
			head = e;
		else
			tail->he_next = e;
		tail = e;
	}

	dkim2_free_array(sets, nsets);
	if (head == NULL)
		return NULL;
	return head;

  fail:
	dkim2_free_array(sets, nsets);
	while (head != NULL)
	{
		dkim2_hashentry_t *next = head->he_next;

		free(head->he_name);
		free(head->he_header);
		free(head->he_body);
		free(head);
		head = next;
	}
	return NULL;
}

dkim2_mi_t *
dkim2_mi_parse(const char *value, size_t len)
{
	dkim2_taglist_t *tl;
	dkim2_mi_t *mi;
	const char *v;

	tl = dkim2_taglist_parse(value, len);
	if (tl == NULL)
		return NULL;

	mi = calloc(1, sizeof *mi);
	if (mi == NULL)
	{
		dkim2_taglist_free(tl);
		return NULL;
	}

	if (dkim2_parse_u64(dkim2_taglist_get(tl, "m"), &mi->mi_m) != 0)
		goto fail;

	v = dkim2_taglist_get(tl, "h");
	if (v == NULL)
		goto fail;
	mi->mi_h = dkim2_hashentry_parse(v);
	if (mi->mi_h == NULL)
		goto fail;

	v = dkim2_taglist_get(tl, "r");
	if (v != NULL && (mi->mi_r = strdup(v)) == NULL)
		goto fail;

	dkim2_taglist_free(tl);
	return mi;

  fail:
	dkim2_taglist_free(tl);
	dkim2_mi_free(mi);
	return NULL;
}

char *
dkim2_mi_format(const dkim2_mi_t *mi)
{
	char *buf = NULL;
	size_t buflen = 0;
	FILE *f;
	const dkim2_hashentry_t *e;

	if (mi == NULL)
		return NULL;

	f = open_memstream(&buf, &buflen);
	if (f == NULL)
		return NULL;

	fprintf(f, "m=%llu; h=", (unsigned long long) mi->mi_m);

	for (e = mi->mi_h; e != NULL; e = e->he_next)
	{
		fprintf(f, "%s%s:%s:%s", e == mi->mi_h ? "" : ",",
		        e->he_name, e->he_header, e->he_body);
	}

	fputc(';', f);

	if (mi->mi_r != NULL)
		fprintf(f, " r=%s;", mi->mi_r);

	if (fclose(f) != 0)
	{
		free(buf);
		return NULL;
	}

	return buf;
}

void
dkim2_mi_free(dkim2_mi_t *mi)
{
	dkim2_hashentry_t *e;

	if (mi == NULL)
		return;

	free(mi->mi_r);

	e = mi->mi_h;
	while (e != NULL)
	{
		dkim2_hashentry_t *next = e->he_next;

		free(e->he_name);
		free(e->he_header);
		free(e->he_body);
		free(e);
		e = next;
	}

	free(mi);
}
