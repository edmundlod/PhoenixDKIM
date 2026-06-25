/*
**  dkim2-hash.c -- DKIM2 body and header field hashing.  See dkim2-hash.h.
*/

#include "dkim2-hash.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/evp.h>
#include "openssl-compat.h"

/* ── SHA-256 helpers ─────────────────────────────────────────────────────── */

/*
**  DKIM2_SHA256_* -- thin wrappers around the OpenSSL 3 EVP digest API, matching
**  the streaming idiom used elsewhere in the library (dkim-canon.c).
*/

static EVP_MD_CTX *
dkim2_sha256_new(void)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	if (ctx == NULL)
		return NULL;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
	{
		EVP_MD_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

static int
dkim2_sha256_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
	if (len == 0)
		return 0;
	return EVP_DigestUpdate(ctx, data, len) == 1 ? 0 : -1;
}

static int
dkim2_sha256_final(EVP_MD_CTX *ctx, unsigned char digest[DKIM2_HASH_LEN])
{
	int ok = EVP_DigestFinal_ex(ctx, digest, NULL) == 1;

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -1;
}

/* ── Body hash (Section 5.1) ─────────────────────────────────────────────── */

int
dkim2_body_hash(const char *body, size_t bodylen,
                unsigned char digest[DKIM2_HASH_LEN])
{
	EVP_MD_CTX *ctx;
	size_t n;

	if (body == NULL)
		bodylen = 0;

	/* DKIM1 "simple": strip every trailing CRLF, then add exactly one back.
	** This collapses "*CRLF" at the end (including a body with no terminator)
	** to a single CRLF, while leaving interior empty lines untouched. */
	n = bodylen;
	while (n >= 2 && body[n - 2] == '\r' && body[n - 1] == '\n')
		n -= 2;

	ctx = dkim2_sha256_new();
	if (ctx == NULL)
		return -1;

	if (dkim2_sha256_update(ctx, body, n) != 0 ||
	    dkim2_sha256_update(ctx, "\r\n", 2) != 0)
	{
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	return dkim2_sha256_final(ctx, digest);
}

/* Normalize a body to canonical CRLF line endings (see dkim2-hash.h).  Operates
** on a complete buffer, so a CRLF that an MTA split across two milter chunks --
** which the caller has already concatenated -- is rejoined correctly. */
int
dkim2_body_to_crlf(const char *in, size_t inlen, char **out, size_t *outlen)
{
	char *o;
	size_t i, j = 0;

	/* Worst case is every input octet being a lone CR or LF, each of which
	** expands to two octets. */
	o = malloc(inlen * 2 + 1);
	if (o == NULL)
		return -1;

	for (i = 0; i < inlen; i++)
	{
		if (in[i] == '\r')
		{
			o[j++] = '\r';
			o[j++] = '\n';
			if (i + 1 < inlen && in[i + 1] == '\n')
				i++;		/* CRLF: consume the LF */
		}
		else if (in[i] == '\n')
		{
			o[j++] = '\r';		/* lone LF -> CRLF */
			o[j++] = '\n';
		}
		else
			o[j++] = in[i];
	}

	o[j] = '\0';
	*out = o;
	*outlen = j;
	return 0;
}

/* ── Header field canonicalization (Section 5.2) ─────────────────────────── */

int
dkim2_header_is_signed(const char *name)
{
	if (name == NULL)
		return 0;

	/* Prefix matches: proprietary trace fields and other signature chains. */
	if (strncasecmp(name, "x-", 2) == 0 ||
	    strncasecmp(name, "arc-", 4) == 0)
		return 0;

	/* Exact matches: trace headers, intra-ADMD results, and the DKIM/DKIM2
	** structures that are either signed separately or covered directly. */
	if (strcasecmp(name, "received") == 0 ||
	    strcasecmp(name, "return-path") == 0 ||
	    strcasecmp(name, "delivered-to") == 0 ||
	    strcasecmp(name, "authentication-results") == 0 ||
	    strcasecmp(name, "dkim-signature") == 0 ||
	    strcasecmp(name, "message-instance") == 0 ||
	    strcasecmp(name, "dkim2-signature") == 0)
		return 0;

	return 1;
}

static int
dkim2_is_wsp(char c)
{
	return c == ' ' || c == '\t';
}

/*
**  DKIM2_CANON_HEADER -- canonicalize one header field per Section 5.2.
**
**  Produces "<lowercase-name>:<canonical-value>\r\n" in a freshly allocated
**  buffer.  Returns NULL if the field has no colon or is on the ignore list,
**  with *ignored set accordingly so the caller can tell "drop" from "error".
**  The caller recovers the name length from the position of the ':'.
*/
static char *
dkim2_canon_header(const char *h, int *ignored)
{
	const char *colon;
	const char *vp;
	size_t namelen;
	size_t i;
	size_t hlen;
	char *name;
	char *out;
	size_t outlen;
	int pending_space;

	*ignored = 0;

	colon = strchr(h, ':');
	if (colon == NULL)
	{
		/* malformed: no name/value separator */
		*ignored = 1;
		return NULL;
	}

	namelen = (size_t) (colon - h);

	/* Lowercase a copy of the name for the ignore test and for sorting. */
	name = malloc(namelen + 1);
	if (name == NULL)
		return NULL;
	for (i = 0; i < namelen; i++)
		name[i] = (char) tolower((unsigned char) h[i]);
	name[namelen] = '\0';

	if (!dkim2_header_is_signed(name))
	{
		free(name);
		*ignored = 1;
		return NULL;
	}

	/* Worst case the value is unchanged in length; allocate name + ':' + value
	** + CRLF + NUL. */
	hlen = strlen(h);
	out = malloc(namelen + 1 + hlen + 2 + 1);
	if (out == NULL)
	{
		free(name);
		return NULL;
	}

	memcpy(out, name, namelen);
	out[namelen] = ':';
	outlen = namelen + 1;
	free(name);

	/* Canonicalize the value: unfold (delete CRLF that introduces a folded
	** continuation), collapse WSP runs -- including those around a fold -- to a
	** single SP, and trim leading and trailing WSP. */
	vp = colon + 1;
	pending_space = 0;
	for (i = 0; vp[i] != '\0'; i++)
	{
		char c = vp[i];

		if (c == '\r' && vp[i + 1] == '\n')
		{
			/* fold (or stray CRLF): delete it; following WSP, if any,
			** sets pending_space and collapses naturally */
			i++;
			continue;
		}
		if (dkim2_is_wsp(c))
		{
			pending_space = 1;
			continue;
		}
		if (c == '\r' || c == '\n')
			continue;	/* stray bare CR/LF: delete */

		if (pending_space && outlen > namelen + 1)
			out[outlen++] = ' ';
		pending_space = 0;
		out[outlen++] = c;
	}

	out[outlen++] = '\r';
	out[outlen++] = '\n';
	out[outlen] = '\0';

	return out;
}

/* A canonicalized header field plus its sort key. */
struct dkim2_canon_hdr
{
	char	*line;		/* "name:value\r\n" */
	size_t	 namelen;	/* bytes of name before the ':' */
	size_t	 idx;		/* original position, for the same-name tiebreak */
};

static int
dkim2_canon_cmp(const void *pa, const void *pb)
{
	const struct dkim2_canon_hdr *a = pa;
	const struct dkim2_canon_hdr *b = pb;
	size_t na = a->namelen < b->namelen ? a->namelen : b->namelen;
	int r = memcmp(a->line, b->line, na);

	if (r != 0)
		return r;
	if (a->namelen != b->namelen)
		return a->namelen < b->namelen ? -1 : 1;

	/* Same field name: keep "bottom up" (last occurrence first), i.e. higher
	** original index sorts earlier. */
	if (a->idx != b->idx)
		return a->idx > b->idx ? -1 : 1;
	return 0;
}

int
dkim2_header_hash(const char *const *headers, size_t nheaders,
                  unsigned char digest[DKIM2_HASH_LEN])
{
	struct dkim2_canon_hdr *canon;
	size_t ncanon = 0;
	size_t i;
	EVP_MD_CTX *ctx;
	int rc = -1;

	canon = calloc(nheaders ? nheaders : 1, sizeof *canon);
	if (canon == NULL)
		return -1;

	for (i = 0; i < nheaders; i++)
	{
		int ignored;
		char *line;

		if (headers[i] == NULL)
			continue;

		line = dkim2_canon_header(headers[i], &ignored);
		if (line == NULL)
		{
			if (ignored)
				continue;
			goto done;	/* allocation failure */
		}

		canon[ncanon].line = line;
		canon[ncanon].namelen = (size_t) (strchr(line, ':') - line);
		canon[ncanon].idx = i;
		ncanon++;
	}

	qsort(canon, ncanon, sizeof *canon, dkim2_canon_cmp);

	ctx = dkim2_sha256_new();
	if (ctx == NULL)
		goto done;

	for (i = 0; i < ncanon; i++)
	{
		if (dkim2_sha256_update(ctx, canon[i].line,
		                        strlen(canon[i].line)) != 0)
		{
			EVP_MD_CTX_free(ctx);
			goto done;
		}
	}

	rc = dkim2_sha256_final(ctx, digest);

  done:
	for (i = 0; i < ncanon; i++)
		free(canon[i].line);
	free(canon);

	return rc;
}
