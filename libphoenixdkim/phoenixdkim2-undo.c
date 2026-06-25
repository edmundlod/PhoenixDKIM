/*
**  phoenixdkim2-undo.c -- reconstruct an earlier DKIM2 Message-Instance.
**
**  Reads a signed message on stdin and walks the Message-Instance recipes
**  backward, undoing each modifying hop to reconstruct the message as it stood
**  at an earlier instance, then writes that message to stdout.  It is the
**  inverse of the modifying re-sign path and mirrors the interop dkim2undo tool;
**  the recipe logic itself lives in dkim2-recipe.c.
**
**  Usage:
**    phoenixdkim2-undo [--target-version N] < signed.eml > earlier.eml
**
**  --target-version selects the instance to reconstruct back to: the default
**  (-1) undoes a single hop (highest - 1); 0 reconstructs the original
**  pre-signing message.  Output carries the DKIM2-Signature and Message-Instance
**  fields with m= <= target, the reconstructed content headers, and the body.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"
#include "dkim2-eml.h"
#include "dkim2-hash.h"
#include "dkim2-header.h"
#include "dkim2-recipe.h"

static char *
read_all(FILE *f, size_t *len)
{
	size_t cap = 65536, n = 0;
	char *buf = malloc(cap);
	size_t r;

	if (buf == NULL)
		return NULL;
	while ((r = fread(buf + n, 1, cap - n, f)) > 0)
	{
		n += r;
		if (n == cap)
		{
			char *grown = realloc(buf, cap *= 2);

			if (grown == NULL)
			{
				free(buf);
				return NULL;
			}
			buf = grown;
		}
	}
	*len = n;
	return buf;
}

/* Field name (before ':') equals name, case-insensitively. */
static int
field_is(const char *field, const char *name)
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

int
main(int argc, char **argv)
{
	long target = -1;
	int i;
	char *msg;
	size_t msglen;
	dkim2_eml_t *eml = NULL;
	char **content = NULL;		/* current content headers (owned copies) */
	size_t ncontent = 0;
	char *body = NULL;		/* current body (owned) */
	size_t bodylen = 0;
	uint64_t highest = 0;
	long v;
	int ret = 2;

	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--target-version") == 0 && i + 1 < argc)
			target = strtol(argv[++i], NULL, 10);
		else
		{
			fprintf(stderr, "usage: phoenixdkim2-undo [--target-version N] "
			        "< signed.eml\n");
			return 2;
		}
	}

	msg = read_all(stdin, &msglen);
	eml = msg != NULL ? dkim2_eml_parse(msg, msglen) : NULL;
	if (eml == NULL)
	{
		fprintf(stderr, "phoenixdkim2-undo: cannot parse message\n");
		free(msg);
		return 2;
	}

	/* Split into content headers (owned copies) and find the highest m=. */
	content = calloc(eml->em_nheaders != 0 ? eml->em_nheaders : 1,
	                 sizeof *content);
	if (content == NULL)
		goto done;
	for (i = 0; (size_t) i < eml->em_nheaders; i++)
	{
		const char *field = eml->em_headers[i];

		if (field_is(field, "message-instance"))
		{
			dkim2_mi_t *mi = dkim2_mi_parse(strchr(field, ':') + 1,
			    strlen(strchr(field, ':') + 1));

			if (mi != NULL)
			{
				if (mi->mi_m > highest)
					highest = mi->mi_m;
				dkim2_mi_free(mi);
			}
			continue;
		}
		if (field_is(field, "dkim2-signature"))
			continue;
		content[ncontent] = strdup(field);
		if (content[ncontent] == NULL)
			goto done;
		ncontent++;
	}

	if (highest == 0)
	{
		fprintf(stderr, "phoenixdkim2-undo: no Message-Instance to undo\n");
		ret = 1;
		goto done;
	}
	if (target < 0)
		target = (long) highest - 1;
	if (target >= (long) highest)
	{
		fprintf(stderr, "phoenixdkim2-undo: target %ld >= highest %llu, "
		        "nothing to undo\n", target, (unsigned long long) highest);
		ret = 1;
		goto done;
	}

	body = malloc(eml->em_bodylen != 0 ? eml->em_bodylen : 1);
	if (body == NULL)
		goto done;
	memcpy(body, eml->em_body, eml->em_bodylen);
	bodylen = eml->em_bodylen;

	/* Undo each hop from the highest instance down to target + 1. */
	for (v = (long) highest; v > target; v--)
	{
		dkim2_mi_t *mi = NULL;
		dkim2_recipe_t *rec;
		char **ph = NULL;
		size_t pnh = 0;
		char *pb = NULL;
		size_t pbl = 0;
		size_t j;
		int ar;

		for (j = 0; j < eml->em_nheaders; j++)
		{
			const char *field = eml->em_headers[j];
			dkim2_mi_t *m;

			if (!field_is(field, "message-instance"))
				continue;
			m = dkim2_mi_parse(strchr(field, ':') + 1,
			    strlen(strchr(field, ':') + 1));
			if (m != NULL && m->mi_m == (uint64_t) v)
			{
				mi = m;
				break;
			}
			dkim2_mi_free(m);
		}
		if (mi == NULL)
		{
			fprintf(stderr, "phoenixdkim2-undo: Message-Instance m=%ld "
			        "not found\n", v);
			ret = 1;
			goto done;
		}
		if (mi->mi_r == NULL)
		{
			/* No recipe: this hop modified nothing (e.g. the originator's
			** m=1); there is nothing to undo, so move down. */
			dkim2_mi_free(mi);
			continue;
		}
		rec = dkim2_recipe_parse(mi->mi_r, strlen(mi->mi_r));
		dkim2_mi_free(mi);
		if (rec == NULL)
		{
			fprintf(stderr, "phoenixdkim2-undo: Message-Instance m=%ld "
			        "recipe is malformed\n", v);
			ret = 1;
			goto done;
		}
		if (rec->re_body_null)
		{
			dkim2_recipe_free(rec);
			fprintf(stderr, "phoenixdkim2-undo: Message-Instance m=%ld "
			        "has an irreversible body\n", v);
			ret = 1;
			goto done;
		}

		ar = dkim2_recipe_apply(rec, (const char *const *) content,
		    ncontent, body, bodylen, &ph, &pnh, &pb, &pbl);
		dkim2_recipe_free(rec);
		if (ar != 0)
		{
			fprintf(stderr, "phoenixdkim2-undo: recipe at m=%ld does not "
			        "apply\n", v);
			ret = 1;
			goto done;
		}

		for (j = 0; j < ncontent; j++)
			free(content[j]);
		free(content);
		free(body);
		content = ph;
		ncontent = pnh;
		body = pb;
		bodylen = pbl;
	}

	/*
	**  Verify the reconstruction against the target instance's hashes (the
	**  cryptographic chain attests the MI hashes; this confirms our undo
	**  reproduced the content they cover).  target 0 is the pre-signing state,
	**  for which no Message-Instance exists, so there is nothing to check.
	*/
	if (target >= 1)
	{
		unsigned char hh[DKIM2_HASH_LEN], bh[DKIM2_HASH_LEN];
		char hh_b64[4 * ((DKIM2_HASH_LEN + 2) / 3) + 1];
		char bh_b64[4 * ((DKIM2_HASH_LEN + 2) / 3) + 1];
		int mismatch = 0;

		for (i = 0; (size_t) i < eml->em_nheaders; i++)
		{
			const char *field = eml->em_headers[i];
			const dkim2_hashentry_t *e;
			dkim2_mi_t *m;

			if (!field_is(field, "message-instance"))
				continue;
			m = dkim2_mi_parse(strchr(field, ':') + 1,
			    strlen(strchr(field, ':') + 1));
			if (m == NULL || m->mi_m != (uint64_t) target)
			{
				dkim2_mi_free(m);
				continue;
			}
			for (e = m->mi_h; e != NULL; e = e->he_next)
				if (strcmp(e->he_name, "sha256") == 0)
					break;
			if (e != NULL &&
			    dkim2_header_hash((const char *const *) content,
			                      ncontent, hh) == 0 &&
			    dkim2_body_hash(body, bodylen, bh) == 0)
			{
				hh_b64[dkim_base64_encode(hh, sizeof hh,
				    (u_char *) hh_b64, sizeof hh_b64)] = '\0';
				bh_b64[dkim_base64_encode(bh, sizeof bh,
				    (u_char *) bh_b64, sizeof bh_b64)] = '\0';
				mismatch = strcmp(e->he_header, hh_b64) != 0 ||
				           strcmp(e->he_body, bh_b64) != 0;
			}
			dkim2_mi_free(m);
			break;
		}
		if (mismatch)
		{
			fprintf(stderr, "phoenixdkim2-undo: reconstruction does not "
			        "match Message-Instance m=%ld hashes\n", target);
			ret = 1;
			goto done;
		}
	}

	/*
	**  Emit the surviving chain: DKIM2-Signature then Message-Instance fields
	**  with m= <= target, then the reconstructed content headers, a blank line,
	**  and the body.  (For target 0 the whole chain is dropped, leaving the
	**  original pre-signing message.)
	*/
	for (i = 0; (size_t) i < eml->em_nheaders; i++)
	{
		const char *field = eml->em_headers[i];
		dkim2_signature_t *s;

		if (!field_is(field, "dkim2-signature"))
			continue;
		s = dkim2_signature_parse(strchr(field, ':') + 1,
		    strlen(strchr(field, ':') + 1));
		if (s != NULL && s->sig_m <= (uint64_t) target)
			printf("%s\r\n", field);
		dkim2_signature_free(s);
	}
	for (i = 0; (size_t) i < eml->em_nheaders; i++)
	{
		const char *field = eml->em_headers[i];
		dkim2_mi_t *m;

		if (!field_is(field, "message-instance"))
			continue;
		m = dkim2_mi_parse(strchr(field, ':') + 1,
		    strlen(strchr(field, ':') + 1));
		if (m != NULL && m->mi_m <= (uint64_t) target)
			printf("%s\r\n", field);
		dkim2_mi_free(m);
	}
	for (i = 0; (size_t) i < ncontent; i++)
		printf("%s\r\n", content[i]);
	printf("\r\n");
	fwrite(body, 1, bodylen, stdout);
	ret = 0;

  done:
	for (i = 0; content != NULL && (size_t) i < ncontent; i++)
		free(content[i]);
	free(content);
	free(body);
	dkim2_eml_free(eml);
	free(msg);
	return ret;
}
