/*
**  dkim2-tags.c -- DKIM2 tag=value list parser.  See dkim2-tags.h.
*/

#include "dkim2-tags.h"

#include <stdlib.h>
#include <string.h>

/* WSP per RFC 5234 plus the CR/LF of folding whitespace; the tag-value grammar
** lets FWS appear around names, '=' and ';'. */
static int
dkim2_is_wsp(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*
**  DKIM2_DUP_TRIMMED -- duplicate s[0..len) with leading/trailing WSP removed.
**
**  Returns a NUL-terminated heap string (possibly empty), or NULL on OOM.
*/
static char *
dkim2_dup_trimmed(const char *s, size_t len)
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

dkim2_taglist_t *
dkim2_taglist_parse(const char *s, size_t len)
{
	const char *end;
	const char *seg;
	dkim2_taglist_t *tl;

	if (s == NULL)
		return NULL;

	tl = calloc(1, sizeof *tl);
	if (tl == NULL)
		return NULL;

	end = s + len;
	seg = s;

	while (seg <= end)
	{
		const char *semi;
		const char *eq;
		const char *p;
		dkim2_tag_t *tag;
		int empty;

		/* find the end of this segment (next ';' or end of input) */
		semi = seg;
		while (semi < end && *semi != ';')
			semi++;

		/* a segment that is empty or all-whitespace is skipped; this
		** covers a single trailing ';' and incidental blank runs */
		empty = 1;
		for (p = seg; p < semi; p++)
		{
			if (!dkim2_is_wsp(*p))
			{
				empty = 0;
				break;
			}
		}

		if (!empty)
		{
			/* split on the first '=' */
			eq = seg;
			while (eq < semi && *eq != '=')
				eq++;

			if (eq == semi)
			{
				/* non-empty segment with no '=' is malformed */
				dkim2_taglist_free(tl);
				return NULL;
			}

			tag = calloc(1, sizeof *tag);
			if (tag == NULL)
			{
				dkim2_taglist_free(tl);
				return NULL;
			}

			tag->t_name = dkim2_dup_trimmed(seg, (size_t) (eq - seg));
			tag->t_value = dkim2_dup_trimmed(eq + 1,
			                                 (size_t) (semi - (eq + 1)));

			if (tag->t_name == NULL || tag->t_value == NULL ||
			    tag->t_name[0] == '\0')
			{
				/* OOM, or an empty tag name (e.g. "=x") */
				free(tag->t_name);
				free(tag->t_value);
				free(tag);
				dkim2_taglist_free(tl);
				return NULL;
			}

			if (tl->tl_tail == NULL)
				tl->tl_head = tag;
			else
				tl->tl_tail->t_next = tag;
			tl->tl_tail = tag;
		}

		if (semi >= end)
			break;
		seg = semi + 1;
	}

	return tl;
}

void
dkim2_taglist_free(dkim2_taglist_t *tl)
{
	dkim2_tag_t *tag;

	if (tl == NULL)
		return;

	tag = tl->tl_head;
	while (tag != NULL)
	{
		dkim2_tag_t *next = tag->t_next;

		free(tag->t_name);
		free(tag->t_value);
		free(tag);
		tag = next;
	}

	free(tl);
}

const char *
dkim2_taglist_get(const dkim2_taglist_t *tl, const char *name)
{
	const dkim2_tag_t *tag;

	if (tl == NULL || name == NULL)
		return NULL;

	for (tag = tl->tl_head; tag != NULL; tag = tag->t_next)
	{
		if (strcmp(tag->t_name, name) == 0)
			return tag->t_value;
	}

	return NULL;
}

size_t
dkim2_taglist_count(const dkim2_taglist_t *tl)
{
	const dkim2_tag_t *tag;
	size_t n = 0;

	if (tl == NULL)
		return 0;

	for (tag = tl->tl_head; tag != NULL; tag = tag->t_next)
		n++;

	return n;
}
