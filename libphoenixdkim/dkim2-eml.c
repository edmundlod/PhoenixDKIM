/*
**  dkim2-eml.c -- minimal message splitter for the DKIM2 test CLIs.
**  See dkim2-eml.h.
*/

#include "dkim2-eml.h"

#include <stdlib.h>
#include <string.h>

/* Normalize line endings to CRLF: every LF not already preceded by CR becomes
** CRLF.  Returns a fresh buffer and its length via *outlen. */
static char *
dkim2_eml_crlf(const char *data, size_t len, size_t *outlen)
{
	char *out = malloc(len * 2 + 1);
	size_t o = 0;
	size_t i;

	if (out == NULL)
		return NULL;
	for (i = 0; i < len; i++)
	{
		if (data[i] == '\n' && (i == 0 || data[i - 1] != '\r'))
			out[o++] = '\r';
		out[o++] = data[i];
	}
	out[o] = '\0';
	*outlen = o;
	return out;
}

/* Append a header field (raw[start..end), trailing CRLF already excluded). */
static int
dkim2_eml_add(dkim2_eml_t *eml, const char *start, size_t fieldlen)
{
	char **grown = realloc(eml->em_headers,
	                       (eml->em_nheaders + 1) * sizeof *grown);
	char *field;

	if (grown == NULL)
		return -1;
	eml->em_headers = grown;

	field = malloc(fieldlen + 1);
	if (field == NULL)
		return -1;
	memcpy(field, start, fieldlen);
	field[fieldlen] = '\0';
	eml->em_headers[eml->em_nheaders++] = field;
	return 0;
}

dkim2_eml_t *
dkim2_eml_parse(const char *data, size_t len)
{
	dkim2_eml_t *eml;
	char *buf;
	size_t buflen;
	const char *sep;
	const char *hdr_end;
	const char *body;
	const char *p;
	const char *field_start;

	eml = calloc(1, sizeof *eml);
	if (eml == NULL)
		return NULL;

	buf = dkim2_eml_crlf(data, len, &buflen);
	if (buf == NULL)
	{
		free(eml);
		return NULL;
	}

	/* Header/body separator: the first empty line. */
	sep = strstr(buf, "\r\n\r\n");
	if (sep != NULL)
	{
		hdr_end = sep + 2;	/* CRLF terminating the last header field */
		body = sep + 4;
	}
	else
	{
		/* no body: header block runs to end (with or without a final CRLF) */
		hdr_end = buf + buflen;
		body = buf + buflen;
	}

	/* Walk the header block, grouping continuation lines (those beginning with
	** WSP) into the preceding field.  field_start marks the current field; a
	** field ends at the CRLF that precedes a non-continuation line. */
	field_start = buf;
	for (p = buf; p < hdr_end; )
	{
		const char *eol = strstr(p, "\r\n");

		if (eol == NULL || eol >= hdr_end)
			eol = hdr_end;

		/* peek the start of the next line */
		{
			const char *next = (eol < hdr_end) ? eol + 2 : hdr_end;

			if (next < hdr_end && (*next == ' ' || *next == '\t'))
			{
				/* continuation: the field extends past this line */
				p = next;
				continue;
			}
		}

		if (eol > field_start &&
		    dkim2_eml_add(eml, field_start, (size_t) (eol - field_start)) != 0)
		{
			free(buf);
			dkim2_eml_free(eml);
			return NULL;
		}

		p = (eol < hdr_end) ? eol + 2 : hdr_end;
		field_start = p;
	}

	eml->em_bodylen = (size_t) (buf + buflen - body);
	eml->em_body = malloc(eml->em_bodylen + 1);
	if (eml->em_body == NULL)
	{
		free(buf);
		dkim2_eml_free(eml);
		return NULL;
	}
	memcpy(eml->em_body, body, eml->em_bodylen);
	eml->em_body[eml->em_bodylen] = '\0';

	free(buf);
	return eml;
}

void
dkim2_eml_free(dkim2_eml_t *eml)
{
	size_t i;

	if (eml == NULL)
		return;
	for (i = 0; i < eml->em_nheaders; i++)
		free(eml->em_headers[i]);
	free(eml->em_headers);
	free(eml->em_body);
	free(eml);
}
