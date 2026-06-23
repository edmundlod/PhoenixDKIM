/*
**  dkim2-json.c -- base64-encoded JSON helpers for DKIM2.  See dkim2-json.h.
*/

#include "dkim2-json.h"

#include <stdlib.h>
#include <string.h>

/* libphoenixdkim includes */
#include "base64.h"

cJSON *
dkim2_json_b64_decode(const char *b64, size_t len)
{
	char *in;
	unsigned char *raw;
	int rawlen;
	cJSON *json;

	if (b64 == NULL)
		return NULL;

	/* The decoder stops at '\0' or '=' and skips non-alphabet bytes, so it
	** needs a NUL-terminated copy; folding whitespace within is harmless. */
	in = malloc(len + 1);
	if (in == NULL)
		return NULL;
	memcpy(in, b64, len);
	in[len] = '\0';

	/* base64 expands 4 chars -> 3 bytes, so the decoded form is never larger
	** than the encoded text; len + 1 is always enough room. */
	raw = malloc(len + 1);
	if (raw == NULL)
	{
		free(in);
		return NULL;
	}

	rawlen = dkim_base64_decode((const u_char *) in, raw, len + 1);
	free(in);
	if (rawlen < 0)
	{
		free(raw);
		return NULL;
	}

	json = cJSON_ParseWithLength((const char *) raw, (size_t) rawlen);
	free(raw);

	return json;
}

char *
dkim2_json_b64_encode(const cJSON *json)
{
	char *txt;
	size_t txtlen;
	size_t buflen;
	unsigned char *buf;
	int enclen;

	if (json == NULL)
		return NULL;

	txt = cJSON_PrintUnformatted(json);
	if (txt == NULL)
		return NULL;

	txtlen = strlen(txt);

	/* 4 output bytes for every 3 input bytes, rounded up, plus a NUL. */
	buflen = 4 * ((txtlen + 2) / 3) + 1;
	buf = malloc(buflen);
	if (buf == NULL)
	{
		free(txt);
		return NULL;
	}

	enclen = dkim_base64_encode((u_char *) txt, txtlen, buf, buflen);
	free(txt);
	if (enclen < 0)
	{
		free(buf);
		return NULL;
	}
	buf[(size_t) enclen] = '\0';

	return (char *) buf;
}
