/*
**  phoenixdkim2-verify.c -- standalone DKIM2-core verifier for the testing phase.
**
**  Reads a message on stdin, verifies its DKIM2 chain, prints the result, and
**  exits 0 PASS / 1 FAIL / 2 PERMERROR / 3 TEMPERROR / 4 NONE.  Keys come from
**  live DNS, or from a fixture file (--dns-fixture) of "qname<WSP>TXT-record"
**  lines so the chain can be checked entirely offline.
**
**  Usage:
**    phoenixdkim2-verify [--mail-from "<a@b>"] [--rcpt-to "<c@d>"]...
**        [--ignore-timestamps] [--dns-fixture FILE]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dkim2-dns.h"
#include "dkim2-eml.h"
#include "dkim2-verify.h"

/* ── DNS fixture (optional, for offline testing) ─────────────────────────── */

static char **g_fix_q;
static char **g_fix_rec;
static size_t g_fix_n;

static char *
fixture_lookup(void *ctx, const char *qname, dkim2_dns_status_t *status)
{
	size_t i;

	(void) ctx;

	for (i = 0; i < g_fix_n; i++)
	{
		if (strcmp(g_fix_q[i], qname) == 0)
		{
			*status = DKIM2_DNS_OK;
			return strdup(g_fix_rec[i]);
		}
	}
	*status = DKIM2_DNS_NOKEY;
	return NULL;
}

/* Load "qname<whitespace>record" lines; '#' comments and blanks ignored. */
static int
load_fixture(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[8192];

	if (f == NULL)
		return -1;
	while (fgets(line, sizeof line, f) != NULL)
	{
		char *q = line;
		char *rec;
		size_t l;

		while (*q == ' ' || *q == '\t')
			q++;
		if (*q == '#' || *q == '\n' || *q == '\0')
			continue;
		rec = q;
		while (*rec != '\0' && *rec != ' ' && *rec != '\t')
			rec++;
		if (*rec == '\0')
			continue;
		*rec++ = '\0';
		while (*rec == ' ' || *rec == '\t')
			rec++;
		l = strlen(rec);
		while (l > 0 && (rec[l - 1] == '\n' || rec[l - 1] == '\r'))
			rec[--l] = '\0';

		g_fix_q = realloc(g_fix_q, (g_fix_n + 1) * sizeof *g_fix_q);
		g_fix_rec = realloc(g_fix_rec, (g_fix_n + 1) * sizeof *g_fix_rec);
		if (g_fix_q == NULL || g_fix_rec == NULL)
		{
			fclose(f);
			return -1;
		}
		g_fix_q[g_fix_n] = strdup(q);
		g_fix_rec[g_fix_n] = strdup(rec);
		g_fix_n++;
	}
	fclose(f);
	return 0;
}

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

static const char *
state_name(dkim2_vstate_t s)
{
	switch (s)
	{
	  case DKIM2_V_PASS:	return "PASS";
	  case DKIM2_V_FAIL:	return "FAIL";
	  case DKIM2_V_PERMERROR:	return "PERMERROR";
	  case DKIM2_V_TEMPERROR:	return "TEMPERROR";
	  default:		return "NONE";
	}
}

int
main(int argc, char **argv)
{
	const char **rcpt;
	size_t nrcpt = 0;
	dkim2_verify_opts_t opts;
	dkim2_verify_result_t res;
	dkim2_eml_t *eml;
	char *msg;
	size_t msglen;
	int i, rc;

	memset(&opts, 0, sizeof opts);
	rcpt = calloc((size_t) argc, sizeof *rcpt);
	if (rcpt == NULL)
		return 2;

	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--mail-from") == 0 && i + 1 < argc)
			opts.vo_mail_from = argv[++i];
		else if (strcmp(argv[i], "--rcpt-to") == 0 && i + 1 < argc)
			rcpt[nrcpt++] = argv[++i];
		else if (strcmp(argv[i], "--ignore-timestamps") == 0)
			opts.vo_ignore_timestamps = 1;
		else if (strcmp(argv[i], "--dns-fixture") == 0 && i + 1 < argc)
		{
			if (load_fixture(argv[++i]) != 0)
			{
				fprintf(stderr, "phoenixdkim2-verify: cannot load "
				        "fixture '%s'\n", argv[i]);
				free(rcpt);
				return 2;
			}
			opts.vo_dns_txt = fixture_lookup;
		}
		else
		{
			fprintf(stderr, "phoenixdkim2-verify: unknown option '%s'\n",
			        argv[i]);
			free(rcpt);
			return 2;
		}
	}
	opts.vo_rcpt_to = rcpt;
	opts.vo_rcpt_count = nrcpt;

	msg = read_all(stdin, &msglen);
	eml = msg != NULL ? dkim2_eml_parse(msg, msglen) : NULL;
	if (eml == NULL)
	{
		fprintf(stderr, "phoenixdkim2-verify: cannot parse message\n");
		free(msg);
		free(rcpt);
		return 2;
	}

	memset(&res, 0, sizeof res);
	if (dkim2_verify((const char *const *) eml->em_headers, eml->em_nheaders,
	                 eml->em_body, eml->em_bodylen, &opts, &res) != 0)
	{
		fprintf(stderr, "phoenixdkim2-verify: internal error\n");
		dkim2_eml_free(eml);
		free(msg);
		free(rcpt);
		return 2;
	}

	printf("DKIM2: %s%s%s\n", state_name(res.vr_state),
	       res.vr_message != NULL ? " - " : "",
	       res.vr_message != NULL ? res.vr_message : "");

	switch (res.vr_state)
	{
	  case DKIM2_V_PASS:	rc = 0; break;
	  case DKIM2_V_FAIL:	rc = 1; break;
	  case DKIM2_V_TEMPERROR:	rc = 3; break;
	  case DKIM2_V_NONE:	rc = 4; break;
	  default:		rc = 2; break;
	}

	dkim2_verify_result_clear(&res);
	dkim2_eml_free(eml);
	free(msg);
	free(rcpt);
	return rc;
}
