/*
**  dkim2-dns.c -- DKIM2 public-key retrieval.  See dkim2-dns.h.
*/

#include "dkim2-dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>

/* libphoenixdkim includes */
#include "dkim2-tags.h"

int
dkim2_dns_queryname(const char *selector, const char *domain,
                    char *buf, size_t buflen)
{
	int n;

	if (selector == NULL || *selector == '\0' ||
	    domain == NULL || *domain == '\0')
		return -1;

	n = snprintf(buf, buflen, "%s._domainkey.%s", selector, domain);
	if (n < 0 || (size_t) n >= buflen)
		return -1;

	return 0;
}

dkim2_keyrecord_t *
dkim2_keyrecord_parse(const char *txt)
{
	dkim2_taglist_t *tl;
	dkim2_keyrecord_t *kr;
	const char *k;
	const char *p;

	if (txt == NULL)
		return NULL;

	tl = dkim2_taglist_parse(txt, strlen(txt));
	if (tl == NULL)
		return NULL;

	/* p= is required; its absence (not its emptiness) is malformed. */
	p = dkim2_taglist_get(tl, "p");
	if (p == NULL)
	{
		dkim2_taglist_free(tl);
		return NULL;
	}

	kr = calloc(1, sizeof *kr);
	if (kr == NULL)
	{
		dkim2_taglist_free(tl);
		return NULL;
	}

	/* k= defaults to "rsa" (RFC 6376 Section 3.6.1). Copy before freeing the
	** tag list -- the returned pointers alias its storage. */
	k = dkim2_taglist_get(tl, "k");
	kr->kr_alg = strdup(k != NULL ? k : "rsa");
	kr->kr_p = strdup(p);

	dkim2_taglist_free(tl);

	if (kr->kr_alg == NULL || kr->kr_p == NULL)
	{
		dkim2_keyrecord_free(kr);
		return NULL;
	}

	return kr;
}

void
dkim2_keyrecord_free(dkim2_keyrecord_t *kr)
{
	if (kr == NULL)
		return;
	free(kr->kr_alg);
	free(kr->kr_p);
	free(kr);
}

/*
**  DKIM2_DNS_PARSE_ANSWER -- extract the first TXT record from a wire-format
**  DNS reply, concatenating its character-strings into one malloc'd
**  NUL-terminated string.
**
**  ns_c_in / ns_t_txt (rather than the BIND-8 C_IN / T_TXT spellings) are used
**  for portability to platforms that gate the legacy names behind
**  BIND_8_COMPAT (e.g. macOS).
*/
char *
dkim2_dns_parse_answer(const unsigned char *answer, size_t len,
                       dkim2_dns_status_t *status)
{
	ns_msg handle;
	ns_rr rr;
	int count;
	int i;

	if (ns_initparse(answer, (int) len, &handle) < 0)
	{
		*status = DKIM2_DNS_TEMPFAIL;
		return NULL;
	}

	count = ns_msg_count(handle, ns_s_an);
	for (i = 0; i < count; i++)
	{
		const unsigned char *rdata;
		size_t rdlen;
		size_t off;
		char *out;
		size_t outlen;

		if (ns_parserr(&handle, ns_s_an, i, &rr) != 0)
			continue;
		if (ns_rr_type(rr) != ns_t_txt)
			continue;

		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);

		/* TXT rdata is a sequence of <length><bytes> character-strings. */
		out = malloc(rdlen + 1);
		if (out == NULL)
		{
			*status = DKIM2_DNS_TEMPFAIL;
			return NULL;
		}
		outlen = 0;
		off = 0;
		while (off < rdlen)
		{
			size_t seg = rdata[off++];

			if (off + seg > rdlen)
				break;	/* malformed segment length */
			memcpy(out + outlen, rdata + off, seg);
			outlen += seg;
			off += seg;
		}
		out[outlen] = '\0';

		*status = DKIM2_DNS_OK;
		return out;
	}

	*status = DKIM2_DNS_NOKEY;
	return NULL;
}

/*
**  DKIM2_DNS_TXT_LIVE -- the bundled live TXT lookup via libc res_query().
**  ctx is unused; the signature matches dkim2_dns_txt_func so it can serve as
**  the default resolver.
*/
char *
dkim2_dns_txt_live(void *ctx, const char *qname, dkim2_dns_status_t *status)
{
	unsigned char answer[NS_PACKETSZ];
	int len;

	(void) ctx;

	len = res_query(qname, ns_c_in, ns_t_txt, answer, sizeof answer);
	if (len < 0)
	{
		/* NXDOMAIN or no TXT data is "no key"; anything else is transient. */
		if (h_errno == HOST_NOT_FOUND || h_errno == NO_DATA)
			*status = DKIM2_DNS_NOKEY;
		else
			*status = DKIM2_DNS_TEMPFAIL;
		return NULL;
	}

	return dkim2_dns_parse_answer(answer, (size_t) len, status);
}

dkim2_keyrecord_t *
dkim2_dns_getkey(const char *selector, const char *domain,
                 dkim2_dns_status_t *status, dkim2_dns_txt_func txt_func,
                 void *txt_ctx)
{
	char qname[NS_MAXDNAME];
	char *txt;
	dkim2_keyrecord_t *kr;
	dkim2_dns_status_t st = DKIM2_DNS_TEMPFAIL;

	if (dkim2_dns_queryname(selector, domain, qname, sizeof qname) != 0)
	{
		*status = DKIM2_DNS_BADKEY;
		return NULL;
	}

	if (txt_func == NULL)
		txt_func = dkim2_dns_txt_live;

	txt = txt_func(txt_ctx, qname, &st);

	if (txt == NULL)
	{
		*status = st;
		return NULL;
	}

	kr = dkim2_keyrecord_parse(txt);
	free(txt);

	if (kr == NULL)
	{
		*status = DKIM2_DNS_BADKEY;
		return NULL;
	}

	*status = DKIM2_DNS_OK;
	return kr;
}
