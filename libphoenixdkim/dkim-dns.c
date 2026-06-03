/*
**  Copyright (c) 2010-2012, The Trusted Domain Project.  All rights reserved.
**
*/

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! REENTRANT */

/* system includes */
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
/* DKIM_PUTSHORT / DKIM_PUTLONG: drop-in replacements for the system
** PUTSHORT/PUTLONG (NS_PUT16/NS_PUT32) with explicit (unsigned char)
** casts on each byte store; the system macro body omits them, causing
** -Wconversion under strict builds. */
#define DKIM_PUTSHORT(s, cp) do { \
	uint16_t _dps = (uint16_t)(s); \
	*(cp)++ = (unsigned char)(_dps >> 8); \
	*(cp)++ = (unsigned char)(_dps); \
} while (0)
#define DKIM_PUTLONG(l, cp) do { \
	uint32_t _dpl = (uint32_t)(l); \
	*(cp)++ = (unsigned char)(_dpl >> 24); \
	*(cp)++ = (unsigned char)(_dpl >> 16); \
	*(cp)++ = (unsigned char)(_dpl >> 8); \
	*(cp)++ = (unsigned char)(_dpl); \
} while (0)
#include <resolv.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>

/* libphoenixdkim includes */
#include "dkim.h"
#include "dkim-dns.h"

/* PhoenixDKIM includes */
#include "build-config.h"

/* macros, limits, etc. */
#ifndef MAXPACKET
# define MAXPACKET      8192
#endif /* ! MAXPACKET */

/* RR type codes that predate some <arpa/nameser.h> headers */
#ifndef T_AAAA
# define T_AAAA		28
#endif /* ! T_AAAA */
#ifndef T_DS
# define T_DS		43
#endif /* ! T_DS */
#ifndef T_DNSKEY
# define T_DNSKEY	48
#endif /* ! T_DNSKEY */

/*
**  Standard UNIX resolver stub functions
*/

struct dkim_res_qh
{
	int		rq_error;
	int		rq_dnssec;
	size_t		rq_buflen;
};

/*
**  Process-wide record of whether the resolver has ever returned a
**  DNSSEC-validated reply.  A monotonic bitmask of DKIM_DNSSEC_FLAG_*; updated
**  with a plain OR (a benign race at worst, as in Postfix's dns_sec module).
*/
static int dkim_dns_sec_stats = 0;

#ifdef HAVE_RES_NINIT
/*
**  Wrapper around __res_state that serializes concurrent access.
**  res_nquery() is not thread-safe on a shared __res_state: glibc keeps
**  UDP sockets open in EXT(statp).nssocks[] between queries, and concurrent
**  threads race on that array, orphaning file descriptors.
*/
struct dkim_res_svc
{
	struct __res_state	rs_state;
	pthread_mutex_t		rs_lock;
};
#endif /* HAVE_RES_NINIT */

/*
**  DKIM_RES_INIT -- initialize the resolver
**
**  Parameters:
**  	srv -- service handle (returned)
**
**  Return value
**  	0 on success, !0 on failure
*/

int
dkim_res_init(void **srv)
{
#ifdef HAVE_RES_NINIT
	struct dkim_res_svc *svc;

	svc = malloc(sizeof(struct dkim_res_svc));
	if (svc == NULL)
		return -1;

	memset(&svc->rs_state, '\0', sizeof(svc->rs_state));

	if (res_ninit(&svc->rs_state) != 0)
	{
		free(svc);
		return -1;
	}
#ifdef RES_USE_DNSSEC
	svc->rs_state.options |= RES_USE_DNSSEC;
#endif

	pthread_mutex_init(&svc->rs_lock, NULL);

	*srv = svc;

	return 0;
#else /* HAVE_RES_NINIT */
	if (res_init() == 0)
	{
#ifdef RES_USE_DNSSEC
		_res.options |= RES_USE_DNSSEC;
#endif
		*srv = (void *) 0x01;
		return 0;
	}
	else
	{
		return -1;
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  DKIM_RES_CLOSE -- shut down the resolver
**
**  Parameters:
**  	srv -- service handle
**
**  Return value:
**  	None.
*/

void
dkim_res_close(void *srv)
{
#ifdef HAVE_RES_NINIT
	struct dkim_res_svc *svc;

	svc = srv;

	if (svc != NULL)
	{
		res_nclose(&svc->rs_state);
		pthread_mutex_destroy(&svc->rs_lock);
		free(svc);
	}
#endif /* HAVE_RES_NINIT */
}

/*
**  DKIM_RES_CANCEL -- cancel a pending resolver query
**
**  Parameters:
**  	srv -- query service handle (ignored)
**  	qh -- query handle (ignored)
**
**  Return value:
**  	0 on success, !0 on error
**
**  Notes:
**  	The standard UNIX resolver is synchronous, so in theory this can
**  	never get called.  We have not yet got any use cases for one thread
**  	canceling another thread's pending queries, so for now just return 0.
*/

int
dkim_res_cancel(void *srv, void *qh)
{
	(void) srv;

	if (qh != NULL)
		free(qh);

	return 0;
}

/*
**  DKIM_RES_QUERY -- initiate a DNS query
**
**  Parameters:
**  	srv -- service handle (ignored)
**  	type -- RR type to query
**  	query -- the question to ask
**  	buf -- where to write the answer
**  	buflen -- bytes at "buf"
** 	qh -- query handle, used with dkim_res_waitreply
**
**  Return value:
**  	0 on success, -1 on error
**
**  Notes:
**  	This is a stub for the stock UNIX resolver (res_) functions, which
**  	are synchronous so no handle needs to be created, so "qh" is set to
**  	"buf".  "buf" is actually populated before this returns (unless
**  	there's an error).
*/

int
dkim_res_query(void *srv, int type, unsigned char *query, unsigned char *buf,
               size_t buflen, void **qh)
{
	int ret;
	struct dkim_res_qh *rq;
#ifdef HAVE_RES_NINIT
	struct dkim_res_svc *svc;
#endif /* HAVE_RES_NINIT */
#ifdef HAVE_RES_NINIT
	svc = srv;
	pthread_mutex_lock(&svc->rs_lock);
	ret = res_nquery(&svc->rs_state, (char *) query, C_IN, type, buf,
	                 buflen);
	pthread_mutex_unlock(&svc->rs_lock);
#else /* HAVE_RES_NINIT */
	ret = res_query((char *) query, C_IN, type, buf, buflen);
#endif /* HAVE_RES_NINIT */
	if (ret == -1)
	{
		/*
		**  Distinguish "the name does not exist" from a genuine
		**  resolver failure.  res_query()/res_nquery() report the
		**  former by setting h_errno to HOST_NOT_FOUND or NO_DATA
		**  (both res_ functions update the thread-local h_errno on
		**  this platform).  Per RFC 6376 a missing key selector is a
		**  permanent condition and must surface as DKIM_STAT_NOKEY,
		**  not the transient DKIM_STAT_KEYFAIL that DKIM_DNS_ERROR
		**  would produce.
		**
		**  Synthesise an NXDOMAIN reply and let the normal parsing
		**  path classify it.  We echo the question section (name,
		**  type, class) rather than emitting a bare header: the shared
		**  answer parsers read the type/class out of the question
		**  before they test the RCODE, so a header-only packet would
		**  be rejected as an "unexpected reply class/type" before the
		**  NXDOMAIN check was ever reached.
		*/

		unsigned char *cp;
		size_t avail;
		int n;

		if ((h_errno != HOST_NOT_FOUND && h_errno != NO_DATA) ||
		    buflen < HFIXEDSZ + 2 * INT16SZ)
			return DKIM_DNS_ERROR;

		{
			HEADER hdr_tmp;
			memset(&hdr_tmp, '\0', sizeof hdr_tmp);
			hdr_tmp.qr = 1;
			hdr_tmp.rcode = NXDOMAIN;
			hdr_tmp.qdcount = htons(1);
			memcpy(buf, &hdr_tmp, sizeof hdr_tmp);
		}

		/* reserve room for the trailing QTYPE and QCLASS */
		cp = buf + HFIXEDSZ;
		avail = buflen - HFIXEDSZ - 2 * INT16SZ;

		n = dn_comp((char *) query, cp, (int) avail, NULL, NULL);
		if (n < 0)
			return DKIM_DNS_ERROR;
		cp += n;
		DKIM_PUTSHORT((unsigned short) type, cp);
		DKIM_PUTSHORT(C_IN, cp);

		ret = cp - buf;
	}

	rq = (struct dkim_res_qh *) malloc(sizeof *rq);
	if (rq == NULL)
		return DKIM_DNS_ERROR;

	{
		HEADER hdr_tmp;
		memcpy(&hdr_tmp, buf, sizeof hdr_tmp);
		if (hdr_tmp.ad)
		{
			rq->rq_dnssec = DKIM_DNSSEC_SECURE;
			dkim_dns_sec_stats |= DKIM_DNSSEC_FLAG_AVAILABLE;
		}
		else
		{
			rq->rq_dnssec = DKIM_DNSSEC_INSECURE;
		}
	}
	if (ret == -1)
	{
		rq->rq_error = errno;
		rq->rq_buflen = 0;
	}
	else
	{
		rq->rq_error = 0;
		rq->rq_buflen = (size_t) ret;
	}

	*qh = (void *) rq;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_RES_WAITREPLY -- wait for a reply to a pending query
**
**  Parameters:
**  	srv -- service handle
**  	qh -- query handle
**  	to -- timeout
**  	bytes -- number of bytes in the reply (returned)
**  	error -- error code (returned)
**
**  Return value:
**  	A DKIM_DNS_* code.
**
**  Notes:
**  	Since the stock UNIX resolver is synchronous, the reply was completed
** 	before dkim_res_query() returned, and thus this is almost a no-op.
*/

int
dkim_res_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
                   int *error, int *dnssec)
{
	struct dkim_res_qh *rq;

	(void) srv;
	(void) to;

	assert(qh != NULL);

	rq = qh;

	if (bytes != NULL)
		*bytes = rq->rq_buflen;
	if (error != NULL)
		*error = rq->rq_error;
	if (dnssec != NULL)
		*dnssec = rq->rq_dnssec;

	return DKIM_DNS_SUCCESS;
}

/*
**  DKIM_RES_DNSSEC_STATS -- return the process-wide DNSSEC status flags
**
**  Parameters:
**  	None.
**
**  Return value:
**  	A bitmask of DKIM_DNSSEC_FLAG_* values.
*/

int
dkim_res_dnssec_stats(void)
{
	return dkim_dns_sec_stats;
}

/*
**  DKIM_DNS_NAMETOTYPE -- map a textual RR type to its numeric value
**
**  Parameters:
**  	name -- type name (case-insensitive), e.g. "ns"
**
**  Return value:
**  	The T_* constant, or -1 if unrecognised.
*/

int
dkim_dns_nametotype(const char *name)
{
	static const struct
	{
		const char	*name;
		int		 type;
	} types[] =
	{
		{ "a",		T_A		},
		{ "aaaa",	T_AAAA		},
		{ "ns",		T_NS		},
		{ "soa",	T_SOA		},
		{ "mx",		T_MX		},
		{ "txt",	T_TXT		},
		{ "cname",	T_CNAME		},
		{ "ptr",	T_PTR		},
		{ "dnskey",	T_DNSKEY	},
		{ "ds",		T_DS		},
		{ NULL,		-1		},
	};
	int c;

	if (name == NULL)
		return -1;

	for (c = 0; types[c].name != NULL; c++)
	{
		if (strcasecmp(name, types[c].name) == 0)
			return types[c].type;
	}

	return -1;
}

/*
**  DKIM_RES_DNSSEC_PROBE -- query a known-signed name to test the resolver
**
**  Parameters:
**  	srv -- service handle
**  	qtype -- RR type to query
**  	qname -- name to query (a known DNSSEC-signed name)
**  	err -- buffer for a human-readable reason (may be NULL)
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	A DKIM_DNSSEC_PROBE_* constant.
**
**  Notes:
**  	The probe is sent at most once per process.  On a validated reply the
**  	process-wide DKIM_DNSSEC_FLAG_AVAILABLE flag is set, after which the
**  	stock resolver's AD=0 results can be trusted to mean "genuinely
**  	insecure" rather than "validation unavailable".
*/

int
dkim_res_dnssec_probe(void *srv, int qtype, const char *qname,
                      char *err, size_t errlen)
{
	int ret;
	unsigned char buf[MAXPACKET];
	HEADER hdr;
#ifdef HAVE_RES_NINIT
	struct dkim_res_svc *svc = srv;
#endif /* HAVE_RES_NINIT */

	assert(qname != NULL);

	/* send the probe at most once per process */
	if ((dkim_dns_sec_stats & DKIM_DNSSEC_FLAG_DONT_PROBE) != 0)
		return DKIM_DNSSEC_PROBE_SKIPPED;
	dkim_dns_sec_stats |= DKIM_DNSSEC_FLAG_DONT_PROBE;

#ifdef HAVE_RES_NINIT
	assert(svc != NULL);
	pthread_mutex_lock(&svc->rs_lock);
	ret = res_nquery(&svc->rs_state, qname, C_IN, qtype, buf, sizeof buf);
	pthread_mutex_unlock(&svc->rs_lock);
#else /* HAVE_RES_NINIT */
	ret = res_query(qname, C_IN, qtype, buf, sizeof buf);
#endif /* HAVE_RES_NINIT */

	if (ret < (int) HFIXEDSZ)
	{
		if (err != NULL)
			strlcpy(err, hstrerror(h_errno), errlen);
		return DKIM_DNSSEC_PROBE_NORESPONSE;
	}

	memcpy(&hdr, buf, sizeof hdr);
	if (hdr.ad)
	{
		dkim_dns_sec_stats |= DKIM_DNSSEC_FLAG_AVAILABLE;
		return DKIM_DNSSEC_PROBE_VALIDATED;
	}

	if (err != NULL)
		strlcpy(err, "reply not DNSSEC-validated (no AD bit)", errlen);
	return DKIM_DNSSEC_PROBE_UNVALIDATED;
}

/*
**  DKIM_RES_SETNS -- set nameserver list
**
**  Parameters:
**  	srv -- service handle
**  	nslist -- nameserver list, as a string
**
**  Return value:
**  	DKIM_DNS_SUCCESS -- success
**  	DKIM_DNS_ERROR -- error
*/

int
dkim_res_nslist(void *srv, const char *nslist)
{
#ifndef HAVE_RES_SETSERVERS
	(void) srv;
	(void) nslist;
#endif /* ! HAVE_RES_SETSERVERS */
#ifdef HAVE_RES_SETSERVERS
	int nscount = 0;
	char *tmp;
	char *ns;
	char *last = NULL;
	struct sockaddr_in in;
# ifdef AF_INET6
	struct sockaddr_in6 in6;
# endif /* AF_INET6 */
	struct dkim_res_svc *svc;
	union res_sockaddr_union nses[MAXNS];

	assert(srv != NULL);
	assert(nslist != NULL);

	memset(nses, '\0', sizeof nses);

	tmp = strdup(nslist);
	if (tmp == NULL)
		return DKIM_DNS_ERROR;

	for (ns = strtok_r(tmp, ",", &last);
	     ns != NULL && nscount < MAXNS;
	     ns = strtok_r(NULL, ",", &last))
	{
		memset(&in, '\0', sizeof in);
# ifdef AF_INET6
		memset(&in6, '\0', sizeof in6);
# endif /* AF_INET6 */

		if (inet_pton(AF_INET, ns, (struct in_addr *) &in.sin_addr,
		              sizeof in.sin_addr) == 1)
		{
			in.sin_family= AF_INET;
			in.sin_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin, &in,
			       sizeof nses[nscount].sin);
			nscount++;
		}
# ifdef AF_INET6
		else if (inet_pton(AF_INET6, ns,
		                   (struct in6_addr *) &in6.sin6_addr,
		                   sizeof in6.sin6_addr) == 1)
		{
			in6.sin6_family= AF_INET6;
			in6.sin6_port = htons(DNSPORT);
			memcpy(&nses[nscount].sin6, &in6,
			       sizeof nses[nscount].sin6);
			nscount++;
		}
# endif /* AF_INET6 */
		else
		{
			free(tmp);
			return DKIM_DNS_ERROR;
		}
	}

	svc = srv;
	res_setservers(&svc->rs_state, nses, nscount);

	free(tmp);
#endif /* HAVE_RES_SETSERVERS */

	return DKIM_DNS_SUCCESS;
}
