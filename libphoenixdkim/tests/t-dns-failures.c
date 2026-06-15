/*
**  Copyright (c) 2026, PhoenixDKIM contributors.
**    All rights reserved.
**
**  DNS failure-mode matrix.
**
**  Verifies that key-record lookup failures are classified with the correct
**  permanence: a missing selector (NXDOMAIN / NODATA) is a PERMANENT "no key"
**  (DKIM_SIGERROR_NOKEY), while a resolver timeout, SERVFAIL/network error, or
**  a truncated reply is a TRANSIENT failure (DKIM_SIGERROR_KEYFAIL) that the
**  caller is expected to retry.  See the mapping table in dkim-keys.c and the
**  synthetic-NXDOMAIN shim in dkim-dns.c.
**
**  Rather than perturb the real resolver (which cannot be driven
**  deterministically), this test installs a mock DNS service via the public
**  dkim_dns_set_query_* hooks and feeds each failure condition straight into
**  the answer-classification path.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/nameser.h>
#include <resolv.h>

/* libphoenixdkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define MAXHEADER	4096

/*
**  A signature that parses cleanly and reaches the key-lookup stage.  Borrowed
**  from t-test104 but with a PAST timestamp (t=): dkim_eom() validates the
**  signature timestamp before it looks up the key, so a future t= would short-
**  circuit as DKIM_SIGERROR_FUTURE and the key-lookup path under test would
**  never run.  The b=/bh= values are never checked here because key lookup
**  fails first; only structural parse validity matters.
*/
#define SIG2 "v=1; a=rsa-sha1; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=ll/0h2aWgG+D3ewmE4Y3pY7Ukz8=; h=Received:Received:\r\n\t Received:From:To:Date:Subject:Message-ID; b=bj9kVUbnBYfe9sVzH9lT45\r\n\tTFKO3eQnDbXLfgmgu/b5QgxcnhT9ojnV2IAM4KUO8+hOo5sDEu5Co/0GASH0vHpSV4P\r\n\t377Iwew3FxvLpHsVbVKgXzoKD4QSbHRpWNxyL6LypaaqFa96YqjXuYXr0vpb88hticn\r\n\t6I16//WThMz8fMU="

/* network byte order put, mirroring dkim-dns.c (named to avoid clashing with
** the system <arpa/nameser_compat.h> PUTSHORT) */
#define WIRE_PUTSHORT(s, cp) do { \
		uint16_t t_s = (uint16_t) (s); \
		*(cp)++ = (unsigned char) ((t_s >> 8) & 0xff); \
		*(cp)++ = (unsigned char) (t_s & 0xff); \
	} while (0)

/* failure scenarios driven through the mock resolver */
enum dnsfail
{
	DF_TIMEOUT = 0,		/* resolver timeout       -> KEYFAIL (transient) */
	DF_SERVFAIL,		/* SERVFAIL / network err -> KEYFAIL (transient) */
	DF_NXDOMAIN,		/* selector absent        -> NOKEY   (permanent) */
	DF_NODATA,		/* NOERROR, zero answers  -> NOKEY   (permanent) */
	DF_TRUNCATED,		/* TC bit set             -> KEYFAIL (transient) */
	DF_MAX
};

static const struct
{
	const char	*name;
	int		 sigerror;	/* expected dkim_sig_geterror() */
	DKIM_STAT	 eomstat;	/* expected dkim_eom() return        */
} scenarios[] =
{
	{ "timeout",        DKIM_SIGERROR_KEYFAIL, DKIM_STAT_KEYFAIL },
	{ "servfail",       DKIM_SIGERROR_KEYFAIL, DKIM_STAT_KEYFAIL },
	{ "nxdomain",       DKIM_SIGERROR_NOKEY,   DKIM_STAT_NOKEY   },
	{ "nodata",         DKIM_SIGERROR_NOKEY,   DKIM_STAT_NOKEY   },
	{ "truncated",      DKIM_SIGERROR_KEYFAIL, DKIM_STAT_KEYFAIL },
};

/* currently-selected scenario; set by main() before each verify */
static int cur_scenario;

/* per-query handle: the reply length and the status waitreply should return */
struct mock_qh
{
	size_t	mq_len;
	int	mq_status;
};

/*
**  Build a DNS wire-format reply into "buf" for the answer-parsing scenarios.
**  Echoes the question section (name/T_TXT/C_IN) exactly as dkim-dns.c does,
**  so the shared parser in dkim-keys.c reads type/class before testing RCODE.
**  Returns the reply length, or 0 if no buffer is needed for this scenario.
*/
static size_t
build_reply(int scenario, unsigned char *query, unsigned char *buf,
            size_t buflen)
{
	HEADER hdr;
	unsigned char *cp;
	int n;

	if (scenario == DF_TIMEOUT || scenario == DF_SERVFAIL)
		return 0;			/* surfaced via waitreply status */

	assert(buflen > HFIXEDSZ + 2 * INT16SZ);

	memset(&hdr, '\0', sizeof hdr);
	hdr.qr = 1;
	hdr.qdcount = htons(1);
	if (scenario == DF_NXDOMAIN)
		hdr.rcode = NXDOMAIN;		/* permanent: name does not exist */
	if (scenario == DF_TRUNCATED)
	{
		hdr.tc = 1;			/* transient: answer overflowed UDP */
		hdr.ancount = htons(1);		/* a (cut-off) answer was present */
	}
	memcpy(buf, &hdr, sizeof hdr);

	/* question section: <qname> T_TXT C_IN */
	cp = buf + HFIXEDSZ;
	n = dn_comp((char *) query, cp,
	            (int) (buflen - HFIXEDSZ - 2 * INT16SZ), NULL, NULL);
	assert(n >= 0);
	cp += n;
	WIRE_PUTSHORT(T_TXT, cp);
	WIRE_PUTSHORT(C_IN, cp);

	/*
	**  NXDOMAIN and NODATA carry zero answers (classified by RCODE /
	**  ancount==0).  The truncation scenario must carry an answer record:
	**  a truncated reply with zero answers is reported as "no record"
	**  (dkim_check_dns_reply() returns 2, not 1), whereas a reply whose
	**  answer was cut off is the genuine transient case the resolver would
	**  normally retry over TCP.  Append one complete TXT record so the TC
	**  bit is what drives the verdict.
	*/
	if (scenario == DF_TRUNCATED)
	{
		WIRE_PUTSHORT(0xc00c, cp);	/* name: pointer to the question */
		WIRE_PUTSHORT(T_TXT, cp);	/* type  */
		WIRE_PUTSHORT(C_IN, cp);	/* class */
		WIRE_PUTSHORT(0, cp);		/* ttl hi */
		WIRE_PUTSHORT(0, cp);		/* ttl lo */
		WIRE_PUTSHORT(4, cp);		/* rdlength */
		*cp++ = 3;			/* TXT char-string length */
		*cp++ = 'a';
		*cp++ = 'b';
		*cp++ = 'c';
	}

	return (size_t) (cp - buf);
}

/* DNS service hooks ---------------------------------------------------------*/

static int
mock_init(void **srv)
{
	static int handle;
	*srv = &handle;			/* any non-NULL handle */
	return 0;
}

static int
mock_start(void *srv, int type, unsigned char *query, unsigned char *buf,
           size_t buflen, void **qh)
{
	struct mock_qh *mq;

	mq = malloc(sizeof *mq);
	assert(mq != NULL);

	mq->mq_len = build_reply(cur_scenario, query, buf, buflen);

	switch (cur_scenario)
	{
	  case DF_TIMEOUT:
		mq->mq_status = DKIM_DNS_EXPIRED;
		break;
	  case DF_SERVFAIL:
		mq->mq_status = DKIM_DNS_ERROR;
		break;
	  default:
		mq->mq_status = DKIM_DNS_SUCCESS;
		break;
	}

	*qh = mq;
	return 0;
}

static int
mock_waitreply(void *srv, void *qh, struct timeval *to, size_t *bytes,
               int *error, int *dnssec)
{
	struct mock_qh *mq = qh;

	if (bytes != NULL)
		*bytes = mq->mq_len;
	if (error != NULL)
		*error = 0;
	if (dnssec != NULL)
		*dnssec = DKIM_DNSSEC_UNKNOWN;

	return mq->mq_status;
}

static int
mock_cancel(void *srv, void *qh)
{
	free(qh);
	return 0;
}

/*
**  No-op close: our service handle is a pointer to static storage, so the
**  default resolver close (which would res_nclose()/free() it) must not run.
*/
static void
mock_close(void *srv)
{
	return;
}

/* drive one verify to completion and return the signature's error code -------*/

static int
run_scenario(DKIM_LIB *lib, int scenario)
{
	DKIM_STAT status;
	DKIM *dkim;
	DKIM_SIGINFO *sig;
	unsigned char hdr[MAXHEADER + 1];

	cur_scenario = scenario;

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	snprintf((char *) hdr, sizeof hdr, "%s: %s", DKIM_SIGNHEADER, SIG2);
	assert(dkim_header(dkim, hdr, strlen((char *) hdr)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER01, strlen(HEADER01)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER02, strlen(HEADER02)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER03, strlen(HEADER03)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER04, strlen(HEADER04)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER05, strlen(HEADER05)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER06, strlen(HEADER06)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER07, strlen(HEADER07)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER08, strlen(HEADER08)) == DKIM_STAT_OK);
	assert(dkim_header(dkim, HEADER09, strlen(HEADER09)) == DKIM_STAT_OK);
	assert(dkim_eoh(dkim) == DKIM_STAT_OK);
	assert(dkim_body(dkim, BODY00, strlen(BODY00)) == DKIM_STAT_OK);
	assert(dkim_body(dkim, BODY01, strlen(BODY01)) == DKIM_STAT_OK);

	/*
	**  dkim_eom() surfaces the key-lookup verdict both as its own return
	**  value (DKIM_STAT_NOKEY vs DKIM_STAT_KEYFAIL) and as the per-signature
	**  error; check the top-level status here and return the sig error to
	**  the caller for the rest of the matrix assertion.
	*/
	status = dkim_eom(dkim, NULL);
	assert(status == scenarios[scenario].eomstat);

	sig = dkim_getsignature(dkim);
	assert(sig != NULL);

	status = (DKIM_STAT) dkim_sig_geterror(sig);

	assert(dkim_free(dkim) == DKIM_STAT_OK);

	return (int) status;
}

int
main(int argc, char **argv)
{
	int i;
	int failures = 0;
	DKIM_LIB *lib;
	dkim_query_t qtype = DKIM_QUERY_DNS;

	printf("*** DNS failure-mode classification matrix\n");

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	(void) dkim_setopt(lib, DKIM_OPTS_QUERYMETHOD, &qtype, sizeof qtype);

	/* install the mock resolver */
	(void) dkim_dns_set_query_service(lib, NULL);
	dkim_dns_set_init(lib, mock_init);
	dkim_dns_set_close(lib, mock_close);
	dkim_dns_set_query_start(lib, mock_start);
	dkim_dns_set_query_waitreply(lib, mock_waitreply);
	dkim_dns_set_query_cancel(lib, mock_cancel);

	for (i = 0; i < DF_MAX; i++)
	{
		int got = run_scenario(lib, i);
		int want = scenarios[i].sigerror;
		const char *verdict = (want == DKIM_SIGERROR_NOKEY)
		                          ? "permanent (NOKEY)"
		                          : "transient (KEYFAIL)";

		if (got == want)
		{
			printf("    PASS  %-10s -> %s\n",
			       scenarios[i].name, verdict);
		}
		else
		{
			printf("    FAIL  %-10s -> got error %d, want %d (%s)\n",
			       scenarios[i].name, got, want, verdict);
			failures++;
		}
	}

	dkim_close(lib);

	if (failures != 0)
	{
		printf("*** %d scenario(s) misclassified\n", failures);
		return 1;
	}

	printf("*** all %d scenarios classified correctly\n", DF_MAX);
	return 0;
}
