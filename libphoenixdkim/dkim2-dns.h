/*
**  dkim2-dns.h -- DKIM2 public-key retrieval.
**
**  A DKIM2 public key is fetched from the DNS exactly as in DKIM1
**  (draft-ietf-dkim-dkim2-spec Section 3.6): a TXT record at
**  "selector._domainkey.domain", whose value is an RFC 6376 key record
**  ("v=DKIM1; k=<alg>; p=<base64 key>").  The keys are the same records DKIM1
**  uses; only the consuming signature format differs.
**
**  This module returns the parsed record fields (algorithm name and base64
**  key); turning those into a usable key and verifying with it is the crypto
**  module's job (dkim2-crypto), keeping DNS free of crypto.
**
**  The actual TXT lookup is supplied by the caller as a dkim2_dns_txt_func, so
**  the milter can route DKIM2 key fetches through libphoenixdkim's resolver
**  (sharing its DNSSEC/cache/test-DNS configuration with the DKIM1 path) while
**  the standalone CLIs and unit tests plug in a fixture or the bundled live
**  res_query() lookup.  When no function is supplied the live lookup is used.
*/

#ifndef PHOENIXDKIM_DKIM2_DNS_H
#define PHOENIXDKIM_DKIM2_DNS_H

#include <stddef.h>

typedef enum
{
	DKIM2_DNS_OK = 0,	/* a usable key record was returned */
	DKIM2_DNS_NOKEY,	/* no such record (NXDOMAIN / no TXT) */
	DKIM2_DNS_TEMPFAIL,	/* transient resolver failure -- retry later */
	DKIM2_DNS_BADKEY	/* a record exists but is malformed */
} dkim2_dns_status_t;

/* A parsed DKIM key record.  An empty kr_p ("") denotes a revoked key. */
typedef struct dkim2_keyrecord
{
	char	*kr_alg;	/* k= value: "rsa" or "ed25519" (default "rsa") */
	char	*kr_p;		/* p= value: base64 public key */
} dkim2_keyrecord_t;

/*
**  DKIM2_DNS_QUERYNAME -- build "selector._domainkey.domain" into buf.
**
**  Return value:
**  	0 on success, -1 if the name does not fit in buflen or an argument is
**  	NULL/empty.
*/
extern int dkim2_dns_queryname(const char *selector, const char *domain,
                               char *buf, size_t buflen);

/*
**  DKIM2_KEYRECORD_PARSE -- parse an RFC 6376 key TXT record.
**
**  Return value:
**  	A heap record (free with dkim2_keyrecord_free()), or NULL if the record
**  	is malformed (no p= tag).  k= defaults to "rsa" when absent.
*/
extern dkim2_keyrecord_t *dkim2_keyrecord_parse(const char *txt);

extern void dkim2_keyrecord_free(dkim2_keyrecord_t *kr);

/*
**  DKIM2_DNS_TXT_FUNC -- caller-supplied TXT resolver.  Given a query name it
**  returns the record as a malloc'd, NUL-terminated string (the caller frees
**  it) and sets *status to DKIM2_DNS_OK, or returns NULL and sets *status to
**  NOKEY / TEMPFAIL.  ctx is the opaque handle the caller registered alongside.
*/
typedef char *(*dkim2_dns_txt_func)(void *ctx, const char *qname,
                                    dkim2_dns_status_t *status);

/*
**  DKIM2_DNS_PARSE_ANSWER -- extract a TXT string from a wire-format DNS reply
**  (as returned by libc res_query() or libphoenixdkim's resolver).  Returns
**  the first TXT record's concatenated character-strings as a malloc'd string
**  with *status = OK, or NULL with *status = NOKEY / TEMPFAIL.  Exposed so a
**  resolver adapter can reuse the DKIM2 extraction.
*/
extern char *dkim2_dns_parse_answer(const unsigned char *answer, size_t len,
                                    dkim2_dns_status_t *status);

/*
**  DKIM2_DNS_TXT_LIVE -- the bundled live TXT lookup via libc res_query(),
**  usable as a dkim2_dns_txt_func default (ctx is ignored).
*/
extern char *dkim2_dns_txt_live(void *ctx, const char *qname,
                                dkim2_dns_status_t *status);

/*
**  DKIM2_DNS_GETKEY -- fetch and parse the key for selector._domainkey.domain.
**
**  txt supplies the TXT lookup (with its ctx); when NULL the live res_query()
**  lookup is used.
**
**  Return value:
**  	The parsed record with *status = DKIM2_DNS_OK, or NULL with *status set
**  	to NOKEY / TEMPFAIL / BADKEY.
*/
extern dkim2_keyrecord_t *dkim2_dns_getkey(const char *selector,
                                           const char *domain,
                                           dkim2_dns_status_t *status,
                                           dkim2_dns_txt_func txt, void *ctx);

#endif /* PHOENIXDKIM_DKIM2_DNS_H */
