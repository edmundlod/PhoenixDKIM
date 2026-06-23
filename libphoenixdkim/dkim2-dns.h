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
**  A test/CLI override hook lets the lookup be driven from a fixture zone
**  without touching live DNS.
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
**  DKIM2_DNS_GETKEY -- fetch and parse the key for selector._domainkey.domain.
**
**  Uses the dkim2_dns_override hook if set, otherwise a live TXT query.
**
**  Return value:
**  	The parsed record with *status = DKIM2_DNS_OK, or NULL with *status set
**  	to NOKEY / TEMPFAIL / BADKEY.
*/
extern dkim2_keyrecord_t *dkim2_dns_getkey(const char *selector,
                                           const char *domain,
                                           dkim2_dns_status_t *status);

/*
**  DKIM2_DNS_OVERRIDE -- test/CLI hook.  If non-NULL it is called with the
**  query name and must return a malloc'd TXT string (the caller frees it) or
**  NULL to fall through to live DNS.
*/
extern char *(*dkim2_dns_override)(const char *qname);

#endif /* PHOENIXDKIM_DKIM2_DNS_H */
