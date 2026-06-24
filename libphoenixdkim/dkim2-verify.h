/*
**  dkim2-verify.h -- DKIM2-core chain verification (draft-ietf-dkim-dkim2-spec
**  Sections 9 & 10).
**
**  Verification walks the signature chain on a received message and reports one
**  of the four RFC 8601-compatible states.  For DKIM2-core it:
**
**    * validates that the Message-Instance (m=) and DKIM2-Signature (i=)
**      numbering is contiguous from 1 with no gaps, and that no instance is
**      numbered higher than any signature (Section 10.2);
**    * optionally rejects signatures older than 14 days (Section 10.3);
**    * recomputes the body and header hashes and compares them to the highest
**      Message-Instance (Section 10.7);
**    * for every DKIM2-Signature, rebuilds the Section 8.5 signing input (with
**      that signature's value(s) blanked), fetches the key from DNS, and checks
**      every signature value -- all must pass (Section 10.6);
**    * checks d= aligns with the mf= domain, and, when the live SMTP envelope
**      is supplied, that mf=/rt= on the top signature match it (Section 10.4).
*/

#ifndef PHOENIXDKIM_DKIM2_VERIFY_H
#define PHOENIXDKIM_DKIM2_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "dkim2-dns.h"

typedef enum
{
	DKIM2_V_PASS = 0,	/* verified */
	DKIM2_V_FAIL,		/* a hash or signature did not match */
	DKIM2_V_PERMERROR,	/* malformed / missing / unrecoverable */
	DKIM2_V_TEMPERROR,	/* transient (key could not be fetched) */
	DKIM2_V_NONE		/* no DKIM2-Signature present */
} dkim2_vstate_t;

typedef struct dkim2_verify_opts
{
	int		  vo_ignore_timestamps;	/* skip the 14-day check */
	const char	 *vo_mail_from;		/* live SMTP MAIL FROM, or NULL */
	const char *const *vo_rcpt_to;		/* live SMTP RCPT TO list, or NULL */
	size_t		  vo_rcpt_count;
	dkim2_dns_txt_func vo_dns_txt;		/* key TXT resolver (NULL => live) */
	void		 *vo_dns_ctx;		/* opaque passed to vo_dns_txt */
} dkim2_verify_opts_t;

typedef struct dkim2_verify_result
{
	dkim2_vstate_t	 vr_state;
	uint64_t	 vr_i;		/* signature index implicated, when relevant */
	char		*vr_message;	/* human-readable detail (caller frees) */
} dkim2_verify_result_t;

/*
**  DKIM2_VERIFY -- verify the DKIM2 chain on a message.
**
**  Parameters:
**  	headers -- message header fields, each "Name: value" with folding
**  	           preserved and no trailing CRLF
**  	nheaders -- number of header fields
**  	body / bodylen -- the raw message body
**  	opts -- options (may be NULL for defaults: enforce timestamps, no
**  	        envelope binding)
**  	out -- result; out->vr_message is heap-allocated, free with
**  	       dkim2_verify_result_clear()
**
**  Return value:
**  	0 if a result was produced (inspect out->vr_state), -1 on internal error.
**
**  Public keys are fetched through dkim2-dns using opts->vo_dns_txt; leave it
**  NULL for a live res_query() lookup, or supply a fixture/library resolver to
**  verify a whole chain offline or via libphoenixdkim's shared resolver.
*/
extern int dkim2_verify(const char *const *headers, size_t nheaders,
                        const char *body, size_t bodylen,
                        const dkim2_verify_opts_t *opts,
                        dkim2_verify_result_t *out);

extern void dkim2_verify_result_clear(dkim2_verify_result_t *out);

#endif /* PHOENIXDKIM_DKIM2_VERIFY_H */
