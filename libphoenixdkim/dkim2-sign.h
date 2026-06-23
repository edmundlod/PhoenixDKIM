/*
**  dkim2-sign.h -- DKIM2-core signing (draft-ietf-dkim-dkim2-spec Section 8).
**
**  Signing a message means: hash the body and header fields into a
**  Message-Instance (the Originator adds m=1; a re-signer references the
**  existing top instance), build an incomplete DKIM2-Signature with the SMTP
**  envelope and an empty s= signature, assemble the signing input from the
**  ordered Message-Instance and DKIM2-Signature fields per Section 8.5, sign
**  it, and drop the signature value into s=.
**
**  This implements the stateless DKIM2-core profile: it declares no body or
**  header recipes, so a re-signer adds only a new DKIM2-Signature and never a
**  new Message-Instance.
*/

#ifndef PHOENIXDKIM_DKIM2_SIGN_H
#define PHOENIXDKIM_DKIM2_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "dkim2-crypto.h"

typedef struct dkim2_sign_params
{
	const char	 *sp_domain;	/* d= */
	const char	 *sp_selector;	/* selector for s= */
	EVP_PKEY	 *sp_key;	/* private key */
	dkim2_alg_t	  sp_alg;	/* signing algorithm */
	const char	 *sp_mf;	/* SMTP reverse-path, e.g. "<a@b.com>" */
	const char *const *sp_rt;	/* SMTP forward-paths */
	size_t		  sp_rt_count;
	uint64_t	  sp_t;		/* timestamp; 0 means "use current time" */
} dkim2_sign_params_t;

/*
**  DKIM2_SIGN -- produce the DKIM2 header field(s) to add to a message.
**
**  Parameters:
**  	p -- signing parameters
**  	headers -- the message header fields, each "Name: value" with folding
**  	           preserved and no trailing CRLF (including any existing
**  	           Message-Instance / DKIM2-Signature fields when re-signing)
**  	nheaders -- number of header fields
**  	body -- the raw message body
**  	bodylen -- body length in bytes
**  	mi_out -- receives a malloc'd "Message-Instance: ..." field, or NULL when
**  	          none is added (re-signing); may itself be set to NULL
**  	sig_out -- receives a malloc'd "DKIM2-Signature: ..." field
**
**  Return value:
**  	0 on success (caller frees *mi_out and *sig_out), -1 on error.
*/
extern int dkim2_sign(const dkim2_sign_params_t *p,
                      const char *const *headers, size_t nheaders,
                      const char *body, size_t bodylen,
                      char **mi_out, char **sig_out);

/*
**  DKIM2_CANON_FIELD_85 -- canonicalize one header field per Section 8.5:
**  lowercase the field name, delete every WSP/CR/LF in the value, and retain
**  the colon and a single trailing CRLF.  Used to build the signing input by
**  both the signer and the verifier.
**
**  Parameters:
**  	field -- "Name: value" with no trailing CRLF
**
**  Return value:
**  	malloc'd "name:value\r\n", or NULL on error / no colon.
*/
extern char *dkim2_canon_field_85(const char *field);

#endif /* PHOENIXDKIM_DKIM2_SIGN_H */
