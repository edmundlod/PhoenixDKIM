/*
**  dkim2-eml.h -- minimal RFC 5322 message splitter for the DKIM2 test CLIs.
**
**  Splits a raw message into its header fields and body in the form the DKIM2
**  sign/verify API expects: each header field is "Name: value" with any folding
**  (CRLF + WSP) preserved and no trailing CRLF; the body is the octets after the
**  empty separator line.  Line endings are normalized to CRLF so a file saved
**  with bare LFs still hashes canonically.
**
**  This lives with the standalone tools, not the milter, which receives headers
**  and body through the milter API instead of parsing a file.
*/

#ifndef PHOENIXDKIM_DKIM2_EML_H
#define PHOENIXDKIM_DKIM2_EML_H

#include <stddef.h>

typedef struct dkim2_eml
{
	char	**em_headers;	/* array of "Name: value" fields */
	size_t	  em_nheaders;
	char	 *em_body;	/* message body (CRLF-normalized) */
	size_t	  em_bodylen;
} dkim2_eml_t;

/*
**  DKIM2_EML_PARSE -- parse a raw message.
**  Returns a heap structure (free with dkim2_eml_free()) or NULL on error.
*/
extern dkim2_eml_t *dkim2_eml_parse(const char *data, size_t len);

extern void dkim2_eml_free(dkim2_eml_t *eml);

#endif /* PHOENIXDKIM_DKIM2_EML_H */
