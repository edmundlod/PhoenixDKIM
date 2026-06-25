/*
**  dkim2-hash.h -- DKIM2 body and header field hashing (draft-ietf-dkim-dkim2
**  Section 5).
**
**  DKIM2 records the message in a set of SHA-256 hashes carried in the h= tag
**  of a Message-Instance header field:
**
**    * the body hash (Section 5.1) uses DKIM1's "simple" body canonicalization;
**    * the header fields hash (Section 5.2) ignores a fixed set of header
**      fields, then lowercases names, unfolds, collapses whitespace, sorts
**      alphabetically (same-name fields kept bottom-up), and hashes the result.
**
**  Only SHA-256 is defined by the spec; both signing algorithms (RSA and
**  Ed25519) hash with it.
*/

#ifndef PHOENIXDKIM_DKIM2_HASH_H
#define PHOENIXDKIM_DKIM2_HASH_H

#include <stddef.h>

/* SHA-256 digest length in bytes. */
#define DKIM2_HASH_LEN 32

/*
**  DKIM2_BODY_HASH -- SHA-256 of the canonicalized message body (Section 5.1).
**
**  Canonicalization is DKIM1 "simple": all empty lines at the end of the body
**  are ignored and exactly one trailing CRLF is guaranteed (an empty body
**  hashes as a single CRLF).
**
**  Parameters:
**  	body -- the raw message body octets (may be NULL iff bodylen is 0)
**  	bodylen -- length of body in bytes
**  	digest -- DKIM2_HASH_LEN-byte output buffer
**
**  Return value:
**  	0 on success, -1 on a crypto error.
*/
extern int dkim2_body_hash(const char *body, size_t bodylen,
                           unsigned char digest[DKIM2_HASH_LEN]);

/*
**  DKIM2_BODY_TO_CRLF -- normalize a body to canonical CRLF line endings.
**
**  DKIM2 body hashes are defined over the on-the-wire (CRLF) form, but a milter
**  receives the body in its MTA's internal representation -- Postfix, for one,
**  presents bare LF.  Converting lone LF and lone CR to CRLF lets the body hash
**  match a CRLF signature regardless of how the MTA delivered the bytes, and is
**  idempotent for already-CRLF input.  The DKIM1 path gets this from libopendkim
**  (DKIM_LIBFLAGS_FIXCRLF); the DKIM2 hasher must apply it before hashing.
**
**  Parameters:
**  	in / inlen -- the raw body octets (in may be NULL iff inlen is 0)
**  	out -- receives a malloc'd NUL-terminated CRLF copy (caller frees)
**  	outlen -- receives the length of *out in bytes
**
**  Return value:
**  	0 on success, -1 on allocation failure.
*/
extern int dkim2_body_to_crlf(const char *in, size_t inlen,
                              char **out, size_t *outlen);

/*
**  DKIM2_HEADER_HASH -- SHA-256 of the canonicalized header fields (Section 5.2).
**
**  Parameters:
**  	headers -- array of header field strings, each the complete "Name: value"
**  	           field as it appeared, with any folding (CRLF + WSP) preserved
**  	           and with no trailing CRLF
**  	nheaders -- number of entries in headers
**  	digest -- DKIM2_HASH_LEN-byte output buffer
**
**  The ignored fields (Received, Return-Path, Authentication-Results, X-*,
**  DKIM-Signature, ARC-*, Message-Instance, DKIM2-Signature) are dropped, and a
**  field with no colon is skipped.
**
**  Return value:
**  	0 on success, -1 on allocation or crypto error.
*/
extern int dkim2_header_hash(const char *const *headers, size_t nheaders,
                             unsigned char digest[DKIM2_HASH_LEN]);

/*
**  DKIM2_HEADER_IS_SIGNED -- whether a header field name is included in the
**  header hash (i.e. is NOT on the Section 5.2 ignore list).
**
**  Parameters:
**  	name -- header field name (without the colon); matched case-insensitively
**
**  Return value:
**  	1 if the field participates in the header hash, 0 if it is ignored.
*/
extern int dkim2_header_is_signed(const char *name);

#endif /* PHOENIXDKIM_DKIM2_HASH_H */
