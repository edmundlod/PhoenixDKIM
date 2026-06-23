/*
**  dkim2-header.h -- structured model of the DKIM2-Signature and
**  Message-Instance header fields (draft-ietf-dkim-dkim2-spec Sections 6 & 7).
**
**  Both header fields are RFC 6376-style tag-value lists.  This module turns a
**  header field value into a struct (and back), splitting the flat sub-fields
**  the core profile uses:
**
**    DKIM2-Signature: i= m= t= mf= rt= d= s= [n=] [f=]
**      mf= / rt=  base64 of the SMTP reverse-/forward-path (rt= comma-separated)
**      s=         comma-separated "selector:algorithm:base64-signature" triples
**
**    Message-Instance: m= h= [r=]
**      h=         comma-separated "hash-name:header-hash:body-hash" triples
**      r=         base64-JSON recipes (extended profile; carried opaquely here)
**
**  Verification reconstructs its signing input from the raw received header
**  bytes, not from these structs (see dkim2-verify); this model is for reading
**  fields and for emitting freshly-built headers when signing.
*/

#ifndef PHOENIXDKIM_DKIM2_HEADER_H
#define PHOENIXDKIM_DKIM2_HEADER_H

#include <stddef.h>
#include <stdint.h>

/* One entry of a DKIM2-Signature s= tag: selector:algorithm:signature. */
typedef struct dkim2_sigentry
{
	char			*se_selector;
	char			*se_alg;	/* e.g. "rsa-sha256" */
	char			*se_sig;	/* base64 signature ("" if not yet signed) */
	struct dkim2_sigentry	*se_next;
} dkim2_sigentry_t;

/* A parsed DKIM2-Signature header field value. */
typedef struct dkim2_signature
{
	uint64_t	 sig_i;		/* hop sequence number */
	uint64_t	 sig_m;		/* highest Message-Instance number covered */
	uint64_t	 sig_t;		/* timestamp (seconds since the epoch) */
	char		*sig_mf;	/* base64 reverse-path */
	char		**sig_rt;	/* base64 forward-paths */
	size_t		 sig_rt_count;
	char		*sig_d;		/* signing domain */
	dkim2_sigentry_t *sig_s;	/* signature set (one or more) */
	char		*sig_n;		/* nonce, or NULL */
	char		*sig_f;		/* raw flags value, or NULL */
} dkim2_signature_t;

/* One entry of a Message-Instance h= tag: name:header-hash:body-hash. */
typedef struct dkim2_hashentry
{
	char			*he_name;	/* e.g. "sha256" */
	char			*he_header;	/* base64 header hash */
	char			*he_body;	/* base64 body hash */
	struct dkim2_hashentry	*he_next;
} dkim2_hashentry_t;

/* A parsed Message-Instance header field value. */
typedef struct dkim2_mi
{
	uint64_t	 mi_m;		/* revision number */
	dkim2_hashentry_t *mi_h;	/* hash set (one or more) */
	char		*mi_r;		/* base64-JSON recipes, or NULL */
} dkim2_mi_t;

/*
**  DKIM2_SIGNATURE_PARSE -- parse a DKIM2-Signature header field value.
**
**  Parameters:
**  	value -- the tag-value text after "DKIM2-Signature:" (need not be
**  	         NUL-terminated)
**  	len -- length of value in bytes
**
**  Return value:
**  	A heap struct, or NULL on a malformed list or a missing required tag
**  	(i, m, t, mf, rt, d, s).  Free with dkim2_signature_free().
*/
extern dkim2_signature_t *dkim2_signature_parse(const char *value, size_t len);

/*
**  DKIM2_SIGNATURE_FORMAT -- serialize a signature back to a tag-value string.
**
**  Emits "i=..; m=..; t=..; mf=..; rt=..; d=..; s=..;" (plus n=/f= when set),
**  each tag terminated by ';' as the ABNF requires.  Returns a heap string the
**  caller must free(), or NULL on error.
*/
extern char *dkim2_signature_format(const dkim2_signature_t *sig);

/*
**  DKIM2_SIGNATURE_FREE -- release a signature (NULL is a no-op).
*/
extern void dkim2_signature_free(dkim2_signature_t *sig);

/*
**  DKIM2_MI_PARSE / DKIM2_MI_FORMAT / DKIM2_MI_FREE -- the same three
**  operations for a Message-Instance header field value.  Required tags are m=
**  and h=.
*/
extern dkim2_mi_t *dkim2_mi_parse(const char *value, size_t len);
extern char *dkim2_mi_format(const dkim2_mi_t *mi);
extern void dkim2_mi_free(dkim2_mi_t *mi);

#endif /* PHOENIXDKIM_DKIM2_HEADER_H */
