/*
**  dkim2-recipe.h -- DKIM2 body and header recipes (draft-ietf-dkim-dkim2-spec
**  Sections 4 & 9.2; the "extended" profile).
**
**  A modifying intermediary (a mailing list, a corporate gateway) that rewrites
**  a message records a reversible diff -- a "recipe" -- on the Message-Instance
**  it adds.  The recipe reconstructs the *previous* instance from the *current*
**  one, so a verifier can walk the chain backward and re-check every hop's
**  hashes even though the bytes changed in flight.
**
**  A recipe is a JSON object, base64-encoded into the Message-Instance r= tag:
**
**    {"h": {"<field-name>": [ops]}, "b": [ops]}
**
**  with "h": null marking an irreversible modification.  Operations are
**  line/field-ordinal based, never byte offsets:
**
**    {"c":[start,end]}   copy field-instances (under h) or body lines (under b)
**                        numbered start..end inclusive from the *current* message
**    {"d":["literal",…]} insert literal data present only in the older version
**
**  Ordinals are 1-based and inclusive; the body is split into CRLF-delimited
**  lines and headers into the field-instances of one name.  This module owns the
**  recipe model and the line-split convention; sign/verify use it through the
**  apply/generate entry points.
*/

#ifndef PHOENIXDKIM_DKIM2_RECIPE_H
#define PHOENIXDKIM_DKIM2_RECIPE_H

#include <stddef.h>

typedef enum
{
	DKIM2_ROP_COPY,		/* copy ordinals start..end from the current message */
	DKIM2_ROP_DATA		/* insert literal data from the older version */
} dkim2_ropt_t;

/* One recipe operation. */
typedef struct dkim2_recipe_op
{
	dkim2_ropt_t		 ro_type;
	size_t			 ro_start;	/* COPY: 1-based inclusive start */
	size_t			 ro_end;	/* COPY: 1-based inclusive end */
	char			**ro_data;	/* DATA: literal strings */
	size_t			 ro_ndata;
	struct dkim2_recipe_op	*ro_next;
} dkim2_recipe_op_t;

/* The op list rebuilding one header field name's instance sequence. */
typedef struct dkim2_recipe_hdr
{
	char			*rh_name;	/* lowercased field name */
	dkim2_recipe_op_t	*rh_ops;
	struct dkim2_recipe_hdr	*rh_next;
} dkim2_recipe_hdr_t;

/* A parsed recipe. */
typedef struct dkim2_recipe
{
	int			 re_null;	/* 1 = irreversible ("h":null) */
	dkim2_recipe_hdr_t	*re_hdrs;	/* header recipes (NULL = unchanged) */
	dkim2_recipe_op_t	*re_body;	/* body ops (NULL = unchanged) */
} dkim2_recipe_t;

/*
**  DKIM2_RECIPE_PARSE -- decode a base64-JSON r= value into a recipe.
**
**  Parameters:
**  	b64 -- the r= tag value (need not be NUL-terminated)
**  	len -- length of b64 in bytes
**
**  Return value:
**  	A heap recipe (free with dkim2_recipe_free()), or NULL on a base64 error,
**  	invalid JSON, or a malformed operation.  Consumes untrusted input.
*/
extern dkim2_recipe_t *dkim2_recipe_parse(const char *b64, size_t len);

/*
**  DKIM2_RECIPE_FORMAT -- serialize a recipe back to a base64-JSON string.
**
**  Returns a NUL-terminated heap string the caller must free(), or NULL on
**  error.  The JSON is emitted unformatted so the output is signing-stable.
*/
extern char *dkim2_recipe_format(const dkim2_recipe_t *r);

/*
**  DKIM2_RECIPE_FREE -- release a recipe (NULL is a no-op).
*/
extern void dkim2_recipe_free(dkim2_recipe_t *r);

/*
**  DKIM2_RECIPE_APPLY -- reconstruct the previous instance from the current one.
**
**  Body is split on CRLF into 1-based lines; the body ops rebuild it.  Only the
**  field names listed in the recipe have their instance sequence rebuilt; every
**  other header field is copied through unchanged.
**
**  Parameters:
**  	r -- the recipe
**  	cur_hdrs / cur_nh -- the current message's "Name: value" header fields
**  	cur_body / cur_blen -- the current message's raw body
**  	prev_hdrs / prev_nh -- receive the reconstructed header array (caller frees
**  	                       each entry and the array)
**  	prev_body / prev_blen -- receive the reconstructed body (caller frees)
**
**  Return value:
**  	0 on success, 1 when the recipe is irreversible (re_null: outputs are not
**  	set and the caller stops the backward walk), -1 on error or an
**  	out-of-range ordinal.
*/
extern int dkim2_recipe_apply(const dkim2_recipe_t *r,
                              const char *const *cur_hdrs, size_t cur_nh,
                              const char *cur_body, size_t cur_blen,
                              char ***prev_hdrs, size_t *prev_nh,
                              char **prev_body, size_t *prev_blen);

/*
**  DKIM2_RECIPE_GENERATE -- produce a recipe reconstructing old from new.
**
**  The body is line-diffed (longest-common-subsequence): matched runs become
**  copy ops over new's lines, old-only runs become data ops.  Headers are
**  diffed per field name; a recipe entry is emitted only for names whose
**  instance sequence differs.  Identical body or headers leave the corresponding
**  member NULL (unchanged).
**
**  Return value:
**  	A heap recipe (free with dkim2_recipe_free()), or NULL on error.
*/
extern dkim2_recipe_t *dkim2_recipe_generate(const char *const *old_hdrs,
                                             size_t old_nh,
                                             const char *old_body,
                                             size_t old_blen,
                                             const char *const *new_hdrs,
                                             size_t new_nh,
                                             const char *new_body,
                                             size_t new_blen);

#endif /* PHOENIXDKIM_DKIM2_RECIPE_H */
