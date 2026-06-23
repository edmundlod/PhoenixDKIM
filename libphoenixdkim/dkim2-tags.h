/*
**  dkim2-tags.h -- DKIM2 tag=value list parser.
**
**  DKIM2 (draft-ietf-dkim-dkim2-spec) headers -- DKIM2-Signature and
**  Message-Instance -- are RFC 6376-style tag-value lists:
**
**      tag = value ; tag = value ; ...
**
**  This is a small, self-contained parser for *logical* tag access (look a tag
**  up by name).  It is deliberately independent of the DKIM1 DKIM_SET machinery
**  so the DKIM2 modules can be built and reasoned about in isolation.
**
**  It is NOT used to reconstruct the signing input: per the spec the verifier
**  must hash the raw received header bytes (blanking the signature in place),
**  not a re-serialization of parsed tags.  That lives in the verify module.
*/

#ifndef PHOENIXDKIM_DKIM2_TAGS_H
#define PHOENIXDKIM_DKIM2_TAGS_H

#include <stddef.h>

/* A single tag=value pair.  name and value are NUL-terminated, with leading and
** trailing whitespace (SP/HTAB/CR/LF) removed.  An empty value (tag=;) yields a
** zero-length value string, not NULL. */
typedef struct dkim2_tag
{
	char			*t_name;
	char			*t_value;
	struct dkim2_tag	*t_next;
} dkim2_tag_t;

/* An ordered list of tags, preserving the order they appeared in the header.
** Order matters for DKIM2 (e.g. multiple s= signature entries). */
typedef struct dkim2_taglist
{
	dkim2_tag_t	*tl_head;
	dkim2_tag_t	*tl_tail;
} dkim2_taglist_t;

/*
**  DKIM2_TAGLIST_PARSE -- parse a tag-value list.
**
**  Parameters:
**  	s -- start of the tag-value text (need not be NUL-terminated)
**  	len -- length of the text in bytes
**
**  Return value:
**  	A heap-allocated tag list, or NULL on allocation failure or a malformed
**  	list (a non-empty segment with no '=').  A single trailing ';' and
**  	whitespace-only segments are tolerated.  Free with dkim2_taglist_free().
**
**  Tag names are matched case-sensitively (RFC 6376 Section 3.2); DKIM2 tag
**  names are lower case.
*/
extern dkim2_taglist_t *dkim2_taglist_parse(const char *s, size_t len);

/*
**  DKIM2_TAGLIST_FREE -- release a tag list (NULL is a no-op).
*/
extern void dkim2_taglist_free(dkim2_taglist_t *tl);

/*
**  DKIM2_TAGLIST_GET -- value of the first tag named `name`, or NULL if absent.
*/
extern const char *dkim2_taglist_get(const dkim2_taglist_t *tl,
                                     const char *name);

/*
**  DKIM2_TAGLIST_COUNT -- number of tags in the list.
*/
extern size_t dkim2_taglist_count(const dkim2_taglist_t *tl);

#endif /* PHOENIXDKIM_DKIM2_TAGS_H */
