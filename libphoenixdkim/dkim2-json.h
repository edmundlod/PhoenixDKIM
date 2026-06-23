/*
**  dkim2-json.h -- base64-encoded JSON helpers for DKIM2.
**
**  draft-ietf-dkim-dkim2-spec carries several structured tag values as JSON
**  that is then base64-encoded into the tag: the DKIM2-Signature s= signature
**  set, and the Message-Instance h= hashes and r= recipes.  These helpers wrap
**  the project base64 codec (base64.c) and cJSON so the header model and
**  sign/verify modules can move between a tag's base64 text and a cJSON tree
**  without repeating the encode/decode dance.
*/

#ifndef PHOENIXDKIM_DKIM2_JSON_H
#define PHOENIXDKIM_DKIM2_JSON_H

#include <stddef.h>

#include <cjson/cJSON.h>

/*
**  DKIM2_JSON_B64_DECODE -- base64-decode then JSON-parse a tag value.
**
**  Parameters:
**  	b64 -- base64 text (need not be NUL-terminated; embedded folding
**  	       whitespace is ignored by the decoder)
**  	len -- length of b64 in bytes
**
**  Return value:
**  	A parsed cJSON tree the caller must release with cJSON_Delete(), or NULL
**  	on allocation failure, a base64 error, or invalid JSON.
*/
extern cJSON *dkim2_json_b64_decode(const char *b64, size_t len);

/*
**  DKIM2_JSON_B64_ENCODE -- compact-serialize JSON then base64-encode it.
**
**  Parameters:
**  	json -- the cJSON tree to encode
**
**  Return value:
**  	A NUL-terminated, heap-allocated base64 string the caller must free(),
**  	or NULL on allocation failure.  The JSON is emitted unformatted (no
**  	insignificant whitespace) so the output is stable for signing.
*/
extern char *dkim2_json_b64_encode(const cJSON *json);

#endif /* PHOENIXDKIM_DKIM2_JSON_H */
