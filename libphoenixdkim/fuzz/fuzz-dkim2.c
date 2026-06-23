/*
**  Copyright (c) 2026, PhoenixDKIM contributors.
**    All rights reserved.
**
**  Coverage-guided fuzz targets for the DKIM2 parsers that consume
**  attacker-controlled bytes:
**
**    fuzz-dkim2-tags  the tag=value list parser   (every DKIM2 header value)
**    fuzz-dkim2-sig   the DKIM2-Signature parser   (message sender controls it)
**    fuzz-dkim2-mi    the Message-Instance parser  (message sender controls it)
**    fuzz-dkim2-key   the DNS key-record parser    (signing-domain DNS controls it)
**    fuzz-dkim2-json  the base64-JSON decoder      (recipe values; cJSON path)
**
**  One source builds all five, selected at compile time by FUZZ_DKIM2_TARGET.
**  The parsers are self-contained and own their output, so each iteration parses
**  then frees with no shared state -- what ASan/LeakSanitizer want to see.  Build
**  with -DPHOENIXDKIM_ENABLE_FUZZERS=ON (Clang + ASan).
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DKIM2_TAGS	1
#define FUZZ_DKIM2_SIG	2
#define FUZZ_DKIM2_MI	3
#define FUZZ_DKIM2_KEY	4
#define FUZZ_DKIM2_JSON	5

#ifndef FUZZ_DKIM2_TARGET
# define FUZZ_DKIM2_TARGET FUZZ_DKIM2_TAGS
#endif

#if FUZZ_DKIM2_TARGET == FUZZ_DKIM2_TAGS
# include "../dkim2-tags.h"
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_SIG || FUZZ_DKIM2_TARGET == FUZZ_DKIM2_MI
# include "../dkim2-header.h"
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_KEY
# include "../dkim2-dns.h"
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_JSON
# include "../dkim2-json.h"
#endif

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* a NUL-terminated copy: some parsers take a NUL-terminated string, and
	** giving the length-based ones a terminator too costs nothing */
	char *s = malloc(size + 1);

	if (s == NULL)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

#if FUZZ_DKIM2_TARGET == FUZZ_DKIM2_TAGS
	dkim2_taglist_free(dkim2_taglist_parse(s, size));
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_SIG
	dkim2_signature_free(dkim2_signature_parse(s, size));
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_MI
	dkim2_mi_free(dkim2_mi_parse(s, size));
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_KEY
	dkim2_keyrecord_free(dkim2_keyrecord_parse(s));
#elif FUZZ_DKIM2_TARGET == FUZZ_DKIM2_JSON
	{
		cJSON *j = dkim2_json_b64_decode(s, size);

		if (j != NULL)
			cJSON_Delete(j);
	}
#endif

	free(s);
	return 0;
}
