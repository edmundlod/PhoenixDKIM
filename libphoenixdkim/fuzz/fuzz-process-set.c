/*
**  Copyright (c) 2026, PhoenixDKIM contributors.
**    All rights reserved.
**
**  Coverage-guided fuzz target for dkim_process_set(), the single tag-list
**  parser PhoenixDKIM uses for BOTH attacker-controlled inputs:
**
**    * the DKIM-Signature header  (DKIM_SETTYPE_SIGNATURE) — every byte of
**      which is supplied by whoever sent the message, and
**    * the public-key TXT record  (DKIM_SETTYPE_KEY) — supplied by whoever
**      controls the signing domain's DNS, including a compromised zone.
**
**  The set type is selected at compile time via -DFUZZ_SETTYPE so the same
**  source builds two independent targets (fuzz-sig, fuzz-key).
**
**  We parse with syntax-only mode (the "syntax" argument set TRUE): that
**  validates structure without attaching the parsed set to the handle, so a
**  single long-lived DKIM handle can be reused across millions of inputs with
**  no per-iteration state to leak — exactly what AddressSanitizer/LeakSanitizer
**  want to see.  Build with -DPHOENIXDKIM_ENABLE_ASAN=ON so memory errors in the
**  parser surface as crashes the fuzzer can minimise.
*/

#include "build-config.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../dkim.h"
#include "../dkim-internal.h"

#ifndef FUZZ_SETTYPE
# define FUZZ_SETTYPE DKIM_SETTYPE_SIGNATURE
#endif

static DKIM_LIB *lib;
static DKIM *dkim;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	DKIM_STAT status;

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
		abort();

	/*
	**  A verify handle is the natural context for parsing inbound material;
	**  it is reused for every input because syntax-only parsing does not
	**  mutate it.
	*/
	dkim = dkim_verify(lib, "fuzz", NULL, &status);
	if (dkim == NULL)
		abort();

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	u_char *buf;

	/* dkim_process_set() asserts str != NULL; nothing to do for empty input */
	if (size == 0)
		return 0;

	/*
	**  Real callers always hand the parser a NUL-terminated C string whose
	**  length is strlen().  Reproduce that contract exactly: copy the fuzz
	**  bytes into a size+1 heap buffer with a trailing NUL.  ASan's redzone
	**  then catches any read past the terminator — a genuine bug — without
	**  manufacturing false positives from a deliberately unterminated buffer.
	*/
	buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	(void) dkim_process_set(dkim, (dkim_set_t) FUZZ_SETTYPE, buf, size,
	                        NULL, TRUE, NULL);

	free(buf);
	return 0;
}
