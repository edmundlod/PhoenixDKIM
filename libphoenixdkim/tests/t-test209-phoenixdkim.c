/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011-2013, The Trusted Domain Project.
**    All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
*/

/*
**  t-test209-phoenixdkim -- RFC 8616 (EAI) header field-body handling in
**  dkim_header().  A PhoenixDKIM-modified fork of upstream's t-test209.
**
**  Prior to EAI support, any byte > 0x7E in a field body returned
**  DKIM_STAT_SYNTAX.  PhoenixDKIM accepts well-formed UTF-8 (the UTF8-2/3/4
**  productions of RFC 3629) in field bodies, and -- unlike OpenDKIM's
**  blanket "accept any byte >= 0x80" -- it still REJECTS malformed UTF-8
**  (lone continuation bytes, overlong encodings, truncated sequences,
**  UTF-16 surrogates and out-of-range lead bytes).  Header field NAMES
**  remain ASCII-only, as RFC 8616 requires.
**
**  All test strings below are NUL-terminated and contain no embedded NUL,
**  so strlen() yields the correct byte length including the UTF-8 octets.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef USE_GNUTLS
# include <gnutls/gnutls.h>
#endif /* USE_GNUTLS */

/* libopendkim includes */
#include "../dkim.h"
#include "t-testdata.h"

/*
**  CHECK_HEADER -- feed one header to a fresh verify handle and assert the
**                  status dkim_header() returns.
*/

static void
check_header(DKIM_LIB *lib, const char *label, const char *hdr, DKIM_STAT want)
{
	DKIM_STAT status;
	DKIM *dkim;

	dkim = dkim_verify(lib, JOBID, NULL, &status);
	assert(dkim != NULL);

	status = dkim_header(dkim, (const u_char *) hdr, strlen(hdr));
	printf("    %-34s status=%d (want %d)\n", label, status, want);
	assert(status == want);

	(void) dkim_free(dkim);
}

int
main(int argc, char **argv)
{
	DKIM_LIB *lib;

	printf("*** RFC 8616 (EAI): UTF-8 in header field bodies\n");

#ifdef USE_GNUTLS
	(void) gnutls_global_init();
#endif /* USE_GNUTLS */

	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

	/* ---- well-formed UTF-8 in the field body is ACCEPTED ---- */

	/* 2-byte: "Héllo wörld" (é = C3 A9, ö = C3 B6) */
	check_header(lib, "2-byte UTF-8 (Latin-1 suppl.)",
	             "Subject: H\xc3\xa9llo w\xc3\xb6rld", DKIM_STAT_OK);

	/* 3-byte: euro sign U+20AC = E2 82 AC */
	check_header(lib, "3-byte UTF-8 (U+20AC euro)",
	             "Subject: 100\xe2\x82\xac", DKIM_STAT_OK);

	/* 4-byte: U+1F600 grinning face = F0 9F 98 80 */
	check_header(lib, "4-byte UTF-8 (U+1F600 emoji)",
	             "Subject: \xf0\x9f\x98\x80", DKIM_STAT_OK);

	/* ---- malformed UTF-8 is REJECTED (beyond OpenDKIM) ---- */

	/* lone continuation byte */
	check_header(lib, "lone continuation byte",
	             "Subject: x\x80y", DKIM_STAT_SYNTAX);

	/* overlong encoding of NUL (C0 80) */
	check_header(lib, "overlong encoding",
	             "Subject: x\xc0\x80", DKIM_STAT_SYNTAX);

	/* truncated 2-byte sequence at end of input */
	check_header(lib, "truncated sequence",
	             "Subject: x\xc3", DKIM_STAT_SYNTAX);

	/* UTF-16 surrogate U+D800 (ED A0 80) */
	check_header(lib, "UTF-16 surrogate",
	             "Subject: x\xed\xa0\x80", DKIM_STAT_SYNTAX);

	/* out-of-range lead byte (> U+10FFFF) */
	check_header(lib, "out-of-range lead byte",
	             "Subject: x\xf5\x80\x80\x80", DKIM_STAT_SYNTAX);

	/* ---- field NAMES remain ASCII-only ---- */

	/*
	**  UTF-8 in the field name (before the colon) is rejected.  The
	**  string is split so the "ct" after \xa9 is not swallowed into the
	**  hex escape (\xa9c would otherwise be one out-of-range escape).
	*/
	check_header(lib, "non-ASCII field name",
	             "Subj\xc3\xa9" "ct: value", DKIM_STAT_SYNTAX);

	dkim_close(lib);

	return 0;
}
