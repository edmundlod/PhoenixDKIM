/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2011, 2012, The Trusted Domain Project.
**    All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors.
**    All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>


/* libphoenixdkim includes */
#include "../dkim.h"
#include "t-testdata.h"

#define	MAXHEADER	4096

#define SIG2 "v=1; a=rsa-sha256; c=relaxed/simple; d=example.com; s=test;\r\n\tt=1172620939; bh=yHBAX+3IwxTZIynBuB/5tlsBInJq9n8qz5fgAycHi80=;\r\n\th=Received:Received:Received:From:To:Date:Subject:Cc:Message-ID;\r\n\tb=Wjssxvz8WUX0uxKnhVpVGBbmWfwB7LNYThP7AuN7bse5OnglHluNcc0ZjDN9K3aT3\r\n\t xJgFnz7ArjWei2NnzYoKbWzcPKlf5XWeSC0d7nHRDTXGlQDGD/BXoTy+tvfgMJnDvV\r\n\t uqAAfpoMdyaknmlEoAZeGBXGBRo/bFYGQf0smvqc="

#define	XHDRNAME	"Cc: "
#define	XHDRADDR	"nosuchuser@nosuchdomain.com"
#define	XHDRVALEOL	",\r\n\t"
#define	XHDRREPEAT	151

/*
**  The Cc: header is XHDRNAME, then XHDRREPEAT copies of "XHDRADDR XHDRVALEOL",
**  then a trailing XHDRADDR -- about 4.7 KB.  That exceeds the 4095-byte string
**  literal limit every ISO C standard since C99 guarantees (§5.2.4.1), which
**  -pedantic-errors enforces, so it is assembled at run time in main() rather
**  than written as one literal.
*/
#define	XHEADERCC_LEN	(sizeof(XHDRNAME) - 1 + \
			 XHDRREPEAT * (sizeof(XHDRADDR) - 1 + sizeof(XHDRVALEOL) - 1) + \
			 sizeof(XHDRADDR) - 1)

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	The usual.
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
#ifdef TEST_KEEP_FILES
	u_int flags;
#endif /* TEST_KEEP_FILES */
	DKIM_STAT status;
	uint64_t fixed_time;
	DKIM *dkim;
	DKIM_LIB *lib;
	dkim_sigkey_t key;
	unsigned char hdr[MAXHEADER + 1];
	unsigned char xheadercc[XHEADERCC_LEN + 1];

	printf("*** relaxed/simple rsa-sha1 signing with large headers\n");


	/* instantiate the library */
	lib = dkim_init(NULL, NULL);
	assert(lib != NULL);

#ifdef TEST_KEEP_FILES
	/* set flags */
	flags = (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_setopt(lib, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);
#endif /* TEST_KEEP_FILES */

	key = KEY;

	dkim = dkim_sign(lib, JOBID, NULL, key, SELECTOR, DOMAIN,
	                 DKIM_CANON_RELAXED, DKIM_CANON_SIMPLE,
	                 DKIM_SIGN_RSASHA256, -1L, &status);
	assert(dkim != NULL);

	/* fix signing time */
	fixed_time = 1172620939;
	(void) dkim_setopt(lib, DKIM_OPTS_FIXEDTIME,
	                    &fixed_time, sizeof fixed_time);

	status = dkim_header(dkim, HEADER02, strlen(HEADER02));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER03, strlen(HEADER03));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER04, strlen(HEADER04));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER05, strlen(HEADER05));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER06, strlen(HEADER06));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER07, strlen(HEADER07));
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER08, strlen(HEADER08));
	assert(status == DKIM_STAT_OK);

	/* assemble the oversized Cc: header (see XHEADERCC_LEN) at run time */
	{
		size_t xclen = 0;
		int n;

		memcpy(xheadercc, XHDRNAME, sizeof(XHDRNAME) - 1);
		xclen += sizeof(XHDRNAME) - 1;
		for (n = 0; n < XHDRREPEAT; n++)
		{
			memcpy(xheadercc + xclen, XHDRADDR, sizeof(XHDRADDR) - 1);
			xclen += sizeof(XHDRADDR) - 1;
			memcpy(xheadercc + xclen, XHDRVALEOL, sizeof(XHDRVALEOL) - 1);
			xclen += sizeof(XHDRVALEOL) - 1;
		}
		memcpy(xheadercc + xclen, XHDRADDR, sizeof(XHDRADDR) - 1);
		xclen += sizeof(XHDRADDR) - 1;
		xheadercc[xclen] = '\0';

		status = dkim_header(dkim, xheadercc, xclen);
	}
	assert(status == DKIM_STAT_OK);

	status = dkim_header(dkim, HEADER09, strlen(HEADER09));
	assert(status == DKIM_STAT_OK);

	status = dkim_eoh(dkim);
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY00, strlen(BODY00));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01, strlen(BODY01));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY01A, strlen(BODY01A));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01B, strlen(BODY01B));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01C, strlen(BODY01C));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01D, strlen(BODY01D));
	assert(status == DKIM_STAT_OK);
	status = dkim_body(dkim, BODY01E, strlen(BODY01E));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY02, strlen(BODY02));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY04, strlen(BODY04));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY05, strlen(BODY05));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_body(dkim, BODY03, strlen(BODY03));
	assert(status == DKIM_STAT_OK);

	status = dkim_eom(dkim, NULL);
	assert(status == DKIM_STAT_OK);

	memset(hdr, '\0', sizeof hdr);
	status = dkim_getsighdr(dkim, hdr, sizeof hdr,
	                        strlen(DKIM_SIGNHEADER) + 2);
	assert(status == DKIM_STAT_OK);
	fprintf(stderr, "ACTUAL: %s\n", hdr); fflush(stderr); assert(strcmp(SIG2, hdr) == 0);
	
	status = dkim_free(dkim);
	assert(status == DKIM_STAT_OK);

	dkim_close(lib);

	return 0;
}
