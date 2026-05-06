/*
**  Copyright (c) 2008, 2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2013, The Trusted Domain Project.
**    All rights reserved.
**
**    Copyright (c) 2026, OpenDKIM contributors. All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* opendkim includes */
#include "opendkim-crypto.h"
#include "opendkim.h"

/* globals */
static _Bool crypto_init_done = FALSE;

/*
**  DKIMF_CRYPTO_INIT -- set up openssl dependencies
**
**  OpenSSL 3 is self-initialising; no application-level setup is required.
**
**  Parameters:
**  	None.
**
**  Return value:
**  	0 -- success
*/

int
dkimf_crypto_init(void)
{
	crypto_init_done = TRUE;
	return 0;
}

/*
**  DKIMF_CRYPTO_FREE -- tear down openssl dependencies
**
**  OpenSSL 3 performs its own cleanup via atexit; nothing to do here.
**
**  Parameters:
**  	None.
**
**  Return value:
**  	None.
*/

void
dkimf_crypto_free(void)
{
	crypto_init_done = FALSE;
}
