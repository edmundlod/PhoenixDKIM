/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009, 2012, The Trusted Domain Project.  All rights reserved.
**
**  Copyright (c) 2026, OpenDKIM contributors. All rights reserved.
**
*/

#ifndef _DKIM_CRYPTO_H_
#define _DKIM_CRYPTO_H_

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* PROTOTYPES */
extern int dkimf_crypto_init __P((void));
extern void dkimf_crypto_free __P((void));

#endif /* _DKIM_CRYPTO_H_ */
