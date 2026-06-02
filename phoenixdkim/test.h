/*
**  Copyright (c) 2007 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _TEST_H_
#define _TEST_H_

/* system includes */
#include <sys/param.h>
#include <sys/types.h>

/* libmilter includes */
#include <libmilter/mfapi.h>

/* libphoenixdkim includes */
#include "dkim.h"

/* PROTOTYPES */
extern int dkimf_testfiles(DKIM_LIB *, char *, uint64_t, bool, int);

extern int dkimf_test_addheader(void *, const char *, const char *);
extern int dkimf_test_addrcpt(void *, char *);
extern int dkimf_test_chgheader(void *, char *, int, char *);
extern int dkimf_test_delrcpt(void *, char *);
extern void *dkimf_test_getpriv(void *);
extern char *dkimf_test_getsymval(void *, const char *);
extern int dkimf_test_insheader(void *, int, const char *, const char *);
extern int dkimf_test_progress(void *);
extern int dkimf_test_quarantine(void *, const char *);
extern int dkimf_test_setpriv(void *, void *);
extern int dkimf_test_setreply(void *, const char *, const char *,
                                    const char *);

#endif /* _TEST_H_ */
