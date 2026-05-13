/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**      All rights reserved.
**
**  Copyright (c) 2009-2013, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _OPENDKIM_DB_H_
#define _OPENDKIM_DB_H_

/* system includes */
#include <sys/types.h>
#include <pthread.h>

/* macros */
#define	DKIMF_DB_FLAG_READONLY	0x0001
#define	DKIMF_DB_FLAG_ICASE	0x0002
#define	DKIMF_DB_FLAG_MATCHBOTH	0x0004
#define	DKIMF_DB_FLAG_VALLIST	0x0008
#define	DKIMF_DB_FLAG_USETLS	0x0010
#define	DKIMF_DB_FLAG_MAKELOCK	0x0020
#define	DKIMF_DB_FLAG_ASCIIONLY	0x0040
#define	DKIMF_DB_FLAG_NOFDLOCK	0x0080
#define	DKIMF_DB_FLAG_SOFTSTART	0x0100
#define	DKIMF_DB_FLAG_NOCACHE	0x0200

#define	DKIMF_DB_TYPE_UNKNOWN	(-1)
#define	DKIMF_DB_TYPE_FILE	0
#define	DKIMF_DB_TYPE_REFILE	1
#define	DKIMF_DB_TYPE_CSL	2
#define DKIMF_DB_TYPE_LUA	6
#define DKIMF_DB_TYPE_MDB	10
#define DKIMF_DB_TYPE_REDIS	12

#ifdef __STDC__
# ifndef __P
#  define __P(x)  x
# endif /* ! __P */
#else /* __STDC__ */
# ifndef __P
#  define __P(x)  ()
# endif /* ! __P */
#endif /* __STDC__ */

/* types */
struct dkimf_db;
typedef struct dkimf_db * DKIMF_DB;

struct dkimf_db_data
{
	unsigned int	dbdata_flags;
	char *		dbdata_buffer;
	size_t		dbdata_buflen;
};
typedef struct dkimf_db_data * DKIMF_DBDATA;

#define	DKIMF_DB_DATA_BINARY	0x01		/* data is binary */
#define	DKIMF_DB_DATA_OPTIONAL	0x02		/* data is optional */

/* prototypes */
extern int dkimf_db_chown __P((DKIMF_DB, uid_t uid));
extern int dkimf_db_close __P((DKIMF_DB));
extern int dkimf_db_delete __P((DKIMF_DB, void *, size_t));
extern void dkimf_db_flags __P((unsigned int));
extern int dkimf_db_get __P((DKIMF_DB, void *, size_t,
                             DKIMF_DBDATA, unsigned int, _Bool *));
extern int dkimf_db_mkarray __P((DKIMF_DB, char ***, const char **));
extern int dkimf_db_open __P((DKIMF_DB *, char *, u_int flags,
                              pthread_mutex_t *, char **));
extern int dkimf_db_put __P((DKIMF_DB, void *, size_t, void *, size_t));
extern int dkimf_db_rewalk __P((DKIMF_DB, char *, DKIMF_DBDATA, unsigned int,
                                void **));
extern int dkimf_db_strerror __P((DKIMF_DB, char *, size_t));
extern int dkimf_db_type __P((DKIMF_DB));
extern int dkimf_db_walk __P((DKIMF_DB, _Bool, void *, size_t *,
                              DKIMF_DBDATA, unsigned int));

#endif /* _OPENDKIM_DB_H_ */
