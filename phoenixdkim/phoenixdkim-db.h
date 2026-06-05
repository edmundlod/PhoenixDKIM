/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**      All rights reserved.
**
**  Copyright (c) 2009-2013, The Trusted Domain Project.  All rights reserved.
**
*/

#ifndef _PHOENIXDKIM_DB_H_
#define _PHOENIXDKIM_DB_H_

/* system includes */
#include <sys/types.h>
#include <pthread.h>
#include <time.h>

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
#define DKIMF_DB_TYPE_HTTP	13
#define DKIMF_DB_TYPE_VAULT	14

/* vault: selectors array (emit-all-valid) bounds */
#define DKIMF_DB_VAULT_MAXSELECTORS	16
#define DKIMF_DB_VAULT_SELLEN		256
#define DKIMF_DB_VAULT_DOMLEN		256
#define DKIMF_DB_VAULT_ALGLEN		64
#define DKIMF_DB_VAULT_KEYLEN		8192


/* types */
struct dkimf_db;
typedef struct dkimf_db * DKIMF_DB;

/*
**  One currently-valid selector pulled from a vault: secret's "selectors"
**  array.  vs_domain/vs_alg are empty strings when the entry omits them.
*/
struct dkimf_vault_selector
{
	char	vs_selector[DKIMF_DB_VAULT_SELLEN];
	char	vs_domain[DKIMF_DB_VAULT_DOMLEN];
	char	vs_alg[DKIMF_DB_VAULT_ALGLEN];
	char	vs_key[DKIMF_DB_VAULT_KEYLEN];
};

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
extern int dkimf_db_close(DKIMF_DB);
extern int dkimf_db_get(DKIMF_DB, const void *, size_t,
                             DKIMF_DBDATA, unsigned int, _Bool *);
extern int dkimf_db_mkarray(DKIMF_DB, char ***, const char **);
extern int dkimf_db_open(DKIMF_DB *, char *, u_int flags,
                              pthread_mutex_t *, const char **);
extern int dkimf_db_rewalk(DKIMF_DB, char *, DKIMF_DBDATA, unsigned int,
                                void **);
extern int dkimf_db_strerror(DKIMF_DB, char *, size_t);
extern int dkimf_db_type(DKIMF_DB);
extern int dkimf_db_walk(DKIMF_DB, _Bool, void *, size_t *,
                              DKIMF_DBDATA, unsigned int);

#ifdef HAVE_LIBCURL
extern void dkimf_db_set_http_config(const char *token, const char *auth_header,
                                     long timeout_secs);
extern void dkimf_db_set_vault_config(const char *token, const char *field);
extern void dkimf_db_set_vault_selectors_field(const char *field);
extern void dkimf_db_set_http_cabundle(const char *path);
extern int dkimf_db_vault_selectors(DKIMF_DB, const void *, size_t, time_t,
                                    struct dkimf_vault_selector **,
                                    unsigned int *);
#endif /* HAVE_LIBCURL */

#endif /* _PHOENIXDKIM_DB_H_ */
