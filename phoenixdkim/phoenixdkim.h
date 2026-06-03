/*
**  Copyright (c) 2005-2009 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2014, The Trusted Domain Project.  All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
*/

#ifndef _PHOENIXDKIM_H_
#define _PHOENIXDKIM_H_

#define	DKIMF_PRODUCT	"PhoenixDKIM Filter"
#define	DKIMF_PRODUCTNS	"PhoenixDKIM-Filter"

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */

/* libmilter */
#ifdef DKIMF_MILTER_PROTOTYPES
# include <libmilter/mfapi.h>
#endif /* DKIMF_MILTER_PROTOTYPES */

/* libphoenixdkim */
#include "dkim.h"

#ifdef USE_LUA
# ifdef DKIMF_LUA_PROTOTYPES
/* LUA */
# include <lua.h>
# endif /* DKIMF_LUA_PROTOTYPES */
#endif /* USE_LUA */

/* make sure we have TRUE and FALSE */
#ifndef FALSE
# define FALSE		0
#endif /* !FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* !TRUE */

/* defaults, limits, etc. */
#define	BUFRSZ		1024
#define	CACHESTATSINT	300
#define	CBINTERVAL	3
#define	DEFCONFFILE	CONFIG_BASE "/phoenixdkim.conf"
#define	DEFDNSSECPROBE	"ns:."
#define	DEFFLOWDATATTL	86400
#define	DEFINTERNAL	"csl:127.0.0.1,::1"
#define	DEFMAXHDRSZ	65536
#define	DEFMAXVERIFY	3
#define	DEFTIMEOUT	5
#define	HOSTUNKNOWN	"unknown-host"
#define	JOBIDUNKNOWN	"(unknown-jobid)"
#define	LOCALHOST	"127.0.0.1"
#define	MAXADDRESS	256
#define	MAXARGV		65536
#define	MAXBUFRSZ	65536
#define	MAXHDRCNT	64
#define	MAXHDRLEN	78
#define	MAXSIGNATURE	1024
#define	MTAMARGIN	78
#define	NULLDOMAIN	"(invalid)"
#define	SUPERUSER	"root"
#define	UNKNOWN		"unknown"

#define	DB_DOMAINS	1
#define DB_THIRDPARTY	2
#define	DB_DONTSIGNTO	3
#define	DB_MTAS		4
#define	DB_MACROS	5
#define	DB_SIGNINGTABLE	6

#define AUTHRESULTSHDR	"Authentication-Results"
#define ORCPTHEADER	"Original-Recipient"

#define	SWHEADERNAME	"DKIM-Filter"
#define	SELECTCANONHDR	"Canonicalization"


/*
**  HEADER -- a handle referring to a header
*/

typedef struct Header * Header;
struct Header
{
	char *		hdr_hdr;
	char *		hdr_val;
	struct Header *	hdr_next;
	struct Header *	hdr_prev;
};

/*
**  SIGNREQ -- signing request (for multiple signature requests)
*/

typedef struct signreq * SIGNREQ;
struct signreq
{
	ssize_t			srq_signlen;
	size_t			srq_keydatalen;
	void *			srq_keydata;
	u_char *		srq_domain;
	u_char *		srq_selector;
	u_char *		srq_signer;
	DKIM *			srq_dkim;
	struct signreq *	srq_next;
};

/* externs */
extern _Bool dolog;
extern char *progname;

/* prototypes, exported for test.c */
#ifdef DKIMF_MILTER_PROTOTYPES
extern sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
extern sfsistat mlfi_envfrom(SMFICTX *, char **);
extern sfsistat mlfi_envrcpt(SMFICTX *, char **);
extern sfsistat mlfi_header(SMFICTX *, char *, char *);
extern sfsistat mlfi_eoh(SMFICTX *);
extern sfsistat mlfi_body(SMFICTX *, u_char *, size_t);
extern sfsistat mlfi_eom(SMFICTX *);
extern sfsistat mlfi_abort(SMFICTX *);
extern sfsistat mlfi_close(SMFICTX *);
#endif /* DKIMF_MILTER_PROTOTYPES */

extern DKIM *dkimf_getdkim(void *);
extern struct signreq *dkimf_getsrlist(void *);

#ifdef USE_LUA
# ifdef DKIMF_LUA_PROTOTYPES
extern void dkimf_import_globals(void *, lua_State *);
extern int dkimf_xs_addheader(lua_State *);
extern int dkimf_xs_addrcpt(lua_State *);
extern int dkimf_xs_bodylength(lua_State *);
extern int dkimf_xs_canonlength(lua_State *);
extern int dkimf_xs_clienthost(lua_State *);
extern int dkimf_xs_clientip(lua_State *);
extern int dkimf_xs_dbclose(lua_State *);
extern int dkimf_xs_dbhandle(lua_State *);
extern int dkimf_xs_dbopen(lua_State *);
extern int dkimf_xs_dbquery(lua_State *);
extern int dkimf_xs_delheader(lua_State *);
extern int dkimf_xs_delrcpt(lua_State *);
extern int dkimf_xs_export(lua_State *);
extern int dkimf_xs_fromdomain(lua_State *);
extern int dkimf_xs_getenvfrom(lua_State *);
extern int dkimf_xs_getheader(lua_State *);
extern int dkimf_xs_getsigarray(lua_State *);
extern int dkimf_xs_getsigcount(lua_State *);
extern int dkimf_xs_getsigdomain(lua_State *);
extern int dkimf_xs_getsighandle(lua_State *);
extern int dkimf_xs_getsigidentity(lua_State *);
extern int dkimf_xs_getsymval(lua_State *);
extern int dkimf_xs_internalip(lua_State *);
extern int dkimf_xs_log(lua_State *);
extern int dkimf_xs_parsefield(lua_State *);
extern int dkimf_xs_quarantine(lua_State *);
extern int dkimf_xs_rcpt(lua_State *);
extern int dkimf_xs_rcptarray(lua_State *);
extern int dkimf_xs_rcptcount(lua_State *);
extern int dkimf_xs_replaceheader(lua_State *);
extern int dkimf_xs_resign(lua_State *);
extern int dkimf_xs_requestsig(lua_State *);
extern int dkimf_xs_setpartial(lua_State *);
extern int dkimf_xs_setreply(lua_State *);
extern int dkimf_xs_setresult(lua_State *);
extern int dkimf_xs_sigbhresult(lua_State *);
extern int dkimf_xs_sigignore(lua_State *);
extern int dkimf_xs_signfor(lua_State *);
extern int dkimf_xs_sigresult(lua_State *);
extern int dkimf_xs_verify(lua_State *);
extern int dkimf_xs_xtag(lua_State *);
# endif /* DKIMF_LUA_PROTOTYPES */
#endif /* USE_LUA */

#endif /* _PHOENIXDKIM_H_ */
