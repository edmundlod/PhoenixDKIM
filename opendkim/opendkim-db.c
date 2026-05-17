/*
**  Copyright (c) 2008 Sendmail, Inc. and its suppliers.
**	All rights reserved.
**
**  Copyright (c) 2009-2014, The Trusted Domain Project.  All rights reserved.
**
**  Copyright (c) 2026, OpenDKIM contributors. All rights reserved.
*/

#include "build-config.h"

/* for Solaris */
#ifndef _REENTRANT
# define _REENTRANT
#endif /* ! _REENTRANT */

/* system includes */
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/file.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <regex.h>
#include <netdb.h>

/* libopendkim includes */
#include <dkim.h>

/* libbsd if found */
#ifdef USE_BSD_H
# include <bsd/string.h>
#endif /* USE_BSD_H */

/* libstrl if needed */
#ifdef USE_STRL_H
# include <strl.h>
#endif /* USE_STRL_H */

/* opendkim includes */
#include "util.h"
#include "opendkim-db.h"
#ifdef USE_LUA
# include "opendkim-lua.h"
#endif /* USE_LUA */
#include "opendkim.h"

/* various DB library includes */
#ifdef USE_LUA
# include <lua.h>
#endif /* USE_LUA */
#ifdef USE_MDB
# include <lmdb.h>
#endif /* USE_MDB */
#ifdef USE_REDIS
# ifdef USE_LIBVALKEY
#  include <valkey/valkey.h>
typedef valkeyContext  redisContext;
typedef valkeyReply    redisReply;
#  define redisConnect       valkeyConnect
#  define redisCommand       valkeyCommand
#  define freeReplyObject    valkeyFreeReplyObject
#  define redisFree          valkeyFree
#  define REDIS_REPLY_NIL    VALKEY_REPLY_NIL
#  define REDIS_REPLY_STRING VALKEY_REPLY_STRING
# else
#  include <hiredis/hiredis.h>
# endif /* USE_LIBVALKEY */
#endif /* USE_REDIS */

/* macros */
#define	BUFRSZ			1024
#define	DEFARRAYSZ		16
#define DKIMF_DB_DEFASIZE	8
#define DKIMF_DB_MODE		0644

#define	DKIMF_DB_IFLAG_FREEARRAY 0x01
#define	DKIMF_DB_IFLAG_RECONNECT 0x02

#ifndef FALSE
# define FALSE			0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE			1
#endif /* ! TRUE */

#ifndef MAX
# define MAX(x,y)	((x) > (y) ? (x) : (y))
#endif /* ! MAX */



/* macros */
#ifndef MIN
# define MIN(x,y)       ((x) < (y) ? (x) : (y))
#endif /* ! MIN */

/* data types */
struct dkimf_db
{
	u_int			db_flags;
	u_int			db_iflags;
	u_int			db_type;
	int			db_status;
	int			db_nrecs;
	pthread_mutex_t *	db_lock;
	void *			db_handle;	/* handler handle */
	void *			db_data;	/* dkimf_db handle */
	void *			db_cursor;	/* cursor */
	void *			db_entry;	/* entry (context) */
	char **			db_array;
};

struct dkimf_db_table
{
	char *			name;
	int 			code;
};

struct dkimf_db_list
{
	char *			db_list_key;
	char *			db_list_value;
	struct dkimf_db_list *	db_list_next;
};

struct dkimf_db_relist
{
	regex_t			db_relist_re;
	char *			db_relist_data;
	struct dkimf_db_relist * db_relist_next;
};



#ifdef USE_LUA
struct dkimf_db_lua
{
	char *			lua_script;
	size_t			lua_scriptlen;
	char *			lua_error;
};
#endif /* USE_LUA */


#ifdef USE_MDB
struct dkimf_db_mdb
{
	MDB_env *		mdb_env;
	MDB_txn *		mdb_txn;
	MDB_dbi			mdb_dbi;
};
#endif /* USE_MDB */

#ifdef USE_REDIS
struct dkimf_db_redis
{
	redisContext *		redis_ctx;
	char *			redis_prefix;
};
#endif /* USE_REDIS */


/* globals */
struct dkimf_db_table dbtypes[] =
{
	{ "csl",		DKIMF_DB_TYPE_CSL },
	{ "file",		DKIMF_DB_TYPE_FILE },
	{ "refile",		DKIMF_DB_TYPE_REFILE },
#ifdef USE_LUA
	{ "lua",		DKIMF_DB_TYPE_LUA },
#endif /* USE_LUA */
#ifdef USE_MDB
	{ "mdb",		DKIMF_DB_TYPE_MDB },
#endif /* USE_MDB */
#ifdef USE_REDIS
	{ "redis",		DKIMF_DB_TYPE_REDIS },
#endif /* USE_REDIS */
	{ NULL,			DKIMF_DB_TYPE_UNKNOWN },
};


/* globals */
static unsigned int gflags = 0;


/*
**  DKIMF_DB_FLAGS -- set global flags
**
**  Parameters:
**  	flags -- new global flag mask
**
**  Return value:
**  	None.
*/

void
dkimf_db_flags(unsigned int flags)
{
	gflags = flags;
}



/*
**  DKIMF_DB_DATASPLIT -- split a database value or set of values into a
**                        request array
**
**  Parameters:
**  	buf -- data buffer
**  	buflen -- buffer length
**  	req -- request array
**  	reqnum -- length of request array
**
**  Return value:
**  	0 -- successful data split
**  	-1 -- not enough elements present to fulfill the request
*/

static int
dkimf_db_datasplit(char *buf, size_t buflen,
                   DKIMF_DBDATA req, unsigned int reqnum)
{
	u_int ridx;
	int ret = 0;
	size_t clen;
	size_t remain;
	char *p;

	assert(buf != NULL);

	if (req == NULL || reqnum == 0)
		return 0;

	p = buf;
	remain = buflen;

	for (ridx = 0; ridx < reqnum; ridx++)
	{
		if (remain <= 0)
			break;

		if ((req[ridx].dbdata_flags & DKIMF_DB_DATA_BINARY) != 0)
		{
			clen = MIN(remain, req[ridx].dbdata_buflen);
			memcpy(req[ridx].dbdata_buffer, p, clen);
			req[ridx].dbdata_buflen = remain;
			remain = 0;
		}
		else if (ridx == reqnum - 1)
		{
			size_t cap = req[ridx].dbdata_buflen;
			clen = MIN(remain, cap);
			memcpy(req[ridx].dbdata_buffer, p, clen);
			if (clen < cap)
				req[ridx].dbdata_buffer[clen] = '\0';
			req[ridx].dbdata_buflen = remain;
		}
		else
		{
			char *q;

			q = strchr(p, ':');
			if (q != NULL)
			{
				size_t cap = req[ridx].dbdata_buflen;
				clen = q - p;
				size_t copy = MIN(clen, cap);
				memcpy(req[ridx].dbdata_buffer, p, copy);
				if (copy < cap)
					req[ridx].dbdata_buffer[copy] = '\0';
				req[ridx].dbdata_buflen = clen;
				p += clen + 1;
				remain -= (clen + 1);
			}
			else
			{
				size_t cap = req[ridx].dbdata_buflen;
				clen = remain;
				size_t copy = MIN(clen, cap);
				memcpy(req[ridx].dbdata_buffer, p, copy);
				if (copy < cap)
					req[ridx].dbdata_buffer[copy] = '\0';
				req[ridx].dbdata_buflen = clen;
				remain = 0;
			}
		}
	}

	/* mark the ones that got no data */
	if (ridx < reqnum)
	{
		u_int c;

		for (c = ridx; c < reqnum; c++)
		{
			if ((req[c].dbdata_flags & DKIMF_DB_DATA_OPTIONAL) == 0)
				ret = -1;
			req[c].dbdata_buflen = (size_t) -1;
		}
	}

        return ret;
}



/*
**  DKIMF_DB_LIST_FREE -- destroy a linked list
**
**  Parameters:
**  	list -- list handle
**
**  Return value:
**  	None.
*/

static void
dkimf_db_list_free(struct dkimf_db_list *list)
{
	struct dkimf_db_list *next;

	assert(list != NULL);

	while (list != NULL)
	{
		free(list->db_list_key);
		if (list->db_list_value != NULL)
			free(list->db_list_value);
		next = list->db_list_next;
		free(list);
		list = next;
	}
}
		
/*
**  DKIMF_DB_RELIST_FREE -- destroy a linked regex list
**
**  Parameters:
**  	list -- list handle
**
**  Return value:
**  	None.
*/

static void
dkimf_db_relist_free(struct dkimf_db_relist *list)
{
	struct dkimf_db_relist *next;

	assert(list != NULL);

	while (list != NULL)
	{
		regfree(&list->db_relist_re);
		if (list->db_relist_data != NULL)
			free(list->db_relist_data);
		next = list->db_relist_next;
		free(list);
		list = next;
	}
}



/*
**  DKIMF_DB_TYPE -- return database type
**
**  Parameters:
**  	db -- DKIMF_DB handle
** 
**  Return value:
**  	A DKIMF_DB_TYPE_* constant.
*/

int
dkimf_db_type(DKIMF_DB db)
{
	assert(db != NULL);

	return db->db_type;
}


/*
**  DKIMF_DB_OPEN -- open a database
**
**  Parameters:
**  	db -- DKIMF_DB handle (returned)
**  	name -- name of DB to open
**  	flags -- operational flags
**  	lock -- lock to use during operations
**  	err -- error string from underlying library (returned; may be NULL)
**
**  Return value:
**  	3 -- other open error
**  	2 -- illegal request (e.g. writable flat file)
**  	1 -- unknown database type
**  	0 -- success
**   	-1 -- failure; check errno
**
**  Notes:
**  	The type of the database is implied by a leading "type:" string
**  	as part of "name".  The list of valid types is listed in the
**  	"dbtypes" table above.  Without such a prefix, a name that starts
**  	with "/" implies "file", otherwise "csl" is used.
**
**  	Currently defined types:
**  	csl -- "name" contains a comma-separated list
**  	file -- a flat file; may be simply a list of names if only a
**  	        memership test is needed, or it can be "key value" lines
**  	        in which case dkimf_db_get() can be used to extract the
**  	        value of a named key
**  	refile -- a flat file containing patterns (i.e. strings with the
**  	          wildcard "*"); only membership tests are allowed
**  	db -- a Sleepycat hash or b-tree database file, which can be used
**  	      for membership tests or key-value pairs
**  	dsn -- a data store name, meaning SQL or ODBC in the backend,
**  	       with interface provided by OpenDBX
**  	ldap -- an LDAP server, interace provide by OpenLDAP
**  	lua -- a Lua script; the returned value is the result
**  	erlang -- an erlang function to be called in a distributed erlang node
*/

int
dkimf_db_open(DKIMF_DB *db, char *name, u_int flags, pthread_mutex_t *lock,
              char **err)
{
	DKIMF_DB new;
	char *comma;
	char *p;

	assert(db != NULL);
	assert(name != NULL);

	new = (DKIMF_DB) malloc(sizeof(struct dkimf_db));
	if (new == NULL)
	{
		if (err != NULL)
			*err = strerror(errno);
		return -1;
	}

	memset(new, '\0', sizeof(struct dkimf_db));

	new->db_flags = (flags | gflags);
	new->db_type = DKIMF_DB_TYPE_UNKNOWN;

	p = strchr(name, ':');
	comma = strchr(name, ',');

	/* catch a CSL that contains colons not in the first entry */
	if (comma != NULL && p != NULL && comma < p)
		p = NULL;

	if (p == NULL)
	{
		if (name[0] == '/')
			new->db_type = DKIMF_DB_TYPE_FILE;
		else
			new->db_type = DKIMF_DB_TYPE_CSL;
		p = name;
	}
	else
	{
		int c;
		char dbtype[BUFRSZ + 1];

		strlcpy(dbtype, name, MIN(sizeof dbtype, (size_t)(p - name) + 1));

		for (c = 0; ; c++)
		{
			if (dbtypes[c].name == NULL)
				break;

			if (strcasecmp(dbtypes[c].name, dbtype) == 0)
				new->db_type = dbtypes[c].code;
		}

		if (new->db_type == (u_int) DKIMF_DB_TYPE_UNKNOWN)
		{
			free(new);
			if (err != NULL)
				*err = "Unknown database type";
			return 1;
		}

		p++;
	}


	/* use provided lock, or create a new one if needed */
	if (lock != NULL)
	{
		new->db_lock = lock;
		new->db_flags &= ~DKIMF_DB_FLAG_MAKELOCK;
	}
	else if ((new->db_flags & DKIMF_DB_FLAG_MAKELOCK) != 0)
	{
		new->db_lock = (pthread_mutex_t *) malloc(sizeof(pthread_mutex_t));
		if (new->db_lock == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		pthread_mutex_init(new->db_lock, NULL);
	}

	switch (new->db_type)
	{
	  case DKIMF_DB_TYPE_CSL:
	  {
		int n = 0;
		char *tmp;
		char *eq;
		char *ctx;
		struct dkimf_db_list *list = NULL;
		struct dkimf_db_list *next = NULL;
		struct dkimf_db_list *newl;

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			free(new);
			errno = EINVAL;
			if (err != NULL)
				*err = strerror(errno);
			return 2;
		}

		tmp = strdup(p);
		if (tmp == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		for (p = strtok_r(tmp, ",", &ctx);
		     p != NULL;
		     p = strtok_r(NULL, ",", &ctx))
		{
			eq = strchr(p, '=');
			if (eq != NULL)
				*eq = '\0';

			if (eq != NULL &&
			    (new->db_flags & DKIMF_DB_FLAG_VALLIST) != 0)
			{
				char *q;
				char *ctx2;

				for (q = strtok_r(eq + 1, "|", &ctx2);
				     q != NULL;
				     q = strtok_r(NULL, "|", &ctx2))
				{
					newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
					if (newl == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						free(new);
						return -1;
					}

					newl->db_list_key = strdup(p);
					if (newl->db_list_key == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);
						free(tmp);
						return -1;
					}
					dkimf_trimspaces(newl->db_list_key);

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(tmp);
						free(new);
						return -1;
					}
					dkimf_trimspaces(newl->db_list_value);

					newl->db_list_next = NULL;

					if (list == NULL)
						list = newl;
					else
						next->db_list_next = newl;

					next = newl;
					n++;
				}
			}
			else
			{
				newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
				if (newl == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					free(new);
					return -1;
				}

				newl->db_list_key = strdup(p);
				if (newl->db_list_key == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					free(tmp);
					free(new);
					return -1;
				}
				dkimf_trimspaces(newl->db_list_key);

				if (eq != NULL)
				{
					newl->db_list_value = strdup(eq + 1);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						free(tmp);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);
						return -1;
					}
					dkimf_trimspaces(newl->db_list_value);
				}
				else
				{
					newl->db_list_value = NULL;
				}

				newl->db_list_next = NULL;

				if (list == NULL)
					list = newl;
				else
					next->db_list_next = newl;

				next = newl;
				n++;
			}
		}

		free(tmp);

		new->db_handle = list;
		new->db_nrecs = n;

		break;
	  }

	  case DKIMF_DB_TYPE_FILE:
	  {
		_Bool gapfound;
		int n = 0;
		FILE *f;
		char *key;
		char *value;
		struct dkimf_db_list *list = NULL;
		struct dkimf_db_list *next = NULL;
		struct dkimf_db_list *newl;
		char line[BUFRSZ + 1];

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		memset(line, '\0', sizeof line);
		while (fgets(line, BUFRSZ, f) != NULL)
		{
			for (p = line; *p != '\0'; p++)
			{
				if (*p == '\n' || *p == '#')
				{
					*p = '\0';
					break;
				}
			}

			dkimf_trimspaces(line);
			if (strlen(line) == 0)
				continue;

			newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
			if (newl == NULL)
			{
				if (err != NULL)
					*err = strerror(errno);
				if (list != NULL)
					dkimf_db_list_free(list);
				fclose(f);
				free(new);
				return -1;
			}

			key = NULL;
			value = NULL;
			gapfound = FALSE;

			for (p = line; *p != '\0'; p++)
			{
				if (!isascii(*p) || !isspace(*p))
				{
					if (key == NULL)
						key = p;
					else if (value == NULL && gapfound)
						value = p;
				}
				else if (key != NULL && value == NULL)
				{
					*p = '\0';
					gapfound = TRUE;
				}
			}

			assert(key != NULL);
			
			if (value != NULL &&
			    (new->db_flags & DKIMF_DB_FLAG_VALLIST) != 0)
			{
				char *q;
				char *ctx;

				for (q = strtok_r(value, "|", &ctx);
				     q != NULL;
				     q = strtok_r(NULL, "|", &ctx))
				{
					newl = (struct dkimf_db_list *) malloc(sizeof(struct dkimf_db_list));
					if (newl == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);

						return -1;
					}

					newl->db_list_key = strdup(key);
					if (newl->db_list_key == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						free(new);

						return -1;
					}
					dkimf_trimspaces(newl->db_list_key);

					newl->db_list_value = strdup(q);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						return -1;
					}
					dkimf_trimspaces(newl->db_list_value);

					newl->db_list_next = NULL;

					if (list == NULL)
						list = newl;
					else
						next->db_list_next = newl;
	
					next = newl;
					n++;
				}
			}
			else
			{
				newl->db_list_key = strdup(key);
				if (newl->db_list_key == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					free(newl);
					if (list != NULL)
						dkimf_db_list_free(list);
					fclose(f);
					free(new);
					return -1;
				}
				dkimf_trimspaces(newl->db_list_key);

				if (value != NULL)
				{
					newl->db_list_value = strdup(value);
					if (newl->db_list_value == NULL)
					{
						if (err != NULL)
							*err = strerror(errno);
						free(newl->db_list_key);
						free(newl);
						if (list != NULL)
							dkimf_db_list_free(list);
						fclose(f);
						free(new);
						return -1;
					}
					dkimf_trimspaces(newl->db_list_value);
				}
				else
				{
					newl->db_list_value = NULL;
				}

				newl->db_list_next = NULL;

				if (list == NULL)
					list = newl;
				else
					next->db_list_next = newl;

				next = newl;
				n++;
			}
		}

		fclose(f);

		new->db_handle = list;
		new->db_nrecs = n;

		break;
	  }

	  case DKIMF_DB_TYPE_REFILE:
	  {
		int status;
		int reflags;
		FILE *f;
		char *end;
		char *data;
		struct dkimf_db_relist *head = NULL;
		struct dkimf_db_relist *tail = NULL;
		struct dkimf_db_relist *newl;
		char line[BUFRSZ + 1];
		char patbuf[BUFRSZ + 1];

		if ((new->db_flags & DKIMF_DB_FLAG_READONLY) == 0)
		{
			if (err != NULL)
				*err = strerror(EINVAL);
			free(new);
			errno = EINVAL;
			return 2;
		}

		f = fopen(p, "r");
		if (f == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new);
			return -1;
		}

		reflags = REG_EXTENDED;
		if ((new->db_flags & DKIMF_DB_FLAG_ICASE) != 0)
			reflags |= REG_ICASE;

		memset(line, '\0', sizeof line);
		while (fgets(line, BUFRSZ, f) != NULL)
		{
			end = NULL;
			data = NULL;

			for (p = line; *p != '\0'; p++)
			{
				if (*p == '\n' || *p == '#')
				{
					*p = '\0';
					break;
				}
				else if (end == NULL &&
				         isascii(*p) && isspace(*p))
				{
					end = p;
				}
			}

			if (end != NULL)
			{
				*end = '\0';
				for (data = end + 1; *data != '\0'; data++)
				{
					if (!isascii(*data) || !isspace(*data))
						break;
				}
			}

			dkimf_trimspaces(line);
			if (strlen(line) == 0)
				continue;

			newl = (struct dkimf_db_relist *) malloc(sizeof(struct dkimf_db_relist));
			if (newl == NULL)
			{
				if (err != NULL)
					*err = strerror(errno);
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			memset(patbuf, '\0', sizeof patbuf);

			if (!dkimf_mkregexp(line, patbuf, sizeof patbuf))
			{
				if (err != NULL)
					*err = "Error constructing regular expression";
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			status = regcomp(&newl->db_relist_re, patbuf, reflags);
			if (status != 0)
			{
				if (err != NULL)
					*err = "Error compiling regular expression";
				if (head != NULL)
					dkimf_db_relist_free(head);
				fclose(f);
				free(new);
				free(newl);
				return -1;
			}

			if (data != NULL)
			{
				newl->db_relist_data = strdup(data);
				if (newl->db_relist_data == NULL)
				{
					if (err != NULL)
						*err = strerror(errno);
					if (head != NULL)
						dkimf_db_relist_free(head);
					fclose(f);
					free(new);
					free(newl);
					return -1;
				}
				dkimf_trimspaces(newl->db_relist_data);
			}
			else
			{
				newl->db_relist_data = NULL;
			}

			newl->db_relist_next = NULL;

			if (head == NULL)
				head = newl;
			else
				tail->db_relist_next = newl;

			tail = newl;
		}

		fclose(f);

		new->db_handle = head;

		break;
	  }




#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		int fd;
		ssize_t rlen;
		char *tmp;
		struct stat s;
		struct dkimf_lua_script_result lres;
		struct dkimf_db_lua *lua;

		fd = open(p, O_RDONLY);
		if (fd < 0)
		{
			if (err != NULL)
				*err = strerror(errno);
			return -1;
		}

		if (fstat(fd, &s) == -1)
		{
			if (err != NULL)
				*err = strerror(errno);
			close(fd);
			return -1;
		}

		lua = (struct dkimf_db_lua *) malloc(sizeof *lua);
		if (lua == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			return -1;
		}
		memset(lua, '\0', sizeof *lua);
		new->db_data = (void *) lua;

		tmp = (void *) malloc(s.st_size + 1);
		if (tmp == NULL)
		{
			if (err != NULL)
				*err = strerror(errno);
			free(new->db_data);
			close(fd);
			return -1;
		}
		memset(tmp, '\0', s.st_size + 1);

		rlen = read(fd, tmp, s.st_size);
		if (rlen < s.st_size)
		{
			if (err != NULL)
			{
				if (rlen == -1)
					*err = strerror(errno);
				else
					*err = "Read truncated";
			}
			free(tmp);
			free(new->db_data);
			close(fd);
			return -1;
		}

		close(fd);

		/* try to compile it */
		if (dkimf_lua_db_hook(tmp, 0, NULL, &lres, 
		                      (void *) &lua->lua_script,
		                      &lua->lua_scriptlen) != 0)
		{
			if (err != NULL)
				*err = "Lua compilation error";
			free(tmp);
			free(new->db_data);
			return -1;
		}

		free(tmp);
		break;
	  }
#endif /* USE_LUA */



#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status;
		struct dkimf_db_mdb *mdb;

		mdb = (struct dkimf_db_mdb *) malloc(sizeof *mdb);
		if (mdb == NULL)
			return -1;

		status = mdb_env_create(&mdb->mdb_env);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			free(mdb);
			return -1;
		}

		status = mdb_env_open(mdb->mdb_env, p, 0, 0);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		status = mdb_txn_begin(mdb->mdb_env, NULL, MDB_RDONLY, &mdb->mdb_txn);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		status = mdb_dbi_open(mdb->mdb_txn, NULL, 0, &mdb->mdb_dbi);
		if (status != 0)
		{
			if (err != NULL)
				*err = mdb_strerror(status);
			mdb_txn_abort(mdb->mdb_txn);
			mdb_env_close(mdb->mdb_env);
			free(mdb);
			return -1;
		}

		new->db_data = (void *) mdb;

		break;
	  }
#endif /* USE_MDB */

#ifdef USE_REDIS
	  case DKIMF_DB_TYPE_REDIS:
	  {
		int port = 6379;
		char host[256];
		char prefix[256];
		static char redis_errbuf[128];
		char *slash;
		char *colon;
		struct dkimf_db_redis *r;
		redisContext *ctx;

		/* after scheme parsing, p points to "//host..." — skip the "//" */
		if (p[0] == '/' && p[1] == '/')
			p += 2;

		slash = strchr(p, '/');
		if (slash == NULL || slash[1] == '\0')
		{
			free(new);
			if (err != NULL)
				*err = "redis: URI must include /prefix";
			return 1;
		}

		colon = memchr(p, ':', slash - p);
		if (colon != NULL)
		{
			char portbuf[16];
			size_t hlen = colon - p;
			if (hlen >= sizeof host)
				hlen = sizeof host - 1;
			memcpy(host, p, hlen);
			host[hlen] = '\0';
			size_t plen = slash - colon - 1;
			if (plen >= sizeof portbuf)
				plen = sizeof portbuf - 1;
			memcpy(portbuf, colon + 1, plen);
			portbuf[plen] = '\0';
			port = atoi(portbuf);
			if (port <= 0 || port > 65535)
			{
				free(new);
				if (err != NULL)
					*err = "redis: invalid port";
				return 1;
			}
		}
		else
		{
			size_t hlen = slash - p;
			if (hlen >= sizeof host)
				hlen = sizeof host - 1;
			memcpy(host, p, hlen);
			host[hlen] = '\0';
		}

		if (strlcpy(prefix, slash + 1, sizeof prefix) >= sizeof prefix)
		{
			free(new);
			if (err != NULL)
				*err = "redis: prefix too long";
			return 1;
		}

		ctx = redisConnect(host, port);
		if (ctx == NULL)
		{
			free(new);
			if (err != NULL)
				*err = "redis: redisConnect returned NULL";
			return -1;
		}
		if (ctx->err != 0)
		{
			if (err != NULL)
			{
				strlcpy(redis_errbuf, ctx->errstr, sizeof redis_errbuf);
				*err = redis_errbuf;
			}
			redisFree(ctx);
			free(new);
			return -1;
		}

		r = (struct dkimf_db_redis *) malloc(sizeof *r);
		if (r == NULL)
		{
			redisFree(ctx);
			free(new);
			return -1;
		}

		r->redis_ctx = ctx;
		r->redis_prefix = strdup(prefix);
		if (r->redis_prefix == NULL)
		{
			redisFree(ctx);
			free(r);
			free(new);
			return -1;
		}

		new->db_data = (void *) r;
		new->db_handle = (void *) r;

		break;
	  }
#endif /* USE_REDIS */

	}

	*db = new;
	return 0;
}

/*
**  DKIMF_DB_DELETE -- delete a key/data pair from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to record to be deleted
**  	buflen -- size of record at "buf"; if 0, use strlen()
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_delete(DKIMF_DB db, void *buf, size_t buflen)
{
	int ret = EINVAL;

	assert(db != NULL);
	assert(buf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL ||
	    db->db_type == DKIMF_DB_TYPE_LUA ||
	    db->db_type == DKIMF_DB_TYPE_REFILE)
		return EINVAL;

	return ret;
}

/*
**  DKIMF_DB_PUT -- store a key/data pair in an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to key record
**  	buflen -- size of key (use strlen() if 0)
**  	outbuf -- data buffer
**  	outbuflen -- number of bytes at outbuf to use as data
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
*/

int
dkimf_db_put(DKIMF_DB db, void *buf, size_t buflen,
             void *outbuf, size_t outbuflen)
{
	int ret = EINVAL;
#ifdef USE_MDB
	MDB_val key;
	MDB_val data;
	MDB_dbi dbi;
	MDB_txn *txn;
	struct dkimf_db_mdb *mdb;
#endif /* USE_MDB */

	assert(db != NULL);
	assert(buf != NULL);
	assert(outbuf != NULL);

	if (db->db_type == DKIMF_DB_TYPE_FILE ||
	    db->db_type == DKIMF_DB_TYPE_CSL ||
	    db->db_type == DKIMF_DB_TYPE_LUA ||
	    db->db_type == DKIMF_DB_TYPE_REFILE)
		return EINVAL;


#ifdef USE_MDB
	mdb = db->db_data;

	if (db->db_lock != NULL)
		(void) pthread_mutex_lock(db->db_lock);

	key.mv_data = outbuf;
	key.mv_size = outbuflen;
	data.mv_data = (char *) buf;
	data.mv_size = (buflen == 0 ? strlen(buf) : buflen);

	if (mdb_txn_begin(mdb->mdb_env, NULL, 0, &txn) == 0 &&
	    mdb_dbi_open(txn, NULL, 0, &dbi) == 0 &&
	    mdb_put(txn, dbi, &key, &data, 0) == 0)
		ret = 0;
	else
		ret = -1;

	if (txn != NULL)
	{
		if (ret == 0)
			mdb_txn_commit(txn);
		else
			mdb_txn_abort(txn);
	}

	if (db->db_lock != NULL)
		(void) pthread_mutex_unlock(db->db_lock);
#endif /* USE_MDB */

	return ret;
}

/*
**  DKIMF_DB_GET -- retrieve data from an open database
**
**  Parameters:
**  	db -- DB handle to use for searching
**  	buf -- pointer to the key
**  	buflen -- length of key (use strlen() if 0)
**  	req -- list of data requests
**  	reqnum -- number of data requests
**  	exists -- pointer to a "_Bool" updated to be TRUE if the record
**  	          was found, FALSE otherwise (may be NULL)
**
**  Return value:
**  	0 -- operation successful
**	!0 -- error occurred; error code returned
**
**  Notes:
**  	"req" references a caller-provided array of DKIMF_DBDATA
**  	structures that describe the name of the attribute wanted,
**  	the location to which to write the data, and how big that buffer is.
**  	On completion, any found attributes will have their lengths
**  	set to the number of bytes retrieved and the data will be copied
**  	up to the limit (if more data was retrieved than the space available,
**  	the available space will be filled but the returned length will be
**  	longer); any not-found attributes will leave the buffers unchanged
**  	and the lengths will be set to (unsigned int) -1.
**
**  	For LDAP queries, the attribute name is used as the LDAP attribute
**  	name in the request.
**
**  	For SQL queries, the attribute name is not used; columns are specified
**  	in the DSN (see dkimf_db_open() above), and are copied into the
**  	request in order.
**
**  	For backward compatibility, text values in the other databases
**  	that are colon-delimited will be parsed as such, and the requested
**  	values will be filled in in order (so for "aaa:bbb", "aaa" will be
**  	copied into the first attribute, "bbb" will be copied to the second,
**  	and all others will receive no data.
*/

int
dkimf_db_get(DKIMF_DB db, void *buf, size_t buflen,
             DKIMF_DBDATA req, unsigned int reqnum, _Bool *exists)
{
	_Bool matched;

	assert(db != NULL);
	assert(buf != NULL);
	assert(req != NULL || reqnum == 0);

	/*
	**  Indicate "not found" if we require ASCII-only and there was
	**  non-ASCII in the query.
	*/

	if ((db->db_flags & DKIMF_DB_FLAG_ASCIIONLY) != 0)
	{
		char *p;
		char *end;

		end = (char *) buf + buflen;

		for (p = (char *) buf; p <= end; p++)
		{
			if (!isascii(*p))
			{
				if (*exists)
					*exists = FALSE;

				return 0;
			}
		}
	}

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
	  {
		struct dkimf_db_list *list;

		for (list = (struct dkimf_db_list *) db->db_handle;
		     list != NULL;
		     list = list->db_list_next)
		{
			matched = FALSE;

			if ((db->db_flags & DKIMF_DB_FLAG_ICASE) == 0)
			{
				if (strcmp(buf, list->db_list_key) == 0)
					matched = TRUE;
			}
			else
			{
				if (strcasecmp(buf, list->db_list_key) == 0)
					matched = TRUE;
			}

			if (!matched)
				continue;

			if ((db->db_flags & DKIMF_DB_FLAG_MATCHBOTH) == 0 ||
			    reqnum == 0 || list->db_list_value == NULL)
				break;

			matched = FALSE;
			assert(list->db_list_value != NULL);

			if ((db->db_flags & DKIMF_DB_FLAG_ICASE) == 0)
			{
				if (strncmp(req[0].dbdata_buffer,
				            list->db_list_value,
				            req[0].dbdata_buflen) == 0)
					matched = TRUE;
			}
			else
			{
				if (strncasecmp(req[0].dbdata_buffer,
				                list->db_list_value,
				                req[0].dbdata_buflen) == 0)
					matched = TRUE;
			}

			if (matched)
				break;
		}

		if (list == NULL)
		{
			if (exists != NULL)
				*exists = FALSE;
		}
		else
		{
			if (exists != NULL)
				*exists = TRUE;
			if (list->db_list_value != NULL && reqnum != 0)
			{
				if (dkimf_db_datasplit(list->db_list_value,
				                       strlen(list->db_list_value),
				                       req, reqnum) != 0)
					return -1;
			}
		}

		return 0;
	  }

	  case DKIMF_DB_TYPE_REFILE:
	  {
		struct dkimf_db_relist *list;

		list = (struct dkimf_db_relist *) db->db_handle;

		while (list != NULL)
		{
			if (regexec(&list->db_relist_re, buf, 0, NULL, 0) == 0)
			{
				if (exists != NULL)
					*exists = TRUE;

				if (reqnum != 0 &&
				    list->db_relist_data != NULL)
				{
					if (dkimf_db_datasplit(list->db_relist_data,
					                       strlen(list->db_relist_data),
					                       req,
					                       reqnum) != 0)
						return -1;
				}

				return 0;
			}

			list = list->db_relist_next;
		}

		if (exists != NULL)
			*exists = FALSE;

		return 0;
	  }




#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		u_int c;
		int status;
		struct dkimf_db_lua *lua;
		struct dkimf_lua_script_result lres;

		memset(&lres, '\0', sizeof lres);

		lua = (struct dkimf_db_lua *) db->db_data;

		status = dkimf_lua_db_hook((const char *) lua->lua_script,
		                           lua->lua_scriptlen,
		                           (const char *) buf, &lres,
		                           NULL, NULL);
		if (status != 0)
			return -1;

		if (exists != NULL)
			*exists = (lres.lrs_rcount != 0);

		/* copy results */
		for (c = 0; c < reqnum && c < (u_int) lres.lrs_rcount; c++)
		{
			req[c].dbdata_buflen = strlcpy(req[c].dbdata_buffer,
			                               lres.lrs_results[c],
			                               req[c].dbdata_buflen);
		}

		/* tag requests that weren't fulfilled */
		while (c < reqnum)
			req[c++].dbdata_buflen = 0;

		/* clean up */
		for (c = 0; c < (u_int) lres.lrs_rcount; c++)
			free(lres.lrs_results[c]);
		if (lres.lrs_results != NULL)
			free(lres.lrs_results);

		return 0;
	  }
#endif /* USE_LUA */




#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status;
		struct dkimf_db_mdb *mdb;
		MDB_val key;
		MDB_val data;

		mdb = (struct dkimf_db_mdb *) db->db_data;

		key.mv_size = buflen;
		key.mv_data = buf;

		status = mdb_get(mdb->mdb_txn, mdb->mdb_dbi, &key, &data);
		if (status == MDB_NOTFOUND)
		{
			if (exists != NULL)
				*exists = FALSE;
		}
		else if (status == 0)
		{
			if (exists != NULL)
				*exists = TRUE;

			if (dkimf_db_datasplit(data.mv_data, data.mv_size,
			                       req, reqnum) != 0)
				return -1;
		}
		else
		{
			db->db_status = status;
			return -1;
		}

		return 0;
	  }
#endif /* USE_MDB */

#ifdef USE_REDIS
	  case DKIMF_DB_TYPE_REDIS:
	  {
		char query[BUFRSZ + 1];
		int n;
		struct dkimf_db_redis *r;
		redisReply *reply;

		r = (struct dkimf_db_redis *) db->db_data;

		if (buflen > (size_t) INT_MAX)
		{
			db->db_status = ENOMEM;
			return -1;
		}

		n = snprintf(query, sizeof query, "%s%.*s",
		             r->redis_prefix, (int) buflen, (char *) buf);
		if (n < 0 || (size_t) n >= sizeof query)
		{
			db->db_status = ENOMEM;
			return -1;
		}

		reply = (redisReply *) redisCommand(r->redis_ctx, "GET %s", query);
		if (reply == NULL)
		{
			db->db_status = EIO;
			return -1;
		}

		if (reply->type == REDIS_REPLY_NIL)
		{
			if (exists != NULL)
				*exists = FALSE;
			freeReplyObject(reply);
			return 0;
		}

		if (exists != NULL)
			*exists = TRUE;

		if (reqnum > 0 && reply->type == REDIS_REPLY_STRING)
		{
			if (dkimf_db_datasplit(reply->str, reply->len,
			                       req, reqnum) != 0)
			{
				freeReplyObject(reply);
				return -1;
			}
		}

		freeReplyObject(reply);
		return 0;
	  }
#endif /* USE_REDIS */

	  default:
		assert(0);
		return 0;		/* to silence the compiler */
	}

	/* NOTREACHED */
}

/*
**  DKIMF_DB_CLOSE -- close a DB handle
**
**  Parameters:
**  	db -- DB handle to shut down
**
**  Return value:
**  	0 on success, something else on failure
**
**  Notes:
**  	On failure, db has not been freed.  It's not clear what to do in
**  	that case other than get very upset because we probably have a
**  	descriptor that can't be closed.  The subsystem involved should
**  	probably disable itself or otherwise attract attention.
*/

int
dkimf_db_close(DKIMF_DB db)
{
	assert(db != NULL);

	if (db->db_array != NULL)
	{
		int c;

		if ((db->db_iflags & DKIMF_DB_IFLAG_FREEARRAY) != 0)
		{
			for (c = 0; db->db_array[c] != NULL; c++)
				free(db->db_array[c]);
		}
		free(db->db_array);
		db->db_array = NULL;
	}

	if (db->db_lock != NULL &&
	    (db->db_flags & DKIMF_DB_FLAG_MAKELOCK) != 0)
	{
		pthread_mutex_destroy(db->db_lock);
		free(db->db_lock);
	}

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
		if (db->db_handle != NULL)
			dkimf_db_list_free(db->db_handle);
		free(db);
		return 0;

	  case DKIMF_DB_TYPE_REFILE:
		if (db->db_handle != NULL)
			dkimf_db_relist_free(db->db_handle);
		free(db);
		return 0;




#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		struct dkimf_db_lua *lua;

		lua = (struct dkimf_db_lua *) db->db_data;

		free(lua->lua_script);
		free(db->db_data);
		free(db);
		return 0;
	  }
#endif /* USE_LUA */




#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		struct dkimf_db_mdb *mdb;

		mdb = db->db_data;

		if (db->db_cursor != NULL)
			mdb_cursor_close(db->db_cursor);

		mdb_txn_abort(mdb->mdb_txn);
		mdb_env_close(mdb->mdb_env);
		free(db->db_data);
		free(db);
	  	return 0;
	  }
#endif /* USE_MDB */

#ifdef USE_REDIS
	  case DKIMF_DB_TYPE_REDIS:
	  {
		struct dkimf_db_redis *r;

		r = (struct dkimf_db_redis *) db->db_data;
		redisFree(r->redis_ctx);
		free(r->redis_prefix);
		free(r);
		free(db);
		return 0;
	  }
#endif /* USE_REDIS */

	  default:
		assert(0);
		return -1;
	}
}

/*
**  DKIMF_DB_STRERROR -- obtain an error string
**
**  Parameters:
**  	db -- DKIMF_DB handle of interest
**  	err -- error buffer
**  	errlen -- bytes available at "err"
**
**  Return value:
**  	Bytes written to "err".
*/

int
dkimf_db_strerror(DKIMF_DB db, char *err, size_t errlen)
{
	assert(db != NULL);
	assert(err != NULL);

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
		return strlcpy(err, strerror(db->db_status), errlen);

	  case DKIMF_DB_TYPE_REFILE:
		return regerror(db->db_status, db->db_data, err, errlen);




#ifdef USE_LUA
	  case DKIMF_DB_TYPE_LUA:
	  {
		struct dkimf_db_lua *lua;

		lua = (struct dkimf_db_lua *) db->db_data;
		if (lua->lua_error != NULL)
			return strlcpy(err, lua->lua_error, errlen);
		else
			return 0;
	  }
#endif /* USE_LUA */



#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
		return strlcpy(err, mdb_strerror(db->db_status), errlen);
#endif /* USE_MDB */

#ifdef USE_REDIS
	  case DKIMF_DB_TYPE_REDIS:
	  {
		struct dkimf_db_redis *r;

		r = (struct dkimf_db_redis *) db->db_data;
		if (r->redis_ctx != NULL && r->redis_ctx->errstr[0] != '\0')
			return strlcpy(err, r->redis_ctx->errstr, errlen);
		return strlcpy(err, "Redis error", errlen);
	  }
#endif /* USE_REDIS */

	  default:
		assert(0);
		return -1;		/* to silence the compiler */
	}

	/* NOTREACHED */
}

/*
**  DKIMF_DB_WALK -- walk a database
**
**  Parameters:
**  	db -- database
**  	first -- get first record?
**  	key -- buffer to receive the key
**  	keylen -- bytes available at "key" (updated)
**  	req -- buffers to receive the data ("requests")
**  	reqnum -- number of requests
**
**  Return value:
**  	0 -- record returned
**  	1 -- no more records
**  	-1 -- error
*/

int
dkimf_db_walk(DKIMF_DB db, _Bool first, void *key, size_t *keylen,
              DKIMF_DBDATA req, unsigned int reqnum)
{
	assert(db != NULL);

	if ((key != NULL && keylen == NULL) ||
	    (key == NULL && keylen != NULL))
		return -1;

	if (db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_LUA)
		return -1;

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_CSL:
	  case DKIMF_DB_TYPE_FILE:
	  {
		struct dkimf_db_list *list;

		if (first)
			list = (struct dkimf_db_list *) db->db_handle;
		else
			list = (struct dkimf_db_list *) db->db_cursor;

		if (list == NULL)
			return 1;

		if (key != NULL)
			*keylen = strlcpy(key, list->db_list_key, *keylen);

		if (reqnum != 0)
		{
			if (list->db_list_value != NULL)
			{
				if (dkimf_db_datasplit(list->db_list_value,
				                       strlen(list->db_list_value),
				                       req, reqnum) != 0)
                                        return -1;
			}
		}

		list = list->db_list_next;
		db->db_cursor = list;

		return 0;
	  }




#ifdef USE_MDB
	  case DKIMF_DB_TYPE_MDB:
	  {
		int status = 0;
		MDB_val k;
		MDB_val d;
		MDB_cursor *dbc;
		struct dkimf_db_mdb *mdb;

		mdb = (struct dkimf_db_mdb *) db->db_data;

		dbc = db->db_cursor;
		if (dbc == NULL)
		{
			status = mdb_cursor_open(mdb->mdb_txn, mdb->mdb_dbi,
			                         &dbc);
			if (status != 0)
			{
				db->db_status = status;
				return -1;
			}

			db->db_cursor = dbc;
		}

		memset(&k, '\0', sizeof k);
		memset(&d, '\0', sizeof d);

		status = mdb_cursor_get(dbc, &k, &d,
		                        first ? MDB_FIRST : MDB_NEXT);
		if (status == MDB_NOTFOUND)
		{
			return 1;
		}
		else if (status != 0)
		{
			db->db_status = status;
			return -1;
		}
		else
		{
			memcpy(key, k.mv_data, MIN(k.mv_size, *keylen));
			*keylen = MIN(k.mv_size, *keylen);

			if (reqnum != 0)
			{
				if (dkimf_db_datasplit(d.mv_data, d.mv_size,
				                       req, reqnum) != 0)
                                        return -1;
			}

			return 0;
		}
	  }
#endif /* USE_MDB */

#ifdef USE_REDIS
	  case DKIMF_DB_TYPE_REDIS:
		return -1;
#endif /* USE_REDIS */

	  default:
		assert(0);
		return -1;		/* to silence compiler warnings */
	}
}

/*
**  DKIMF_DB_MKARRAY_BASE -- make a (char *) array treating the DB as a
**                           delta to a provided base
**
**  Parameters:
**  	db -- a DKIMF_DB handle
**  	a -- array (returned)
**  	base -- base array
** 
**  Return value:
**  	Length of the created array, or -1 on error/empty.
*/

static int
dkimf_db_mkarray_base(DKIMF_DB db, char ***a, const char **base)
{
	_Bool found;
	int c;
	int status;
	int nalloc = 0;
	int nout = 0;
	int nbase;
	size_t buflen;
	char **out = NULL;
	char buf[BUFRSZ + 1];

	assert(db != NULL);
	assert(a != NULL);

	/* count base elements */
	for (nbase = 0; base[nbase] != NULL; nbase++)
		continue;

	/* initialize output array */
	nalloc = MAX(nbase, 16);
	out = (char **) malloc(sizeof(char *) * nalloc);
	if (out == NULL)
		return -1;
	out[0] = NULL;

	/* copy the base array modulo removals in the DB */
	for (c = 0; c < nbase; c++)
	{
		memset(buf, '\0', sizeof buf);

		snprintf(buf, sizeof buf, "-%s", base[c]);

		found = FALSE;
		status = dkimf_db_get(db, buf, 0, NULL, 0, &found);
		if (status != 0)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}

		if (!found)
		{
			if (nout == nalloc - 1)
			{
				char **new;

				new = (char **) realloc(out,
				                        sizeof(char *) * (nalloc * 2));
				if (new == NULL)
				{
					for (c = 0; c < nout; c++)
						free(out[c]);
					free(out);
					return -1;
				}

				out = new;
				nalloc *= 2;
			}

			out[nout] = strdup(base[c]);
			if (out[nout] == NULL)
			{
				for (c = 0; c < nout; c++)
					free(out[c]);
				free(out);
				return -1;
			}

			nout++;
			out[nout] = NULL;
		}
	}

	/* now add any in the DB that aren't in the array */
	for (c = 0; ; c++)
	{
		buflen = sizeof buf - 1;
		memset(buf, '\0', sizeof buf);

		status = dkimf_db_walk(db, (c == 0), buf, &buflen, NULL, 0);
		if (status == -1)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}
		else if (status == 1)
		{
			break;
		}
		else if (buf[0] != '+')
		{
			continue;
		}

		if (nout == nalloc - 1)
		{
			char **new;

			new = (char **) realloc(out,
			                        sizeof(char *) * (nalloc * 2));
			if (new == NULL)
			{
				for (c = 0; c < nout; c++)
					free(out[c]);
				free(out);
				return -1;
			}

			out = new;
			nalloc *= 2;
		}

		out[nout] = strdup(&buf[1]);
		if (out[nout] == NULL)
		{
			for (c = 0; c < nout; c++)
				free(out[c]);
			free(out);
			return -1;
		}

		nout++;
		out[nout] = NULL;
	}

	*a = out;
	return nout;
}

/*
**  DKIMF_DB_MKARRAY -- make a (char *) array of DB contents
**
**  Parameters:
**  	db -- a DKIMF_DB handle
**  	a -- array (returned)
**  	base -- base array (may be NULL)
**
**  Return value:
**  	Length of the created array, or -1 on error/empty.
*/

int
dkimf_db_mkarray(DKIMF_DB db, char ***a, const char **base)
{
	_Bool found;
	int status;
	char **out = NULL;

	assert(db != NULL);
	assert(a != NULL);

	if (db->db_type == DKIMF_DB_TYPE_REFILE ||
	    db->db_type == DKIMF_DB_TYPE_LUA)
		return -1;


	if ((db->db_type == DKIMF_DB_TYPE_FILE ||
	     db->db_type == DKIMF_DB_TYPE_CSL) &&
	    db->db_array != NULL)
	{
		*a = db->db_array;
		return db->db_nrecs;
	}

	found = FALSE;
	status = dkimf_db_get(db, "*", 0, NULL, 0, &found);
	if (status != 0)
		return -1;
	if (found && base != NULL)
		return dkimf_db_mkarray_base(db, a, base);

	switch (db->db_type)
	{
	  case DKIMF_DB_TYPE_FILE:
	  case DKIMF_DB_TYPE_CSL:
	  {
		int c = 0;
		struct dkimf_db_list *cur;

		out = (char **) malloc(sizeof(char *) * (db->db_nrecs + 1));
		if (out != NULL)
		{
			cur = db->db_handle;
			for (c = 0; c < db->db_nrecs; c++)
			{
				out[c] = cur->db_list_key;
				cur = cur->db_list_next;
			}

			out[c] = NULL;
		}

		db->db_array = out;

		*a = out;

		return c;
	  }


	  default:
		return -1;
	}
}

/*
**  DKIMF_DB_REWALK -- walk a regular expression DB looking for matches
**
**  Parameters:
**  	db -- database of interest
**  	str -- string to match
**  	req -- list of data requests
**  	reqnum -- number of data requests
**  	ctx -- context pointer (updated) (may be NULL)
**
**  Return value:
**  	-1 -- error
**  	0 -- match found
**  	1 -- no match found
*/

int
dkimf_db_rewalk(DKIMF_DB db, char *str, DKIMF_DBDATA req, unsigned int reqnum,
                void **ctx)
{
	int status;
	struct dkimf_db_relist *re;

	assert(db != NULL);
	assert(str != NULL);

	if (db->db_type != DKIMF_DB_TYPE_REFILE)
		return -1;

	if (ctx != NULL && *ctx != NULL)
	{
		re = (struct dkimf_db_relist *) *ctx;
		if (re->db_relist_next == NULL)
			return 1;
		else
			re = re->db_relist_next;
	}
	else
	{
		re = (struct dkimf_db_relist *) db->db_handle;
	}

	while (re != NULL)
	{
		status = regexec(&re->db_relist_re, str, 0, NULL, 0);

		if (status == 0)
		{
			if (ctx != NULL)
				*ctx = re;

			if (dkimf_db_datasplit(re->db_relist_data,
			                      strlen(re->db_relist_data),
			                      req, reqnum) != 0)
			{
                                return -1;
			}
			else
			{
                        	return 0;
			}
		}
		else if (status != REG_NOMATCH)
		{
			return -1;
		}

		re = re->db_relist_next;
	}

	return 1;
}


/*
**  DKIMF_DB_CHOWN -- set ownership and permissions on a DB
**
**  Parameters:
**  	db -- DKIMF_DB handle
**  	uid -- target uid
**
**  Return value:
**  	1 -- success
**  	0 -- not a DB that can be chowned
**  	-1 -- fchown() failed
*/

int
dkimf_db_chown(DKIMF_DB db, uid_t uid)
{

	assert(db != NULL);
	assert(uid >= 0);

	return 0;
}
