/*
**  Copyright (c) 2026, OpenDKIM contributors. All rights reserved.
**
**  t-db-redis.c -- unit test for the Redis/Valkey dkimf_db backend
**
**  Assumes a Redis-compatible server is reachable at 127.0.0.1:6379.
**  Skips gracefully (exit 0) if the server is not available.
**
**  Test keys are written under a unique prefix and deleted on exit so
**  the test is safe to run against a live instance.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* redis/valkey client — same shim as opendkim-db.c */
#ifdef USE_LIBVALKEY
# include <valkey/valkey.h>
typedef valkeyContext  redisContext;
typedef valkeyReply    redisReply;
# define redisConnect       valkeyConnect
# define redisCommand       valkeyCommand
# define freeReplyObject    valkeyFreeReplyObject
# define redisFree          valkeyFree
#else
# include <hiredis/hiredis.h>
#endif

/* opendkim-db API */
#include "opendkim-db.h"

#define HOST  "127.0.0.1"
#define PORT  6379
#define PFX   "__opendkim_test__:"

/* ── helpers ────────────────────────────────────────────────────────────────── */

static redisContext *
seed_connect(void)
{
	redisContext *ctx = redisConnect(HOST, PORT);
	if (ctx == NULL || ctx->err != 0)
	{
		if (ctx != NULL)
			redisFree(ctx);
		return NULL;
	}
	return ctx;
}

static void
seed_set(redisContext *ctx, const char *key, const char *val)
{
	redisReply *r = (redisReply *) redisCommand(ctx, "SET %s%s %s",
	                                             PFX, key, val);
	assert(r != NULL);
	freeReplyObject(r);
}

static void
seed_del(redisContext *ctx, const char *key)
{
	redisReply *r = (redisReply *) redisCommand(ctx, "DEL %s%s", PFX, key);
	if (r != NULL)
		freeReplyObject(r);
}

/* ── main ────────────────────────────────────────────────────────────────────── */

int
main(int argc, char **argv)
{
	int status;
	_Bool exists;
	char errbuf[256];
	char *errp;
	DKIMF_DB db;
	redisContext *seed;

	printf("*** Redis/Valkey dkimf_db backend\n");

	/* probe: skip if server is not up */
	seed = seed_connect();
	if (seed == NULL)
	{
		printf("*** SKIP: no Redis/Valkey at %s:%d\n", HOST, PORT);
		return 77;
	}

	/* pre-seed test keys */
	seed_set(seed, "simple",    "hello");
	seed_set(seed, "multi",     "foo:bar:baz");
	seed_set(seed, "emptyval",  "");

	/* ── open: bad URI (missing prefix) ─────────────────────────────────────── */
	errp = NULL;
	status = dkimf_db_open(&db, "redis://" HOST ":6379", 0, NULL, &errp);
	assert(status != 0);

	/* ── open: valid URI with explicit port ──────────────────────────────────── */
	errp = NULL;
	status = dkimf_db_open(&db, "redis://" HOST ":6379/" PFX,
	                        DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status != 0)
	{
		fprintf(stderr, "dkimf_db_open failed: %s\n",
		        errp != NULL ? errp : "(null)");
		seed_del(seed, "simple");
		seed_del(seed, "multi");
		seed_del(seed, "emptyval");
		redisFree(seed);
		return 1;
	}

	/* ── get: key exists, single value, no data extraction ──────────────────── */
	exists = 0;
	status = dkimf_db_get(db, "simple", 6, NULL, 0, &exists);
	assert(status == 0);
	assert(exists == 1);

	/* ── get: key exists, extract first field ────────────────────────────────── */
	{
		char val[64];
		struct dkimf_db_data req;
		memset(&req, 0, sizeof req);
		req.dbdata_buffer = val;
		req.dbdata_buflen = sizeof val;

		exists = 0;
		status = dkimf_db_get(db, "simple", 6, &req, 1, &exists);
		assert(status == 0);
		assert(exists == 1);
		assert(strcmp(val, "hello") == 0);
	}

	/* ── get: colon-separated multi-field ───────────────────────────────────── */
	{
		char f0[64], f1[64], f2[64];
		struct dkimf_db_data req[3];
		memset(req, 0, sizeof req);
		req[0].dbdata_buffer = f0; req[0].dbdata_buflen = sizeof f0;
		req[1].dbdata_buffer = f1; req[1].dbdata_buflen = sizeof f1;
		req[2].dbdata_buffer = f2; req[2].dbdata_buflen = sizeof f2;

		exists = 0;
		status = dkimf_db_get(db, "multi", 5, req, 3, &exists);
		assert(status == 0);
		assert(exists == 1);
		assert(strcmp(f0, "foo") == 0);
		assert(strcmp(f1, "bar") == 0);
		assert(strcmp(f2, "baz") == 0);
	}

	/* ── get: key does not exist ─────────────────────────────────────────────── */
	exists = 1;
	status = dkimf_db_get(db, "nosuchkey", 9, NULL, 0, &exists);
	assert(status == 0);
	assert(exists == 0);

	/* ── get: empty-string value — key present, no data fields ──────────────── */
	exists = 0;
	status = dkimf_db_get(db, "emptyval", 8, NULL, 0, &exists);
	assert(status == 0);
	assert(exists == 1);

	/* ── walk: not supported, must return -1 ────────────────────────────────── */
	{
		char keybuf[64];
		size_t keylen = sizeof keybuf;
		status = dkimf_db_walk(db, 1, keybuf, &keylen, NULL, 0);
		assert(status == -1);
	}

	/* ── strerror: must not crash when called on a healthy connection ─────────── */
	memset(errbuf, 0, sizeof errbuf);
	(void) dkimf_db_strerror(db, errbuf, sizeof errbuf);

	/* ── close ───────────────────────────────────────────────────────────────── */
	status = dkimf_db_close(db);
	assert(status == 0);

	/* ── open: default port (no :port in URI) ────────────────────────────────── */
	errp = NULL;
	status = dkimf_db_open(&db, "redis://" HOST "/" PFX,
	                        DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status != 0)
	{
		fprintf(stderr, "dkimf_db_open (default port) failed: %s\n",
		        errp != NULL ? errp : "(null)");
		seed_del(seed, "simple");
		seed_del(seed, "multi");
		seed_del(seed, "emptyval");
		redisFree(seed);
		return 1;
	}
	exists = 0;
	status = dkimf_db_get(db, "simple", 6, NULL, 0, &exists);
	assert(status == 0);
	assert(exists == 1);
	status = dkimf_db_close(db);
	assert(status == 0);

	/* clean up test keys */
	seed_del(seed, "simple");
	seed_del(seed, "multi");
	seed_del(seed, "emptyval");
	redisFree(seed);

	printf("*** Redis/Valkey dkimf_db backend PASSED\n");
	return 0;
}
