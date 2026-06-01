/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-http.c -- end-to-end test for the http: dkimf_db backend.
**
**  Self-contained: forks a minimal HTTP/1.0 server bound to an ephemeral
**  127.0.0.1 port and drives the real backend (dkimf_db_open / _get) against
**  it.  No external service and no network egress, so it always runs.
**
**  The vault: backend rewrites vault:// to https:// and forces TLS peer
**  verification, so an end-to-end vault test would need a trusted certificate;
**  its JSON extraction is covered offline by t-db-parsers.  This test covers
**  the shared transport: status handling, trailing-CRLF stripping, token and
**  {d}/{s} substitution, bearer auth, and SSRF rejection in the get path.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* opendkim-db API */
#include "phoenixdkim-db.h"

#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

static int failures = 0;

static void
ck(const char *name, int cond)
{
	printf("%-40s %s\n", name, cond ? "OK" : "*** FAIL ***");
	if (!cond)
		failures++;
}

/* ── minimal forked HTTP server ───────────────────────────────────────────── */

static ssize_t
write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len)
	{
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t) n;
	}

	return (ssize_t) off;
}

static void
send_resp(int c, int code, const char *status, const char *body)
{
	char hdr[256];
	size_t blen = (body != NULL) ? strlen(body) : 0;
	int n;

	n = snprintf(hdr, sizeof hdr,
	             "HTTP/1.0 %d %s\r\nContent-Length: %zu\r\n"
	             "Connection: close\r\n\r\n",
	             code, status, blen);
	if (n > 0)
		(void) write_all(c, hdr, (size_t) n);
	if (blen > 0)
		(void) write_all(c, body, blen);
}

static void
handle_conn(int c)
{
	char req[8192];
	size_t len = 0;
	_Bool authed;
	const char *path;
	char *sp;
	char pathbuf[2048];

	/* read request headers (GET has no body) */
	for (;;)
	{
		ssize_t n;

		if (len >= sizeof req - 1)
			break;
		n = read(c, req + len, sizeof req - 1 - len);
		if (n <= 0)
		{
			if (n < 0 && errno == EINTR)
				continue;
			break;
		}
		len += (size_t) n;
		req[len] = '\0';
		if (strstr(req, "\r\n\r\n") != NULL)
			break;
	}
	req[len] = '\0';

	authed = (strstr(req, "Authorization: Bearer testtoken\r\n") != NULL);

	/* extract the request-target from "GET <path> HTTP/1.x" */
	path = "/";
	if (strncmp(req, "GET ", 4) == 0)
	{
		(void) strncpy(pathbuf, req + 4, sizeof pathbuf - 1);
		pathbuf[sizeof pathbuf - 1] = '\0';
		sp = strchr(pathbuf, ' ');
		if (sp != NULL)
			*sp = '\0';
		path = pathbuf;
	}

	if (strstr(path, "/auth") != NULL)
		send_resp(c, authed ? 200 : 401, authed ? "OK" : "Unauthorized",
		          authed ? "ok" : NULL);
	else if (strstr(path, "/miss") != NULL)
		send_resp(c, 404, "Not Found", NULL);
	else if (strstr(path, "/err") != NULL)
		send_resp(c, 500, "Server Error", NULL);
	else if (strstr(path, "/multi") != NULL)
		send_resp(c, 200, "OK", "foo:bar:baz\r\n");
	else if (strstr(path, "/key/example.com/sel") != NULL)
		send_resp(c, 200, "OK", "PEMDATA\r\n");
	else if (strstr(path, "/lookup") != NULL && strstr(path, "?key=") != NULL)
		send_resp(c, 200, "OK", "queryok\r\n");
	else
		send_resp(c, 404, "Not Found", NULL);
}

static void
run_server(int lfd)
{
	signal(SIGPIPE, SIG_IGN);

	for (;;)
	{
		int c = accept(lfd, NULL, NULL);

		if (c < 0)
		{
			if (errno == EINTR)
				continue;
			break;
		}
		handle_conn(c);
		(void) close(c);
	}
}

/* ── helpers driving the backend ──────────────────────────────────────────── */

static int
get_value(DKIMF_DB db, const char *key, char *out, size_t outlen, _Bool *exists)
{
	struct dkimf_db_data req;

	memset(&req, 0, sizeof req);
	req.dbdata_buffer = out;
	req.dbdata_buflen = outlen;
	out[0] = '\0';

	return dkimf_db_get(db, key, strlen(key), &req, 1, exists);
}

int
main(void)
{
	int lfd;
	int port;
	int status;
	pid_t pid;
	socklen_t alen;
	struct sockaddr_in addr;
	char uri[256];
	const char *errp;
	_Bool exists;
	char val[256];
	DKIMF_DB db;

	printf("*** http: dkimf_db backend (e2e)\n");

	signal(SIGPIPE, SIG_IGN);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return 77;			/* environment can't host the test */
	}

	{
		int one = 1;
		(void) setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	}

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(lfd, (struct sockaddr *) &addr, sizeof addr) < 0 ||
	    listen(lfd, 16) < 0)
	{
		fprintf(stderr, "bind/listen: %s\n", strerror(errno));
		(void) close(lfd);
		return 77;
	}

	alen = sizeof addr;
	if (getsockname(lfd, (struct sockaddr *) &addr, &alen) < 0)
	{
		fprintf(stderr, "getsockname: %s\n", strerror(errno));
		(void) close(lfd);
		return 77;
	}
	port = ntohs(addr.sin_port);

	pid = fork();
	if (pid < 0)
	{
		fprintf(stderr, "fork: %s\n", strerror(errno));
		(void) close(lfd);
		return 77;
	}
	if (pid == 0)
	{
		run_server(lfd);
		_exit(0);
	}
	(void) close(lfd);

	/* ── 200 with {d}/{s} substitution + trailing-CRLF strip ─────────────── */
	dkimf_db_set_http_config(NULL, NULL, 5);
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/key/{d}/{s}", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	ck("open http {d}/{s}", status == 0);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "example.com:sel", val, sizeof val, &exists);
		ck("get 200 value", status == 0 && exists && strcmp(val, "PEMDATA") == 0);
		(void) dkimf_db_close(db);
	}

	/* ── multi-field colon split ─────────────────────────────────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/multi/{key}", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		char f0[64], f1[64], f2[64];
		struct dkimf_db_data req[3];

		memset(req, 0, sizeof req);
		req[0].dbdata_buffer = f0; req[0].dbdata_buflen = sizeof f0;
		req[1].dbdata_buffer = f1; req[1].dbdata_buflen = sizeof f1;
		req[2].dbdata_buffer = f2; req[2].dbdata_buflen = sizeof f2;

		exists = FALSE;
		status = dkimf_db_get(db, "x", 1, req, 3, &exists);
		ck("get multi-field split",
		   status == 0 && exists && strcmp(f0, "foo") == 0 &&
		   strcmp(f1, "bar") == 0 && strcmp(f2, "baz") == 0);
		(void) dkimf_db_close(db);
	}
	else
		ck("get multi-field split", 0);

	/* ── 404 is a miss, not an error ─────────────────────────────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/miss/{key}", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = TRUE;
		status = get_value(db, "nope", val, sizeof val, &exists);
		ck("get 404 miss", status == 0 && !exists);
		(void) dkimf_db_close(db);
	}
	else
		ck("get 404 miss", 0);

	/* ── 5xx is an error ─────────────────────────────────────────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/err/{key}", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "x", val, sizeof val, &exists);
		ck("get 5xx error", status == -1);
		(void) dkimf_db_close(db);
	}
	else
		ck("get 5xx error", 0);

	/* ── no-token path appends ?key=<encoded> ────────────────────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/lookup", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "example.com", val, sizeof val, &exists);
		ck("get ?key= fallback",
		   status == 0 && exists && strcmp(val, "queryok") == 0);
		(void) dkimf_db_close(db);
	}
	else
		ck("get ?key= fallback", 0);

	/* ── bearer auth: required and rejected without a token ──────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/auth/{key}", port);
	dkimf_db_set_http_config(NULL, NULL, 5);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "x", val, sizeof val, &exists);
		ck("get auth missing -> 401 error", status == -1);
		(void) dkimf_db_close(db);
	}
	else
		ck("get auth missing -> 401 error", 0);

	/* ── bearer auth: accepted with the configured token ─────────────────── */
	dkimf_db_set_http_config("testtoken", NULL, 5);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "x", val, sizeof val, &exists);
		ck("get auth present -> 200",
		   status == 0 && exists && strcmp(val, "ok") == 0);
		(void) dkimf_db_close(db);
	}
	else
		ck("get auth present -> 200", 0);
	dkimf_db_set_http_config(NULL, NULL, 5);

	/* ── SSRF: an unsafe key is rejected before any request ──────────────── */
	(void) snprintf(uri, sizeof uri, "http://127.0.0.1:%d/key/{key}", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = get_value(db, "ev/il", val, sizeof val, &exists);
		ck("get rejects unsafe key", status == -1);
		(void) dkimf_db_close(db);
	}
	else
		ck("get rejects unsafe key", 0);

	/* ── shut the server down ────────────────────────────────────────────── */
	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, NULL, 0);

	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;
}
