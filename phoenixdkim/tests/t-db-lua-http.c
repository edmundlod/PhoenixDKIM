/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-lua-http.c -- integration test for pdkim.http_get() in the Lua sandbox.
**
**  Drives the lua: dkimf_db backend with a script that calls pdkim.http_get()
**  against a self-contained forked HTTP/1.0 server on an ephemeral 127.0.0.1
**  port.  The lookup key carries the full URL (so the dynamic port reaches the
**  static script via the "query" global).  No external service, no egress.
**
**  Requires both USE_LUA and HAVE_LIBCURL; the CTest target is gated on
**  WITH_LUA AND WITH_CURL.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
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

static const char SCRIPT[] =
	"if query == nil then return nil end\n"
	"local body, err = pdkim.http_get(query, "
	"{ token = \"testtoken\", timeout = 5 })\n"
	"if body == nil then return \"MISS:\" .. tostring(err) end\n"
	"return body\n";

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

	if (strstr(req, "GET /auth") != NULL)
		send_resp(c, authed ? 200 : 401, authed ? "OK" : "Unauthorized",
		          authed ? "authok" : NULL);
	else if (strstr(req, "GET /miss") != NULL)
		send_resp(c, 404, "Not Found", NULL);
	else if (strstr(req, "GET /ok") != NULL)
		send_resp(c, 200, "OK", "luaval");
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

/* ── helpers ──────────────────────────────────────────────────────────────── */

static int
lua_get(DKIMF_DB db, const char *url, char *out, size_t outlen, _Bool *exists)
{
	struct dkimf_db_data req;

	memset(&req, 0, sizeof req);
	req.dbdata_buffer = out;
	req.dbdata_buflen = outlen;
	out[0] = '\0';

	return dkimf_db_get(db, url, strlen(url), &req, 1, exists);
}

int
main(void)
{
	int lfd;
	int port;
	int status;
	int fd;
	pid_t pid;
	socklen_t alen;
	struct sockaddr_in addr;
	char scriptpath[] = "/tmp/t-db-lua-http-XXXXXX";
	char uri[256];
	char url[256];
	char val[256];
	const char *errp;
	_Bool exists;
	DKIMF_DB db;

	printf("*** pdkim.http_get() via lua: backend (integration)\n");

	signal(SIGPIPE, SIG_IGN);

	/* materialise the Lua script on disk for the lua: backend to load */
	fd = mkstemp(scriptpath);
	if (fd < 0)
	{
		fprintf(stderr, "mkstemp: %s\n", strerror(errno));
		return 77;
	}
	if (write_all(fd, SCRIPT, sizeof SCRIPT - 1) < 0)
	{
		fprintf(stderr, "write script: %s\n", strerror(errno));
		(void) close(fd);
		(void) unlink(scriptpath);
		return 77;
	}
	(void) close(fd);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
	{
		(void) unlink(scriptpath);
		return 77;
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
		(void) close(lfd);
		(void) unlink(scriptpath);
		return 77;
	}

	alen = sizeof addr;
	if (getsockname(lfd, (struct sockaddr *) &addr, &alen) < 0)
	{
		(void) close(lfd);
		(void) unlink(scriptpath);
		return 77;
	}
	port = ntohs(addr.sin_port);

	pid = fork();
	if (pid < 0)
	{
		(void) close(lfd);
		(void) unlink(scriptpath);
		return 77;
	}
	if (pid == 0)
	{
		run_server(lfd);
		_exit(0);
	}
	(void) close(lfd);

	(void) snprintf(uri, sizeof uri, "lua:%s", scriptpath);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	ck("open lua: script", status == 0);

	if (status == 0)
	{
		/* happy path: pdkim.http_get returns the 200 body verbatim */
		(void) snprintf(url, sizeof url, "http://127.0.0.1:%d/ok", port);
		exists = FALSE;
		status = lua_get(db, url, val, sizeof val, &exists);
		ck("http_get 200 body",
		   status == 0 && exists && strcmp(val, "luaval") == 0);

		/* opts.token becomes the Bearer header the /auth route requires */
		(void) snprintf(url, sizeof url, "http://127.0.0.1:%d/auth", port);
		exists = FALSE;
		status = lua_get(db, url, val, sizeof val, &exists);
		ck("http_get opts.token auth",
		   status == 0 && exists && strcmp(val, "authok") == 0);

		/* failure path: 404 yields nil, script maps it to a MISS sentinel */
		(void) snprintf(url, sizeof url, "http://127.0.0.1:%d/miss", port);
		exists = FALSE;
		status = lua_get(db, url, val, sizeof val, &exists);
		ck("http_get 404 -> nil",
		   status == 0 && exists && strncmp(val, "MISS", 4) == 0);

		(void) dkimf_db_close(db);
	}
	else
	{
		fprintf(stderr, "dkimf_db_open failed: %s\n",
		        errp != NULL ? errp : "(null)");
		ck("http_get 200 body", 0);
		ck("http_get opts.token auth", 0);
		ck("http_get 404 -> nil", 0);
	}

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, NULL, 0);
	(void) unlink(scriptpath);

	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;
}
