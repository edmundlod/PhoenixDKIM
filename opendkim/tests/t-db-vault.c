/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-vault.c -- end-to-end test for the vault: dkimf_db backend over TLS.
**
**  The vault: open path rewrites vault:// to https:// and forces
**  SSL_VERIFYPEER/VERIFYHOST, so this test stands up a real TLS endpoint:
**  it generates a throwaway self-signed cert (SAN IP:127.0.0.1) with the
**  openssl CLI, forks an OpenSSL HTTPS server that returns a Vault KVv2
**  envelope, and supplies the cert as the CA bundle (HttpCaBundle ->
**  dkimf_db_set_http_cabundle) so the forced peer verification succeeds.
**  Asserts the scheme rewrite, the X-Vault-Token header, and KVv2 field
**  extraction (including \n unescaping) end to end.
**
**  Skips (exit 77) if the openssl CLI is unavailable or a loopback socket
**  cannot be created.  Gated on WITH_CURL.
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

/* OpenSSL (server side) */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* opendkim-db API */
#include "opendkim-db.h"

#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

/* KVv2 envelope; the private_key value carries escaped newlines */
static const char ENVELOPE[] =
	"{\"data\":{\"data\":{\"private_key\":"
	"\"-----BEGIN-----\\nLINE2\\n-----END-----\"},"
	"\"metadata\":{\"version\":1}}}";
static const char EXPECT[] = "-----BEGIN-----\nLINE2\n-----END-----";

static int failures = 0;

static void
ck(const char *name, int cond)
{
	printf("%-40s %s\n", name, cond ? "OK" : "*** FAIL ***");
	if (!cond)
		failures++;
}

/* ── forked TLS server ────────────────────────────────────────────────────── */

static void
ssl_write_all(SSL *ssl, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len)
	{
		int n = SSL_write(ssl, buf + off, (int) (len - off));

		if (n <= 0)
			return;
		off += (size_t) n;
	}
}

static void
serve_one(SSL *ssl)
{
	char req[8192];
	int len = 0;
	_Bool tokened;
	char hdr[128];
	int n;

	if (SSL_accept(ssl) != 1)
		return;

	for (;;)
	{
		int r;

		if (len >= (int) sizeof req - 1)
			break;
		r = SSL_read(ssl, req + len, (int) sizeof req - 1 - len);
		if (r <= 0)
			break;
		len += r;
		req[len] = '\0';
		if (strstr(req, "\r\n\r\n") != NULL)
			break;
	}
	req[len < 0 ? 0 : len] = '\0';

	tokened = (strstr(req, "X-Vault-Token: testtoken\r\n") != NULL);

	if (!tokened)
	{
		const char *body = "missing token";

		n = snprintf(hdr, sizeof hdr,
		             "HTTP/1.0 401 Unauthorized\r\nContent-Length: %zu\r\n"
		             "Connection: close\r\n\r\n", strlen(body));
		if (n > 0)
			ssl_write_all(ssl, hdr, (size_t) n);
		ssl_write_all(ssl, body, strlen(body));
	}
	else
	{
		n = snprintf(hdr, sizeof hdr,
		             "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n"
		             "Connection: close\r\n\r\n", sizeof ENVELOPE - 1);
		if (n > 0)
			ssl_write_all(ssl, hdr, (size_t) n);
		ssl_write_all(ssl, ENVELOPE, sizeof ENVELOPE - 1);
	}

	SSL_shutdown(ssl);
}

static void
run_tls_server(int lfd, const char *cert, const char *key)
{
	SSL_CTX *ctx;

	signal(SIGPIPE, SIG_IGN);

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL ||
	    SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
		_exit(2);

	for (;;)
	{
		int c = accept(lfd, NULL, NULL);
		SSL *ssl;

		if (c < 0)
		{
			if (errno == EINTR)
				continue;
			break;
		}

		ssl = SSL_new(ctx);
		if (ssl != NULL)
		{
			SSL_set_fd(ssl, c);
			serve_one(ssl);
			SSL_free(ssl);
		}
		(void) close(c);
	}

	SSL_CTX_free(ctx);
}

/* ── helpers ──────────────────────────────────────────────────────────────── */

static int
vault_get(DKIMF_DB db, const char *key, char *out, size_t outlen, _Bool *exists)
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
	int fd;
	pid_t pid;
	socklen_t alen;
	struct sockaddr_in addr;
	char certpath[] = "/tmp/t-db-vault-cert-XXXXXX";
	char keypath[] = "/tmp/t-db-vault-key-XXXXXX";
	char cmd[512];
	char uri[256];
	char val[1024];
	const char *errp;
	_Bool exists;
	DKIMF_DB db;

	printf("*** vault: dkimf_db backend over TLS (e2e)\n");

	signal(SIGPIPE, SIG_IGN);
	(void) unsetenv("VAULT_TOKEN");

	fd = mkstemp(certpath);
	if (fd < 0)
		return 77;
	(void) close(fd);
	fd = mkstemp(keypath);
	if (fd < 0)
	{
		(void) unlink(certpath);
		return 77;
	}
	(void) close(fd);

	(void) snprintf(cmd, sizeof cmd,
	                "openssl req -x509 -newkey rsa:2048 -nodes "
	                "-keyout %s -out %s -days 1 -subj /CN=127.0.0.1 "
	                "-addext subjectAltName=IP:127.0.0.1 >/dev/null 2>&1",
	                keypath, certpath);
	if (system(cmd) != 0)
	{
		fprintf(stderr, "*** SKIP: openssl CLI cert generation failed\n");
		(void) unlink(certpath);
		(void) unlink(keypath);
		return 77;
	}

	/* the backend forces SSL_VERIFYPEER; trust our throwaway CA explicitly */
	dkimf_db_set_http_cabundle(certpath);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		goto skip;
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
		goto skip;
	}

	alen = sizeof addr;
	if (getsockname(lfd, (struct sockaddr *) &addr, &alen) < 0)
	{
		(void) close(lfd);
		goto skip;
	}
	port = ntohs(addr.sin_port);

	pid = fork();
	if (pid < 0)
	{
		(void) close(lfd);
		goto skip;
	}
	if (pid == 0)
	{
		run_tls_server(lfd, certpath, keypath);
		_exit(0);
	}
	(void) close(lfd);

	/* ── correct token: vault:// rewrite + X-Vault-Token + KVv2 extract ──── */
	dkimf_db_set_vault_config("testtoken", NULL);
	(void) snprintf(uri, sizeof uri,
	                "vault://127.0.0.1:%d/v1/secret/data/dkim", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	ck("open vault://", status == 0);
	if (status == 0)
	{
		exists = FALSE;
		status = vault_get(db, "example.com", val, sizeof val, &exists);
		ck("get private_key (TLS + KVv2)",
		   status == 0 && exists && strcmp(val, EXPECT) == 0);
		(void) dkimf_db_close(db);
	}
	else
	{
		fprintf(stderr, "open failed: %s\n", errp != NULL ? errp : "(null)");
		ck("get private_key (TLS + KVv2)", 0);
	}

	/* ── no token configured: server rejects with 401 -> get error ───────── */
	dkimf_db_set_vault_config(NULL, NULL);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	if (status == 0)
	{
		exists = FALSE;
		status = vault_get(db, "example.com", val, sizeof val, &exists);
		ck("missing token -> 401 error", status == -1);
		(void) dkimf_db_close(db);
	}
	else
		ck("missing token -> 401 error", 0);

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, NULL, 0);
	(void) unlink(certpath);
	(void) unlink(keypath);

	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;

skip:
	(void) unlink(certpath);
	(void) unlink(keypath);
	return 77;
}
