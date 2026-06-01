/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-vault-sign.c -- end-to-end proof of the vault: emit-all-valid model:
**  one Vault secret carrying four currently-valid selectors -- an OLD and a
**  NEW selector for each of RSA and Ed25519, the rspamd rotation-overlap case
**  -- must yield four DKIM signatures (two rsa-sha256, two ed25519-sha256),
**  each verifiable against its own published key.
**
**  This is the scenario an operator hits during a key roll with algorithm
**  diversity: the old and new selector of each algorithm are signed
**  concurrently so a verifier passes against whichever DNS record it has.
**
**  Fidelity: four keypairs are generated, embedded in a KVv2 envelope, and
**  served over real TLS by a forked OpenSSL server.  The test then requests
**  them back through the *production* vault: path -- dkimf_db_open("vault://")
**  + dkimf_db_vault_selectors() -- exactly as dkimf_add_signrequest_vault()
**  does in the daemon.  Each kept selector is then signed with the daemon's
**  *default* algorithm (DKIM_SIGN_DEFAULT == rsa-sha256), the same single
**  global signalg dkimf_eom() uses; libopendkim derives the real algorithm
**  from the key material, so the Ed25519 selectors must still produce
**  ed25519-sha256.  Every signature is verified offline (DKIM_QUERY_FILE)
**  against its matching public record.
**
**  Skips (exit 77) if the openssl CLI is unavailable, a loopback socket
**  cannot be created, or libopendkim lacks the SHA256/Ed25519 features.
**  Gated on WITH_CURL.
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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL (server side) */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* opendkim-db API + libopendkim sign/verify */
#include "opendkim-db.h"
#include <dkim.h>

#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE 1
#endif

#define T_DOMAIN	"example.com"
#define T_JOBID		"t-db-vault-sign"
#define T_MAXHDR	8192
#define T_SIGNTIME	((uint64_t) 2000)

/* mutable copies so the strict daemon flags (-Wwrite-strings/-Wcast-qual)
** stay happy when these are handed to libopendkim's u_char* parameters */
static char t_jobid[] = T_JOBID;
static char t_domain[] = T_DOMAIN;
static char h_from[] = "From: Joe <joe@example.com>";
static char h_to[] = "To: Suzie <suzie@example.net>";
static char h_subj[] = "Subject: rotation overlap";
static char h_date[] = "Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)";
static char h_msgid[] = "Message-ID: <20030712040037.46341@example.com>";
static char body00[] = "Hi.\r\n\r\nWe rotated the keys.\r\n";

static int failures = 0;

/* the KVv2 envelope the forked server returns; built before fork() */
static char g_envelope[32768];
static size_t g_envlen = 0;

static void
ck(const char *name, int cond)
{
	printf("%-44s %s\n", name, cond ? "OK" : "*** FAIL ***");
	if (!cond)
		failures++;
}

/* ── shell helpers (key generation, public-key extraction) ──────────────── */

static int
run(const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(cmd, sizeof cmd, fmt, ap);
	va_end(ap);

	return system(cmd);
}

static int
capture(char *out, size_t outlen, const char *fmt, ...)
{
	char cmd[1024];
	FILE *p;
	size_t n;
	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(cmd, sizeof cmd, fmt, ap);
	va_end(ap);

	p = popen(cmd, "r");
	if (p == NULL)
		return -1;

	n = fread(out, 1, outlen - 1, p);
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';

	return (pclose(p) == 0) ? 0 : -1;
}

static int
slurp(const char *path, char *buf, size_t buflen)
{
	FILE *f;
	size_t n;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;
	n = fread(buf, 1, buflen - 1, f);
	buf[n] = '\0';
	(void) fclose(f);

	return (n > 0) ? 0 : -1;
}

/* escape a PEM string for embedding in a JSON string value */
static void
json_escape(const char *in, char *out, size_t outlen)
{
	size_t o = 0;

	for (; *in != '\0' && o + 2 < outlen; in++)
	{
		switch (*in)
		{
		  case '\n':	out[o++] = '\\'; out[o++] = 'n'; break;
		  case '\r':	out[o++] = '\\'; out[o++] = 'r'; break;
		  case '"':	out[o++] = '\\'; out[o++] = '"'; break;
		  case '\\':	out[o++] = '\\'; out[o++] = '\\'; break;
		  default:	out[o++] = *in; break;
		}
	}
	out[o] = '\0';
}

/* ── forked TLS server (serves g_envelope on a valid X-Vault-Token) ─────── */

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

	if (strstr(req, "X-Vault-Token: testtoken\r\n") == NULL)
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
		             "Connection: close\r\n\r\n", g_envlen);
		if (n > 0)
			ssl_write_all(ssl, hdr, (size_t) n);
		ssl_write_all(ssl, g_envelope, g_envlen);
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

/* ── libopendkim sign + offline verify of one selector ──────────────────── */

static void
feed_headers(DKIM *d)
{
	(void) dkim_header(d, (u_char *) h_from, strlen(h_from));
	(void) dkim_header(d, (u_char *) h_to, strlen(h_to));
	(void) dkim_header(d, (u_char *) h_subj, strlen(h_subj));
	(void) dkim_header(d, (u_char *) h_date, strlen(h_date));
	(void) dkim_header(d, (u_char *) h_msgid, strlen(h_msgid));
}

/*
**  Sign a standard message with one selector's key using the daemon default
**  algorithm, verify the result offline, and report the algorithm libopendkim
**  actually chose.  Returns 1 on a clean verified round-trip.
*/

static int
sign_verify(DKIM_LIB *lib, struct dkimf_vault_selector *sel,
            char *alg_out, size_t alg_outlen)
{
	DKIM *sd;
	DKIM *vd;
	DKIM_STAT st;
	int wn;
	u_char hdr[T_MAXHDR + 1];
	u_char inhdr[T_MAXHDR * 2];
	char selneedle[DKIMF_DB_VAULT_SELLEN + 4];
	char *a;

	sd = dkim_sign(lib, (u_char *) t_jobid, NULL,
	               (dkim_sigkey_t) sel->vs_key,
	               (u_char *) sel->vs_selector, (u_char *) t_domain,
	               DKIM_CANON_RELAXED, DKIM_CANON_RELAXED,
	               DKIM_SIGN_DEFAULT, -1L, &st);
	if (sd == NULL || st != DKIM_STAT_OK)
		return 0;

	feed_headers(sd);
	if (dkim_eoh(sd) != DKIM_STAT_OK ||
	    dkim_body(sd, (u_char *) body00, strlen(body00)) != DKIM_STAT_OK ||
	    dkim_eom(sd, NULL) != DKIM_STAT_OK)
	{
		(void) dkim_free(sd);
		return 0;
	}

	memset(hdr, '\0', sizeof hdr);
	if (dkim_getsighdr(sd, hdr, sizeof hdr,
	                   strlen(DKIM_SIGNHEADER) + 2) != DKIM_STAT_OK)
	{
		(void) dkim_free(sd);
		return 0;
	}
	(void) dkim_free(sd);

	/* record the algorithm libopendkim chose from the key material */
	alg_out[0] = '\0';
	a = strstr((char *) hdr, "a=");
	if (a != NULL)
	{
		size_t i = 0;

		a += 2;
		while (a[i] != '\0' && a[i] != ';' && a[i] != ' ' &&
		       a[i] != '\r' && a[i] != '\n' && i < alg_outlen - 1)
		{
			alg_out[i] = a[i];
			i++;
		}
		alg_out[i] = '\0';
	}

	/* the produced signature must carry this selector */
	(void) snprintf(selneedle, sizeof selneedle, "s=%s", sel->vs_selector);
	if (strstr((char *) hdr, selneedle) == NULL)
		return 0;

	/* verify the signature offline against the published key */
	vd = dkim_verify(lib, (u_char *) t_jobid, NULL, &st);
	if (vd == NULL)
		return 0;

	wn = snprintf((char *) inhdr, sizeof inhdr, "%s: %s",
	              DKIM_SIGNHEADER, (char *) hdr);
	if (wn < 0 || (size_t) wn >= sizeof inhdr ||
	    dkim_header(vd, inhdr, (size_t) wn) != DKIM_STAT_OK)
	{
		(void) dkim_free(vd);
		return 0;
	}

	feed_headers(vd);
	if (dkim_eoh(vd) != DKIM_STAT_OK ||
	    dkim_body(vd, (u_char *) body00, strlen(body00)) != DKIM_STAT_OK)
	{
		(void) dkim_free(vd);
		return 0;
	}

	st = dkim_eom(vd, NULL);
	(void) dkim_free(vd);

	return (st == DKIM_STAT_OK);
}

/* ── key material: four keypairs, the verify key file, and the envelope ─── */

static const struct
{
	const char *	sel;
	_Bool		rsa;
} KEYS[4] = {
	{ "rsa-old", TRUE },
	{ "rsa-new", TRUE },
	{ "ed-old",  FALSE },
	{ "ed-new",  FALSE },
};

/*
**  Generate the four keypairs into "dir", write the DKIM_QUERY_FILE verify
**  records to "keyfile", and build g_envelope (selectors all valid at
**  T_SIGNTIME).  Returns 0 on success, 77 to signal a skip.
*/

static int
build_keys(const char *dir, const char *keyfile)
{
	FILE *kf;
	size_t off;
	unsigned int i;

	kf = fopen(keyfile, "w");
	if (kf == NULL)
		return 77;

	off = 0;
	off += (size_t) snprintf(g_envelope + off, sizeof g_envelope - off,
	                         "{\"data\":{\"data\":{\"selectors\":[");

	for (i = 0; i < 4; i++)
	{
		char path[300];
		char pem[8192];
		char escaped[16384];
		char pub[2048];
		int rc;

		(void) snprintf(path, sizeof path, "%s/%s.pem", dir, KEYS[i].sel);

		if (KEYS[i].rsa)
			rc = run("openssl genpkey -algorithm RSA "
			         "-pkeyopt rsa_keygen_bits:2048 -out %s "
			         ">/dev/null 2>&1", path);
		else
			rc = run("openssl genpkey -algorithm ED25519 -out %s "
			         ">/dev/null 2>&1", path);
		if (rc != 0)
		{
			(void) fclose(kf);
			fprintf(stderr, "*** SKIP: openssl keygen failed\n");
			return 77;
		}

		if (slurp(path, pem, sizeof pem) != 0)
		{
			(void) fclose(kf);
			return 77;
		}

		/* publish the DKIM record used for offline verification */
		if (KEYS[i].rsa)
		{
			if (capture(pub, sizeof pub,
			            "openssl pkey -in %s -pubout -outform DER "
			            "2>/dev/null | openssl base64 -A", path) != 0)
			{
				(void) fclose(kf);
				return 77;
			}
			fprintf(kf, "%s._domainkey.%s v=DKIM1; k=rsa; p=%s\n",
			        KEYS[i].sel, T_DOMAIN, pub);
		}
		else
		{
			/* DKIM Ed25519 p= is the raw 32-byte key (tail of the SPKI) */
			if (capture(pub, sizeof pub,
			            "openssl pkey -in %s -pubout -outform DER "
			            "2>/dev/null | tail -c 32 | openssl base64 -A",
			            path) != 0)
			{
				(void) fclose(kf);
				return 77;
			}
			fprintf(kf, "%s._domainkey.%s v=DKIM1; k=ed25519; p=%s\n",
			        KEYS[i].sel, T_DOMAIN, pub);
		}

		json_escape(pem, escaped, sizeof escaped);

		off += (size_t) snprintf(g_envelope + off,
		                         sizeof g_envelope - off,
		                         "%s{\"selector\":\"%s\",\"key\":\"%s\","
		                         "\"valid_start\":1000,\"valid_end\":3000}",
		                         i == 0 ? "" : ",", KEYS[i].sel, escaped);
	}

	off += (size_t) snprintf(g_envelope + off, sizeof g_envelope - off,
	                         "]}}}");
	(void) fclose(kf);

	if (off >= sizeof g_envelope)
	{
		fprintf(stderr, "*** envelope buffer overflow\n");
		return 1;
	}
	g_envlen = off;

	return 0;
}

int
main(void)
{
	int lfd;
	int port;
	pid_t pid;
	socklen_t alen;
	struct sockaddr_in addr;
	struct dkimf_vault_selector *sels = NULL;
	unsigned int n = 0;
	unsigned int i;
	int status;
	int fd;
	int nrsa = 0;
	int ned = 0;
	char certpath[] = "/tmp/t-db-vault-sign-cert-XXXXXX";
	char keypath[] = "/tmp/t-db-vault-sign-key-XXXXXX";
	char dir[] = "/tmp/t-db-vault-sign-XXXXXX";
	char keyfile[300];
	char cmd[512];
	char uri[256];
	const char *errp;
	DKIMF_DB db;
	DKIM_LIB *lib;
	dkim_query_t qtype = DKIM_QUERY_FILE;
	uint64_t fixed = T_SIGNTIME;

	printf("*** vault: emit-all-valid four-key signing (RSA+Ed25519 roll)\n");

	signal(SIGPIPE, SIG_IGN);
	(void) unsetenv("VAULT_TOKEN");

	if (mkdtemp(dir) == NULL)
		return 77;
	(void) snprintf(keyfile, sizeof keyfile, "%s/keys", dir);

	status = build_keys(dir, keyfile);
	if (status != 0)
	{
		(void) run("rm -rf %s >/dev/null 2>&1", dir);
		return status;
	}

	/* ── self-signed cert for the TLS server (trusted via the test seam) ── */
	fd = mkstemp(certpath);
	if (fd < 0)
		goto skip;
	(void) close(fd);
	fd = mkstemp(keypath);
	if (fd < 0)
	{
		(void) unlink(certpath);
		goto skip;
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
		goto skip;
	}

	dkimf_db_set_http_cabundle(certpath);

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		goto skip_cert;
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
		goto skip_cert;
	}

	alen = sizeof addr;
	if (getsockname(lfd, (struct sockaddr *) &addr, &alen) < 0)
	{
		(void) close(lfd);
		goto skip_cert;
	}
	port = ntohs(addr.sin_port);

	pid = fork();
	if (pid < 0)
	{
		(void) close(lfd);
		goto skip_cert;
	}
	if (pid == 0)
	{
		run_tls_server(lfd, certpath, keypath);
		_exit(0);
	}
	(void) close(lfd);

	/* ── request the secret back through the production vault: path ─────── */
	dkimf_db_set_vault_config("testtoken", NULL);
	(void) snprintf(uri, sizeof uri,
	                "vault://127.0.0.1:%d/v1/secret/data/dkim", port);
	errp = NULL;
	status = dkimf_db_open(&db, uri, DKIMF_DB_FLAG_READONLY, NULL, &errp);
	ck("open vault://", status == 0);

	if (status == 0)
	{
		status = dkimf_db_vault_selectors(db, "roll", 0,
		                                  (time_t) T_SIGNTIME, &sels, &n);
		ck("vault returns four valid selectors",
		   status == 0 && n == 4);
		(void) dkimf_db_close(db);
	}
	else
	{
		fprintf(stderr, "open failed: %s\n", errp != NULL ? errp : "(null)");
		ck("vault returns four valid selectors", 0);
	}

	(void) kill(pid, SIGTERM);
	(void) waitpid(pid, NULL, 0);

	if (status != 0 || n != 4)
		goto done;

	/* ── sign each kept selector with the daemon default algorithm ──────── */
	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
		goto done;

	if (!dkim_libfeature(lib, DKIM_FEATURE_SHA256)
#ifdef DKIM_FEATURE_ED25519
	    || !dkim_libfeature(lib, DKIM_FEATURE_ED25519)
#endif
	   )
	{
		dkim_close(lib);
		fprintf(stderr, "*** SKIP: required libopendkim feature missing\n");
		free(sels);
		(void) unlink(certpath);
		(void) unlink(keypath);
		(void) run("rm -rf %s >/dev/null 2>&1", dir);
		return 77;
	}

	(void) dkim_setopt(lib, DKIM_OPTS_FIXEDTIME, &fixed, sizeof fixed);
	(void) dkim_setopt(lib, DKIM_OPTS_QUERYMETHOD, &qtype, sizeof qtype);
	(void) dkim_setopt(lib, DKIM_OPTS_QUERYINFO, keyfile, strlen(keyfile));

	for (i = 0; i < n; i++)
	{
		char alg[64];
		char label[DKIMF_DB_VAULT_SELLEN + 128];
		_Bool want_rsa;
		int ok;

		ok = sign_verify(lib, &sels[i], alg, sizeof alg);
		want_rsa = (strncmp(sels[i].vs_selector, "rsa", 3) == 0);

		(void) snprintf(label, sizeof label, "sign+verify %s (%s)",
		                sels[i].vs_selector, alg[0] ? alg : "?");

		if (want_rsa)
		{
			ck(label, ok && strcmp(alg, "rsa-sha256") == 0);
			if (ok && strcmp(alg, "rsa-sha256") == 0)
				nrsa++;
		}
		else
		{
			ck(label, ok && strcmp(alg, "ed25519-sha256") == 0);
			if (ok && strcmp(alg, "ed25519-sha256") == 0)
				ned++;
		}
	}

	ck("two rsa-sha256 + two ed25519-sha256", nrsa == 2 && ned == 2);

	dkim_close(lib);

  done:
	free(sels);
	(void) unlink(certpath);
	(void) unlink(keypath);
	(void) run("rm -rf %s >/dev/null 2>&1", dir);
	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;

  skip_cert:
	(void) unlink(certpath);
	(void) unlink(keypath);
  skip:
	(void) run("rm -rf %s >/dev/null 2>&1", dir);
	return 77;
}
