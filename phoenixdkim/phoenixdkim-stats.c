/*
**  Copyright (c) 2026, The PhoenixDKIM Authors.  All rights reserved.
**
**  phoenixdkim-stats.c -- in-process metrics counters plus a Prometheus
**                         textfile writer and a StatsD UDP pusher.
**
**  Design notes
**  ------------
**  * The counters are C11 atomics, so the hot-path recorders are lock-free and
**    safe to call from every milter worker thread.  Counter increments use
**    relaxed ordering: we only ever need eventual, monotonic totals, never an
**    ordering relationship with other memory.
**  * Labels with unbounded cardinality (e.g. the signing domain) are
**    deliberately NOT used; they belong in the per-message log line, not in a
**    time series.  Only bounded enums (result, algorithm) appear as labels.
**  * StatsD has no label concept, so the same events are emitted there with the
**    label values folded into dotted metric names.
**  * Both exporters are pure POSIX; nothing here pulls in an external library.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>

/* libphoenixdkim includes (for the DKIM_SIGN_* algorithm constants) */
#include <dkim.h>

/* phoenixdkim includes */
#include "phoenixdkim-stats.h"

/* signing-algorithm label slots */
#define ST_ALG_RSASHA256	0
#define ST_ALG_ED25519		1
#define ST_ALG_RSASHA1		2
#define ST_ALG_OTHER		3
#define ST_ALG_MAX		4

static const char *st_alg_label[ST_ALG_MAX] =
{
	"rsa-sha256",
	"ed25519-sha256",
	"rsa-sha1",
	"other",
};

static const char *st_verify_label[DKIMF_STATS_V_MAX] =
{
	"pass",
	"fail",
	"none",
	"neutral",
	"policy",
	"temperror",
	"permerror",
};

static const char *st_dns_label[DKIMF_STATS_DNS_MAX] =
{
	"success",
	"timeout",
	"error",
};

static const char *st_dnssec_label[DKIMF_STATS_DNSSEC_MAX] =
{
	"secure",
	"insecure",
	"bogus",
	"unavailable",
	"unknown",
};

/* DNS latency histogram bucket upper bounds, in seconds */
static const double st_dns_bounds[] =
{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
};
#define ST_DNS_NBUCKETS	(sizeof st_dns_bounds / sizeof st_dns_bounds[0])

/* counters */
static atomic_uint_fast64_t st_messages;
static atomic_uint_fast64_t st_sign[2][ST_ALG_MAX];	/* [ok ? 1 : 0][alg] */
static atomic_uint_fast64_t st_verify[DKIMF_STATS_V_MAX];
static atomic_uint_fast64_t st_dnssec[DKIMF_STATS_DNSSEC_MAX];
static atomic_uint_fast64_t st_dns_queries;
static atomic_uint_fast64_t st_dns_results[DKIMF_STATS_DNS_MAX];
static atomic_uint_fast64_t st_dns_bucket[ST_DNS_NBUCKETS];	/* cumulative (le) */
static atomic_uint_fast64_t st_dns_count;
static atomic_uint_fast64_t st_dns_sum_us;		/* microseconds */

/* identity / exporter state */
static char st_version[64] = "unknown";
static char st_prefix[64] = "phoenixdkim";
static int st_statsd_fd = -1;
static char st_metrics_path[1024];
static unsigned int st_metrics_interval;

/*
**  DKIMF_STATS_ALGSLOT -- map a DKIM_SIGN_* value to a label slot
*/

static int
dkimf_stats_algslot(int signalg)
{
	switch (signalg)
	{
	  case DKIM_SIGN_RSASHA256:
		return ST_ALG_RSASHA256;
	  case DKIM_SIGN_ED25519SHA256:
		return ST_ALG_ED25519;
	  case DKIM_SIGN_RSASHA1:
		return ST_ALG_RSASHA1;
	  default:
		return ST_ALG_OTHER;
	}
}

/*
**  DKIMF_STATS_INIT -- record the daemon version for the build_info gauge
*/

void
dkimf_stats_init(const char *version)
{
	if (version != NULL)
		snprintf(st_version, sizeof st_version, "%s", version);
}

/* ============================ StatsD pusher ============================ */

/*
**  DKIMF_STATS_STATSD_SEND -- format and fire a single StatsD UDP packet
**
**  Errors (including a full/blocked socket) are deliberately ignored: StatsD
**  is fire-and-forget, and a stalled collector must never throttle the milter.
*/

static void
dkimf_stats_statsd_send(const char *fmt, ...)
{
	int fd;
	int n;
	va_list ap;
	char buf[256];

	fd = st_statsd_fd;
	if (fd < 0)
		return;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	if (n <= 0 || (size_t) n >= sizeof buf)
		return;

	(void) send(fd, buf, (size_t) n, 0);
}

/*
**  DKIMF_STATS_SET_STATSD -- open the StatsD UDP socket
**
**  Parameters:
**  	hostport -- "host:port" (or "host", defaulting to port 8125)
**  	prefix -- metric name prefix (NULL keeps the default "phoenixdkim")
**
**  Return value:
**  	0 on success, -1 on failure.
*/

int
dkimf_stats_set_statsd(const char *hostport, const char *prefix)
{
	int fd;
	int flags;
	int status;
	char *colon;
	const char *port = "8125";
	char host[256];
	struct addrinfo hints;
	struct addrinfo *res = NULL;

	if (hostport == NULL)
		return -1;

	if (prefix != NULL && prefix[0] != '\0')
		snprintf(st_prefix, sizeof st_prefix, "%s", prefix);

	snprintf(host, sizeof host, "%s", hostport);

	/* split off ":port"; cope with bracketed IPv6 literals */
	if (host[0] == '[')
	{
		char *end = strchr(host, ']');

		if (end != NULL)
		{
			*end = '\0';			/* terminate the address */
			if (end[1] == ':')
				port = end + 2;		/* stable: past the address */
			/* drop the leading '[' in place */
			memmove(host, host + 1, strlen(host + 1) + 1);
		}
	}
	else
	{
		colon = strrchr(host, ':');
		if (colon != NULL)
		{
			*colon = '\0';
			port = colon + 1;
		}
	}

	memset(&hints, '\0', sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	status = getaddrinfo(host, port, &hints, &res);
	if (status != 0 || res == NULL)
	{
		syslog(LOG_ERR, "StatsDHost: cannot resolve \"%s\": %s",
		       hostport, gai_strerror(status));
		return -1;
	}

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0)
	{
		syslog(LOG_ERR, "StatsDHost: socket() failed: %s",
		       strerror(errno));
		freeaddrinfo(res);
		return -1;
	}

	/* connect() so later sends need no address and so we learn the route */
	if (connect(fd, res->ai_addr, res->ai_addrlen) != 0)
	{
		syslog(LOG_ERR, "StatsDHost: connect(\"%s\") failed: %s",
		       hostport, strerror(errno));
		close(fd);
		freeaddrinfo(res);
		return -1;
	}

	freeaddrinfo(res);

	/* never let a backed-up socket block a worker thread */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	st_statsd_fd = fd;

	return 0;
}

/* ============================== recorders ============================== */

void
dkimf_stats_record_message(void)
{
	atomic_fetch_add_explicit(&st_messages, 1, memory_order_relaxed);

	if (st_statsd_fd >= 0)
		dkimf_stats_statsd_send("%s.messages:1|c", st_prefix);
}

void
dkimf_stats_record_signature(_Bool ok, int signalg)
{
	int alg = dkimf_stats_algslot(signalg);
	int r = ok ? 1 : 0;

	atomic_fetch_add_explicit(&st_sign[r][alg], 1, memory_order_relaxed);

	if (st_statsd_fd >= 0)
	{
		dkimf_stats_statsd_send("%s.signatures.%s.%s:1|c", st_prefix,
		                        ok ? "ok" : "error", st_alg_label[alg]);
	}
}

void
dkimf_stats_record_verify(int vclass)
{
	if (vclass < 0 || vclass >= DKIMF_STATS_V_MAX)
		return;

	atomic_fetch_add_explicit(&st_verify[vclass], 1, memory_order_relaxed);

	if (st_statsd_fd >= 0)
	{
		dkimf_stats_statsd_send("%s.verifications.%s:1|c", st_prefix,
		                        st_verify_label[vclass]);
	}
}

void
dkimf_stats_record_dnssec(int dnssecclass)
{
	if (dnssecclass < 0 || dnssecclass >= DKIMF_STATS_DNSSEC_MAX)
		return;

	atomic_fetch_add_explicit(&st_dnssec[dnssecclass], 1,
	                          memory_order_relaxed);

	if (st_statsd_fd >= 0)
	{
		dkimf_stats_statsd_send("%s.dnssec.%s:1|c", st_prefix,
		                        st_dnssec_label[dnssecclass]);
	}
}

void
dkimf_stats_record_dns_query(void)
{
	atomic_fetch_add_explicit(&st_dns_queries, 1, memory_order_relaxed);

	if (st_statsd_fd >= 0)
		dkimf_stats_statsd_send("%s.dns.queries:1|c", st_prefix);
}

void
dkimf_stats_record_dns_result(int dnsclass, double seconds)
{
	size_t i;

	if (dnsclass < 0 || dnsclass >= DKIMF_STATS_DNS_MAX)
		return;

	atomic_fetch_add_explicit(&st_dns_results[dnsclass], 1,
	                          memory_order_relaxed);

	if (seconds < 0.0)
		seconds = 0.0;

	for (i = 0; i < ST_DNS_NBUCKETS; i++)
	{
		if (seconds <= st_dns_bounds[i])
			atomic_fetch_add_explicit(&st_dns_bucket[i], 1,
			                          memory_order_relaxed);
	}

	atomic_fetch_add_explicit(&st_dns_count, 1, memory_order_relaxed);
	atomic_fetch_add_explicit(&st_dns_sum_us,
	                          (uint_fast64_t) (seconds * 1e6),
	                          memory_order_relaxed);

	if (st_statsd_fd >= 0)
	{
		dkimf_stats_statsd_send("%s.dns.responses.%s:1|c", st_prefix,
		                        st_dns_label[dnsclass]);
		dkimf_stats_statsd_send("%s.dns.duration:%d|ms", st_prefix,
		                        (int) (seconds * 1e3));
	}
}

/* ========================= Prometheus rendering ========================= */

/*
**  ST_APPEND -- printf into buf starting at offset *off, advancing *off
**
**  On overflow *off is left >= buflen so the caller can detect truncation.
*/

static void
st_append(char *buf, size_t buflen, size_t *off, const char *fmt, ...)
{
	int n;
	va_list ap;

	if (*off >= buflen)
		return;

	va_start(ap, fmt);
	n = vsnprintf(buf + *off, buflen - *off, fmt, ap);
	va_end(ap);

	if (n < 0)
		*off = buflen;
	else
		*off += (size_t) n;
}

/*
**  DKIMF_STATS_RENDER_PROM -- render all counters in Prometheus exposition
**                             format into the caller's buffer
**
**  Return value:
**  	Number of bytes written, or -1 if the buffer was too small.
*/

int
dkimf_stats_render_prom(char *buf, size_t buflen)
{
	int r;
	size_t i;
	size_t off = 0;
	uint_fast64_t cum;

	if (buf == NULL || buflen == 0)
		return -1;

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_build_info Build/version information.\n"
	          "# TYPE phoenixdkim_build_info gauge\n"
	          "phoenixdkim_build_info{version=\"%s\"} 1\n",
	          st_version);

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_messages_total Messages processed.\n"
	          "# TYPE phoenixdkim_messages_total counter\n"
	          "phoenixdkim_messages_total %llu\n",
	          (unsigned long long) atomic_load_explicit(&st_messages,
	                                                     memory_order_relaxed));

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_signatures_total Signatures emitted by result and algorithm.\n"
	          "# TYPE phoenixdkim_signatures_total counter\n");
	for (r = 0; r < 2; r++)
	{
		for (i = 0; i < ST_ALG_MAX; i++)
		{
			st_append(buf, buflen, &off,
			          "phoenixdkim_signatures_total{result=\"%s\",algorithm=\"%s\"} %llu\n",
			          r == 1 ? "ok" : "error",
			          st_alg_label[i],
			          (unsigned long long) atomic_load_explicit(&st_sign[r][i],
			                                                     memory_order_relaxed));
		}
	}

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_verifications_total Verification results.\n"
	          "# TYPE phoenixdkim_verifications_total counter\n");
	for (i = 0; i < DKIMF_STATS_V_MAX; i++)
	{
		st_append(buf, buflen, &off,
		          "phoenixdkim_verifications_total{result=\"%s\"} %llu\n",
		          st_verify_label[i],
		          (unsigned long long) atomic_load_explicit(&st_verify[i],
		                                                     memory_order_relaxed));
	}

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_dnssec_keys_total Key-record DNSSEC status. secure=validated; insecure=provably no DNSSEC (normal for most domains); bogus=DNSSEC present but validation failed; unavailable=local resolver does not validate so the status is unknowable; unknown=not evaluated.\n"
	          "# TYPE phoenixdkim_dnssec_keys_total counter\n");
	for (i = 0; i < DKIMF_STATS_DNSSEC_MAX; i++)
	{
		st_append(buf, buflen, &off,
		          "phoenixdkim_dnssec_keys_total{status=\"%s\"} %llu\n",
		          st_dnssec_label[i],
		          (unsigned long long) atomic_load_explicit(&st_dnssec[i],
		                                                     memory_order_relaxed));
	}

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_dns_queries_total DNS queries issued.\n"
	          "# TYPE phoenixdkim_dns_queries_total counter\n"
	          "phoenixdkim_dns_queries_total %llu\n",
	          (unsigned long long) atomic_load_explicit(&st_dns_queries,
	                                                     memory_order_relaxed));

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_dns_responses_total DNS query outcomes.\n"
	          "# TYPE phoenixdkim_dns_responses_total counter\n");
	for (i = 0; i < DKIMF_STATS_DNS_MAX; i++)
	{
		st_append(buf, buflen, &off,
		          "phoenixdkim_dns_responses_total{result=\"%s\"} %llu\n",
		          st_dns_label[i],
		          (unsigned long long) atomic_load_explicit(&st_dns_results[i],
		                                                     memory_order_relaxed));
	}

	st_append(buf, buflen, &off,
	          "# HELP phoenixdkim_dns_duration_seconds DNS query latency.\n"
	          "# TYPE phoenixdkim_dns_duration_seconds histogram\n");
	for (i = 0; i < ST_DNS_NBUCKETS; i++)
	{
		cum = atomic_load_explicit(&st_dns_bucket[i], memory_order_relaxed);
		st_append(buf, buflen, &off,
		          "phoenixdkim_dns_duration_seconds_bucket{le=\"%g\"} %llu\n",
		          st_dns_bounds[i], (unsigned long long) cum);
	}
	cum = atomic_load_explicit(&st_dns_count, memory_order_relaxed);
	st_append(buf, buflen, &off,
	          "phoenixdkim_dns_duration_seconds_bucket{le=\"+Inf\"} %llu\n"
	          "phoenixdkim_dns_duration_seconds_sum %.6f\n"
	          "phoenixdkim_dns_duration_seconds_count %llu\n",
	          (unsigned long long) cum,
	          (double) atomic_load_explicit(&st_dns_sum_us,
	                                        memory_order_relaxed) / 1e6,
	          (unsigned long long) cum);

	if (off >= buflen)
		return -1;

	return (int) off;
}

/*
**  DKIMF_STATS_WRITE_PROM -- render to a temp file and atomically rename
**
**  Return value:
**  	0 on success, -1 on failure.
*/

static int
dkimf_stats_write_prom(const char *path)
{
	int fd;
	int len;
	ssize_t w;
	char tmp[1056];
	char buf[8192];

	len = dkimf_stats_render_prom(buf, sizeof buf);
	if (len < 0)
	{
		syslog(LOG_ERR, "MetricsFile: render buffer too small");
		return -1;
	}

	snprintf(tmp, sizeof tmp, "%s.tmp", path);

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
	{
		syslog(LOG_ERR, "MetricsFile: open(\"%s\") failed: %s",
		       tmp, strerror(errno));
		return -1;
	}

	w = write(fd, buf, (size_t) len);
	(void) close(fd);

	if (w != (ssize_t) len)
	{
		syslog(LOG_ERR, "MetricsFile: short write to \"%s\"", tmp);
		(void) unlink(tmp);
		return -1;
	}

	if (rename(tmp, path) != 0)
	{
		syslog(LOG_ERR, "MetricsFile: rename(\"%s\") failed: %s",
		       path, strerror(errno));
		(void) unlink(tmp);
		return -1;
	}

	return 0;
}

/*
**  DKIMF_STATS_FLUSH -- write the Prometheus textfile once, now
**
**  Used on clean shutdown so the file reflects final counts rather than
**  lagging by up to one write interval.  A no-op if no MetricsFile is set.
*/

void
dkimf_stats_flush(void)
{
	if (st_metrics_path[0] != '\0')
		(void) dkimf_stats_write_prom(st_metrics_path);
}

/*
**  DKIMF_STATS_WRITER -- background thread that periodically rewrites the
**                        Prometheus textfile
*/

static void *
dkimf_stats_writer(void *arg)
{
	(void) arg;

	for (;;)
	{
		(void) dkimf_stats_write_prom(st_metrics_path);
		sleep(st_metrics_interval);
	}

	/* NOTREACHED */
	return NULL;
}

/*
**  DKIMF_STATS_START_WRITER -- spawn the Prometheus textfile writer thread
**
**  Parameters:
**  	path -- output file path
**  	interval -- seconds between writes (0 selects the default)
**
**  Return value:
**  	0 on success, -1 on failure.
*/

int
dkimf_stats_start_writer(const char *path, unsigned int interval)
{
	pthread_t tid;
	pthread_attr_t attr;

	if (path == NULL || path[0] == '\0')
		return -1;

	snprintf(st_metrics_path, sizeof st_metrics_path, "%s", path);
	st_metrics_interval = (interval == 0) ? 15 : interval;

	/* write once immediately so the file exists before the first scrape */
	(void) dkimf_stats_write_prom(st_metrics_path);

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&tid, &attr, dkimf_stats_writer, NULL) != 0)
	{
		syslog(LOG_ERR, "MetricsFile: cannot start writer thread: %s",
		       strerror(errno));
		(void) pthread_attr_destroy(&attr);
		return -1;
	}

	(void) pthread_attr_destroy(&attr);

	return 0;
}

/* ========================= Prometheus HTTP endpoint ===================== */

/*
**  The embedded endpoint is a hand-rolled HTTP/1.0 responder on a dedicated
**  accept thread -- the same "own a long-lived thread" pattern as the textfile
**  writer above, and like it pulls in no new library.  It answers GET /metrics
**  with the exposition text and 404s everything else.  Each connection is
**  served then closed (no keep-alive), which keeps the single accept loop
**  simple; a Prometheus scrape is one request per interval, so there is no
**  concurrency to win back.  A receive timeout guards the loop against a slow
**  client holding the (single) accept thread.
*/

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL	0
#endif /* ! MSG_NOSIGNAL */

static int st_http_fd = -1;

/*
**  ST_WRITE_ALL -- send the whole buffer, coping with partial / interrupted
**                  writes; a dead peer just ends the loop
*/

static void
st_write_all(int fd, const char *p, size_t len)
{
	while (len > 0)
	{
		ssize_t w = send(fd, p, len, MSG_NOSIGNAL);

		if (w < 0)
		{
			if (errno == EINTR)
				continue;
			break;
		}
		if (w == 0)
			break;

		p += w;
		len -= (size_t) w;
	}
}

/*
**  DKIMF_STATS_HTTP_SERVE -- handle one accepted connection
**
**  We only need the request line, so a single recv() is enough for any sane
**  client; we never read the body.  The path is matched after stripping the
**  HTTP version and any query string.
*/

static void
dkimf_stats_http_serve(int fd)
{
	int blen;
	int bodylen;
	ssize_t n;
	char *path;
	char *end;
	char req[1024];
	char hdr[256];
	char body[8192];

	n = recv(fd, req, sizeof req - 1, 0);
	if (n <= 0)
		return;
	req[n] = '\0';

	if (strncmp(req, "GET ", 4) != 0)
	{
		blen = snprintf(hdr, sizeof hdr,
		                "HTTP/1.0 405 Method Not Allowed\r\n"
		                "Allow: GET\r\n"
		                "Content-Length: 0\r\n"
		                "Connection: close\r\n\r\n");
		st_write_all(fd, hdr, (size_t) blen);
		return;
	}

	/* isolate the request target: from after "GET " up to the next space */
	path = req + 4;
	end = strpbrk(path, " \t\r\n");
	if (end != NULL)
		*end = '\0';
	end = strchr(path, '?');		/* drop any query string */
	if (end != NULL)
		*end = '\0';

	if (strcmp(path, "/metrics") != 0)
	{
		blen = snprintf(hdr, sizeof hdr,
		                "HTTP/1.0 404 Not Found\r\n"
		                "Content-Length: 0\r\n"
		                "Connection: close\r\n\r\n");
		st_write_all(fd, hdr, (size_t) blen);
		return;
	}

	bodylen = dkimf_stats_render_prom(body, sizeof body);
	if (bodylen < 0)
	{
		blen = snprintf(hdr, sizeof hdr,
		                "HTTP/1.0 500 Internal Server Error\r\n"
		                "Content-Length: 0\r\n"
		                "Connection: close\r\n\r\n");
		st_write_all(fd, hdr, (size_t) blen);
		return;
	}

	/* Prometheus text exposition content type (format version 0.0.4) */
	blen = snprintf(hdr, sizeof hdr,
	                "HTTP/1.0 200 OK\r\n"
	                "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
	                "Content-Length: %d\r\n"
	                "Connection: close\r\n\r\n",
	                bodylen);
	st_write_all(fd, hdr, (size_t) blen);
	st_write_all(fd, body, (size_t) bodylen);
}

/*
**  DKIMF_STATS_HTTP_THREAD -- accept loop for the /metrics endpoint
*/

static void *
dkimf_stats_http_thread(void *arg)
{
	(void) arg;

	for (;;)
	{
		int cfd;
		struct timeval tv;

		cfd = accept(st_http_fd, NULL, NULL);
		if (cfd < 0)
		{
			if (errno == EINTR)
				continue;
			/* transient listener error: pause to avoid a tight spin */
			sleep(1);
			continue;
		}

		/* a slow client must not stall the single accept loop */
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		(void) setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
		(void) setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

		dkimf_stats_http_serve(cfd);
		(void) close(cfd);
	}

	/* NOTREACHED */
	return NULL;
}

/*
**  DKIMF_STATS_START_HTTP -- bind a listener and spawn the accept thread
**
**  Parameters:
**  	hostport -- "host:port" (default port 9323); a literal IPv6 address
**  	            must be bracketed, e.g. "[::1]:9323"
**
**  Return value:
**  	0 on success, -1 on failure.
*/

int
dkimf_stats_start_http(const char *hostport)
{
	int fd = -1;
	int status;
	int on = 1;
	char *colon;
	const char *port = "9323";
	char host[256];
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	pthread_t tid;
	pthread_attr_t attr;

	if (hostport == NULL || hostport[0] == '\0')
		return -1;

	snprintf(host, sizeof host, "%s", hostport);

	/* split off ":port"; cope with bracketed IPv6 literals */
	if (host[0] == '[')
	{
		char *bend = strchr(host, ']');

		if (bend != NULL)
		{
			*bend = '\0';			/* terminate the address */
			if (bend[1] == ':')
				port = bend + 2;	/* stable: past the address */
			/* drop the leading '[' in place */
			memmove(host, host + 1, strlen(host + 1) + 1);
		}
	}
	else
	{
		colon = strrchr(host, ':');
		if (colon != NULL)
		{
			*colon = '\0';
			port = colon + 1;
		}
	}

	memset(&hints, '\0', sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	status = getaddrinfo(host[0] != '\0' ? host : NULL, port, &hints, &res);
	if (status != 0 || res == NULL)
	{
		syslog(LOG_ERR, "MetricsAddr: cannot resolve \"%s\": %s",
		       hostport, gai_strerror(status));
		return -1;
	}

	for (ai = res; ai != NULL; ai = ai->ai_next)
	{
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;

		(void) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#ifdef IPV6_V6ONLY
		/* keep an IPv6 bind from silently shadowing IPv4 (or vice versa) */
		if (ai->ai_family == AF_INET6)
			(void) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
			                  &on, sizeof on);
#endif /* IPV6_V6ONLY */

		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
		    listen(fd, 16) == 0)
			break;

		(void) close(fd);
		fd = -1;
	}

	freeaddrinfo(res);

	if (fd < 0)
	{
		syslog(LOG_ERR, "MetricsAddr: cannot listen on \"%s\": %s",
		       hostport, strerror(errno));
		return -1;
	}

	st_http_fd = fd;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&tid, &attr, dkimf_stats_http_thread, NULL) != 0)
	{
		syslog(LOG_ERR, "MetricsAddr: cannot start accept thread: %s",
		       strerror(errno));
		(void) pthread_attr_destroy(&attr);
		(void) close(fd);
		st_http_fd = -1;
		return -1;
	}

	(void) pthread_attr_destroy(&attr);

	return 0;
}
