/*
**  Copyright (c) 2026, The PhoenixDKIM Authors.  All rights reserved.
**
**  phoenixdkim-stats.h -- in-process metrics counters with Prometheus
**                         (textfile) and StatsD (UDP) exporters.
**
**  The counter core is dependency-free and always compiled in; it is just a
**  set of lock-free atomic counters updated from the milter worker threads at
**  the natural points (message processed, signature emitted, verification
**  completed, DNS query issued/answered).  The two exporters are pure POSIX
**  (file I/O and a UDP socket), so they too are always available and are
**  switched on by configuration alone -- no external library and no compile
**  flag are required.
*/

#ifndef _PHOENIXDKIM_STATS_H_
#define _PHOENIXDKIM_STATS_H_

#include "build-config.h"

/* system includes */
#include <sys/types.h>

/*
**  Verification result classes.  These mirror the RFC 8601 "dkim=" result
**  vocabulary so a verifier's Authentication-Results output and its metrics
**  agree.  The mapping from the milter's internal DKIMF_STATUS_* codes is done
**  by the caller (see dkimf_stats_vclass()).
*/

#define DKIMF_STATS_V_PASS	0
#define DKIMF_STATS_V_FAIL	1
#define DKIMF_STATS_V_NONE	2
#define DKIMF_STATS_V_NEUTRAL	3
#define DKIMF_STATS_V_POLICY	4
#define DKIMF_STATS_V_TEMPERROR	5
#define DKIMF_STATS_V_PERMERROR	6
#define DKIMF_STATS_V_MAX	7

/* DNS outcome classes (terminal result of a single query) */
#define DKIMF_STATS_DNS_SUCCESS	0
#define DKIMF_STATS_DNS_TIMEOUT	1
#define DKIMF_STATS_DNS_ERROR	2
#define DKIMF_STATS_DNS_MAX	3

/* lifecycle */
extern void dkimf_stats_init(const char *version);

/* hot-path recorders (safe to call from any milter worker thread) */
extern void dkimf_stats_record_message(void);
extern void dkimf_stats_record_signature(_Bool ok, int signalg);
extern void dkimf_stats_record_verify(int vclass);
extern void dkimf_stats_record_dns_query(void);
extern void dkimf_stats_record_dns_result(int dnsclass, double seconds);

/* exporters */
extern int dkimf_stats_set_statsd(const char *hostport, const char *prefix);
extern int dkimf_stats_start_writer(const char *path, unsigned int interval);
extern int dkimf_stats_start_http(const char *hostport);
extern int dkimf_stats_render_prom(char *buf, size_t buflen);

/* write the Prometheus textfile once now (e.g. on clean shutdown) */
extern void dkimf_stats_flush(void);

#endif /* ! _PHOENIXDKIM_STATS_H_ */
