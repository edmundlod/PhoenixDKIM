# Metrics and observability

PhoenixDKIM maintains a small set of in-process counters at negligible cost and
can expose them two ways: a **Prometheus** text file (pull) and a **StatsD** UDP
stream (push). Both are pure POSIX — no extra library is linked and no compile
flag is required — so they are switched on by configuration alone. There is
also a per-message structured log line for log-based tooling.

If you run an OpenTelemetry stack, you do not need a native OTel exporter: the
OpenTelemetry Collector has both a `prometheus` receiver and a `statsd`
receiver, so point it at either output below and route onward to Datadog,
Grafana Cloud, New Relic, etc.

## Per-message log line

Set `LogResults yes` (with `Syslog` and/or `StdoutLog` enabled). In addition to
the per-signature detail it already logs, PhoenixDKIM emits one structured
`key=value` summary per message:

```
<jobid>: summary action=verify result=pass d=example.com a=rsa-sha256 sigs=1
<jobid>: summary action=sign d=example.com a=rsa-sha256
```

The signing domain and algorithm live here rather than in metric labels, on
purpose — see "A note on labels" below.

## Prometheus

```sh
MetricsFile      /var/lib/prometheus/node-exporter/phoenixdkim.prom
MetricsInterval  15        # seconds; default 15
```

A background thread writes atomically (temp file + `rename(2)`) every
`MetricsInterval` seconds and once more on clean shutdown. The file lives
directly in the Prometheus `node_exporter` **textfile collector** directory,
which node_exporter watches by default — no extra flag and no network listener
in the daemon.

On Debian/Ubuntu the textfile directory is `/var/lib/prometheus/node-exporter`;
on other distributions it is commonly `/var/lib/node_exporter/textfile_collector`.
The PhoenixDKIM systemd unit already has `ReadWritePaths=` set for both. If you
configure `MetricsFile` to a different path, add the directory via a drop-in:

```sh
systemctl edit phoenixdkim.service
# add under [Service]:
# ReadWritePaths=/your/custom/path
```

### HTTP endpoint (pull, no textfile collector)

If you would rather have Prometheus scrape PhoenixDKIM directly — no
node_exporter, no textfile collector, no shared directory and its permissions
dance — enable the built-in endpoint instead of (or alongside) `MetricsFile`:

```sh
MetricsAddr  127.0.0.1:9323     # default port 9323; [::1]:9323 for IPv6
```

A dedicated accept thread answers `GET /metrics` with the same exposition text
and returns `404` for every other path. It speaks HTTP/1.0 and closes after each
response (no keep-alive); a Prometheus scrape is one request per interval, so
there is nothing to gain from connection reuse. No new library is linked.

There is **no authentication or TLS** — bind to a loopback or a dedicated
management address and let Prometheus reach it over a trusted network (or front
it with a reverse proxy if you need auth/TLS). A matching scrape config:

```yaml
scrape_configs:
  - job_name: phoenixdkim
    static_configs:
      - targets: ['127.0.0.1:9323']
```

## StatsD

```sh
StatsDHost    127.0.0.1:8125    # default port 8125; [::1]:8125 for IPv6
StatsDPrefix  phoenixdkim       # default
```

Events are pushed as StatsD counters/timers over a non-blocking UDP socket;
packets drop silently if the collector is down, so a stalled collector never
throttles mail flow. StatsD has no labels, so label values are folded into
dotted names, e.g. `phoenixdkim.verifications.pass:1|c`.

## Exported series

| Metric | Type | Labels |
| --- | --- | --- |
| `phoenixdkim_build_info` | gauge | `version` |
| `phoenixdkim_messages_total` | counter | — |
| `phoenixdkim_signatures_total` | counter | `result` (ok/error), `algorithm` |
| `phoenixdkim_verifications_total` | counter | `result` (pass/fail/none/neutral/policy/temperror/permerror) |
| `phoenixdkim_dns_queries_total` | counter | — |
| `phoenixdkim_dns_responses_total` | counter | `result` (success/timeout/error) |
| `phoenixdkim_dns_duration_seconds` | histogram | — |

`verifications_total` labels mirror the RFC 8601 `dkim=` result vocabulary, so
the metric and the `Authentication-Results` header agree. The DNS series
reflect the asynchronous **libunbound** resolver; the file-based test resolver
(`TestPublicKeys`/`TestDNSData`) is not instrumented.

## A note on labels

High-cardinality values — the signing domain (`d=`), selector, job ID — are
deliberately **not** used as metric labels. Each distinct label value is a new
Prometheus time series, and an unbounded set (one per signing domain on a busy
signer) will overwhelm the store. Per-domain breakdowns belong in the
`LogResults` summary line, which feeds log-based tools that handle high
cardinality well.

## Example PromQL

```promql
# inbound verification pass rate over 5m
sum(rate(phoenixdkim_verifications_total{result="pass"}[5m]))
  / sum(rate(phoenixdkim_verifications_total[5m]))

# 95th-percentile DNS key-lookup latency
histogram_quantile(0.95,
  sum(rate(phoenixdkim_dns_duration_seconds_bucket[5m])) by (le))

# signing errors per second
sum(rate(phoenixdkim_signatures_total{result="error"}[5m]))
```
