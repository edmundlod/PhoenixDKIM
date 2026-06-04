# Statistics (via Prometheus and StatsD)

*Published 4 June 2026.*

When I forked the OpenDKIM project I created a SCOPE document in which I write down what I wanted from the fork. What did I want to change, add, remove from the original that warranted a fork[^1]? One of the code paths that I decided to remove was `stats`, which aggregated per-message statistics and sent them to a dead upstream server. Besides, I had also decided to remove SQL support; not because of SQL, but because `libopendbx` is unmaintained, which is the abstraction layer that was used in OpenDKIM. I was going to redo the whole database backend.

Statistics are very useful, though, and so statistics as such were added to the Roadmap. I also reckon that if PhoenixDKIM emits statistics in a useful way for today's sysadmins, that they might be more willing to give PhoenixDKIM a try.

And so I set to implement a feature that would emit statistics that could be used in [Prometheus](https://prometheus.io/), which I see being mentioned time and time again, as well as in good old [StatsD](https://github.com/statsd/statsd).

## What I did not want

The old `stats` code wrote rows to a database and posted them to a collector that no longer exists. That is exactly the shape of dependency I had spent the fork getting rid of: a backend service that has to be running, reachable and maintained before the milter can tell you anything. I did not want metrics to bring back a hard dependency, an extra build flag, or a daemon that has to be healthy for mail to flow.

So I gave myself three rules:

* **No new library.** The counters and both exporters had to be pure POSIX — file I/O, a UDP socket, a TCP socket. If a distribution can build the milter, it can emit metrics, with nothing extra to install.
* **No compile flag.** The feature is always built in. You turn it on with configuration alone; if you configure nothing, it costs nothing.
* **Never throttle mail.** A metrics sink that stalls — a full disk, a dead collector, a slow scraper — must never slow down or block the signing and verification path. Mail flow wins, always.

## The counter core

Underneath both exporters is a small set of in-process counters, and they are the part I am happiest with. They are C11 atomics, incremented with relaxed ordering straight from the milter worker threads at the natural points: a message processed, a signature emitted, a verification completed, a DNS query issued and answered. There is no lock on the hot path and no buffer to flush — just a handful of `atomic_fetch_add`s. The cost is genuinely negligible, which is why I was comfortable compiling it in unconditionally.

The one design decision worth dwelling on is **label cardinality**. It is tempting to label every signature with its signing domain, so you can slice the dashboard by `d=`. Don't. In Prometheus each distinct combination of label values is a separate time series, and a busy signer handling thousands of domains would mint thousands of series and eventually fall over. So PhoenixDKIM only ever uses *bounded* enums as labels — the result class, the algorithm — and never the domain, the selector or the job ID. The per-message detail still exists; it lives in the `LogResults` summary line, which is exactly the kind of high-cardinality data that log-based tooling handles well. Metrics answer "how is the system behaving"; the log answers "what happened to this message". Keeping those two jobs apart is what keeps the metrics cheap.

The series that come out the other end are:

| Metric | Type | Labels |
| --- | --- | --- |
| `phoenixdkim_build_info` | gauge | `version` |
| `phoenixdkim_messages_total` | counter | — |
| `phoenixdkim_signatures_total` | counter | `result`, `algorithm` |
| `phoenixdkim_verifications_total` | counter | `result` |
| `phoenixdkim_dns_queries_total` | counter | — |
| `phoenixdkim_dns_responses_total` | counter | `result` |
| `phoenixdkim_dns_duration_seconds` | histogram | — |

The `verifications_total` result labels deliberately mirror the RFC 8601 `dkim=` vocabulary — `pass`, `fail`, `none`, `neutral`, `policy`, `temperror`, `permerror` — so the number on your dashboard and the result in the `Authentication-Results` header are speaking the same language.

## Prometheus, the textfile way

The first exporter writes the whole counter set in Prometheus' text exposition format to a file, rewritten atomically (a temporary file and a `rename(2)`, so a scraper never catches a half-written file) every `MetricsInterval` seconds, and once more on clean shutdown so the final counts are not lost. A background thread owns this; the worker threads never touch a file.

```
MetricsFile      /var/lib/prometheus/node-exporter/phoenixdkim.prom
MetricsInterval  15
```

Point it at the directory that the Prometheus `node_exporter` "textfile" collector already watches and the metrics appear in your existing scrape with no new target and — crucially — no listening socket added to the milter. For a lot of deployments that already run node_exporter, this is the whole job done.

## Prometheus, the direct way

The textfile collector is lovely until it isn't. It means PhoenixDKIM and node_exporter have to share a directory, which means getting the permissions right, which means a little dance with `ReadWritePaths=` in the systemd unit, and it means you are running node_exporter at all. If you would rather just point Prometheus straight at the milter, you now can:

```
MetricsAddr  127.0.0.1:9323
```

This is a hand-rolled HTTP/1.0 responder on a dedicated accept thread — the same "own a long-lived thread" pattern as the textfile writer, and, true to rule one, no new library. It answers `GET /metrics` with the same exposition text and returns a 404 for everything else, closing the connection after each response. There is no keep-alive and no concurrency, because a Prometheus scrape is one request per interval; there is nothing to win by making it cleverer, and a great deal of surface area to lose. It binds IPv4 and IPv6, and a per-connection receive timeout means a slow client cannot tie up the single accept thread.

One thing to be clear about, because it is the kind of detail that bites people: **there is no authentication and no TLS** on this endpoint. Bind it to loopback or a dedicated management address and let Prometheus reach it over a network you trust — or put a reverse proxy in front if you need auth or TLS. It is a metrics port, not a public API.

## StatsD, for the push crowd

Not everyone pulls. The StatsD exporter pushes the same events to a collector over UDP:

```
StatsDHost    127.0.0.1:8125
StatsDPrefix  phoenixdkim
```

The socket is non-blocking and the sends are fire-and-forget: if the collector is down, the packets are dropped silently and the milter does not so much as pause. That is rule three made concrete — a stalled collector is the collector's problem, never the mail's. StatsD has no concept of labels, so the label values are folded into dotted metric names instead, e.g. `phoenixdkim.verifications.pass:1|c`.

And if you live in OpenTelemetry land, you do not need a native OTel exporter from me: the OpenTelemetry Collector has both a `prometheus` receiver and a `statsd` receiver, so point it at either of the outputs above and route onward to wherever you like.

## What is still rough

Two honest caveats, both noted in the docs and on my list. The DNS series currently reflect the asynchronous libunbound resolver only; the file-based test resolver is not instrumented (it is a test aid, so this bothers me less). And verifications are counted once per message by their determinative result rather than once per signature — fine for "what is my inbound pass rate", less precise if you want to reason about multiple-signed mail. If there is appetite for per-signature granularity, that is a reasonable next step.

For the full list of series, the PromQL examples and the exact configuration, see the [metrics guide](/guides/metrics.html) and the sample configuration file.

[^1]: Remember that at that time in early 2026 when this was going through my head, the project seemed more or less abandoned, with the last commit to the master branch being from 25 February 2018, a good eight years prior to my musings.
