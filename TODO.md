Remove libbsd dependency for Debian >= 13 (Trixie). strlcpy/strlcat are in
glibc 2.38, which ships with Debian 13 but not Debian 12.
[PARTIAL] The Debian Build-Depends now gates it as
"libc6-dev (>= 2.38) | libbsd-dev", so Trixie+ never pulls or links libbsd
(CMake already prefers libc) while bookworm falls through to libbsd-dev.
Remaining: once Debian 12 support is dropped entirely, the alternative and
the cmake libbsd detection branch can be removed outright.
Ref: https://sourceware.org/pipermail/libc-alpha/2023-July/150524.html

========================

DEAD CODE SWEEP

- opendkim-db.c / phoenixdkim-db.c: the backend type table is now down to the
  supported set only (csl, file, refile, lua, lmdb, redis, http/https, vault)
  — the bdb/dsn/ldap/socketdb entries are already gone. Remaining audit is for
  *internal* dead code, not dead backends: stale #if 0 blocks, helpers left
  behind after the SQL/LDAP removal, and dead struct members. Re-scan with the
  warnings build and a clean rebuild before quoting any counts.

- sha1 in tests: 75 of 145 libphoenixdkim/tests reference SHA1; 71 carry an
  "a=rsa-sha1" signature and assert DKIM_STAT_OK at the *library* layer. That
  is consistent with our policy — the library still RECOGNISES and computes
  rsa-sha1 so the milter can permfail/neutral it at the disposition layer; the
  refusal is not in libphoenixdkim. So these are NOT simply dead and must not
  be bulk-deleted (that would gut sha1 recognition coverage — see the rsa-sha1
  policy). TODO instead: classify the 71, confirm each still reflects current
  behaviour (library OK + disposition refusal), and add a one-line header to
  each explaining why an rsa-sha1 test still asserts OK. Tests are FROZEN
  (SCOPE Process Rule 1) — raise any discrepancy for human review; do not
  silently edit a test to match the implementation.

========================

DKIM2 READINESS

See ai/dkim2-readiness.md — tracks DKIM2-core vs DKIM2-extended requirements
against where PhoenixDKIM actually is, with a "Latest check" date to re-evaluate
on a cadence. The no-regret prep items have now been audited against the tree
(readiness §4); status:

- [DONE] Body-hash sharing across multiple signatures. Already implemented and
  verified in dkim_add_canon() (libphoenixdkim/dkim-canon.c:734-751): body
  canons dedup on (hdr,hashtype,canon,length) so the body is hashed once across
  signatures. Was mis-listed as pending; it isn't. See optimisation-roadmap §2.1.
- [DONE/AUDITED] Envelope-capture completeness. MAIL FROM is captured on every
  message (bracket-normalised, MAXADDRESS-truncated — not byte-verbatim).
  RCPT TO list (mctx_rcptlist) is the one gap: it is built ONLY when
  dontsigntodb/bldb/redirect/resigndb/Lua is enabled (phoenixdkim.c:10799-10823);
  a plain signer keeps no recipients. Within that guard every RCPT is kept, but
  LIFO (reverse) order. Multi-message-per-connection is clean (fresh context per
  MAIL FROM). No code change now (unconditional capture isn't DKIM1-justified and
  SCOPE gates the feature); deliverable is the corrected readiness C5 + §4.2.
  When DKIM2 starts: make capture unconditional/gated, fix ordering, pin MAIL
  FROM normalisation to the draft.
- [CONFIRMED] Signature-header construction is centralised — single emit loop
  over mctx_srhead (phoenixdkim.c:13326-13352). A second header type is a
  parameterisation, not a fork. Header name is the hardcoded DKIM_SIGNHEADER.
- [DECIDED] Reserved compile flag WITH_DKIM2 and a Dkim2* config-keyword
  namespace (readiness §4.4). Reservation only; nothing wired up.
- [CORRECTION] AR emission is NOT table-driven for emission: the method token is
  a literal ("dkim=%s", phoenixdkim.c:12470) and result mapping is an if/else
  chain (dkimf_ar_all_sigs ~9979). Only AR *parsing* has a method table. A
  method=dkim2 clause needs a small emission refactor; deferred (no DKIM1 win on
  its own, touches the verifier-reporting path).

When the SCOPE gate opens (draft at Proposed Standard + shepherd/IESG date),
follow the ordered, WITH_DKIM2-gated implementation checklist in readiness §6:
Phase 0 build/config scaffold → 1 unconditional envelope capture → 2 AR
method-token refactor → 3 generalised sig-header emitter (Phases 0-3 contain NO
wire bytes) → 4 DKIM2-Signature header → 5 dual-signing → 6 verify+AR+chain.
Phases 4+ are [DRAFT-PINNED]: re-read the draft, don't code them from the doc.

Do NOT implement DKIM2 wire output yet — SCOPE gates that on Proposed Standard.

========================

MISSING SIGNER / VERIFIER FEATURES TO CONSIDER

- PKCS#11 / HSM / KMS key storage (already noted below) — accept a pkcs11: URI
  in KeyFile via the OpenSSL 3 provider model; no crypto-code change needed.
- [DONE] Metrics (StatsD/Prometheus). New dep-free phoenixdkim-stats.c holds
  lock-free atomic counters; exporters are a Prometheus textfile writer
  (MetricsFile/MetricsInterval) and a StatsD UDP pusher (StatsDHost/
  StatsDPrefix). Series: phoenixdkim_{messages,signatures{result,algorithm},
  verifications{result},dns_queries,dns_responses{result}}_total +
  dns_duration_seconds histogram + build_info. See docs/metrics.md. Remaining
  follow-ups: (a) DNS series cover the libunbound resolver only — the file
  resolver (TestDNSData) is uninstrumented; (b) verifications are counted once
  per message by determinative result, not per-signature — revisit if
  per-signature granularity is wanted; (c) [DONE] embedded /metrics HTTP
  endpoint: config keyword MetricsAddr host:port (default port 9323).
  Hand-rolled HTTP/1.0, no new library. Dedicated accept thread (same pattern
  as the writer thread) calls dkimf_stats_render_prom() on GET /metrics, 404s
  every other path, 405s non-GET, closes after each response (no keep-alive).
  IPv4 and IPv6 via getaddrinfo / AI_PASSIVE / SO_REUSEADDR (IPV6_V6ONLY so a
  v6 bind doesn't shadow v4). Per-connection recv/send timeout guards the
  single accept loop against a slow client. See phoenixdkim-stats.c
  dkimf_stats_start_http(); documented in phoenixdkim.conf.sample,
  phoenixdkim.conf.5 and docs/metrics.md. Removes the need for the
  node_exporter textfile collector and its permissions dance; (d) ship a
  contrib/grafana/ dashboard JSON.
- [DONE] DKIM key-record DNSSEC reporting clarity: we already downgrade/penalise
  non-DNSSEC key records (UnprotectedKey). Verified the AR output now
  distinguishes the cases (phoenixdkim.c dkimf_ar_all_sigs): "insecure" =
  provably no DNSSEC, "bogus" = DNSSEC present but validation failed, and the
  new "validation unavailable" token = the local resolver does not validate so
  AD=0 is unknowable (previously emitted nothing, which read identically to
  "not evaluated"). Same outcome is exported as
  phoenixdkim_dnssec_keys_total{status="secure|insecure|bogus|unavailable|
  unknown"} for Prometheus/StatsD. (Commit deac76ad.)
- [DONE] Per-result logging/observability: LogResults now also emits a
  structured one-line "summary action=... result=... d=... a=... sigs=..."
  per message (signing and verifying), the human-readable companion to the
  metrics counters. See docs/metrics.md.
- Verify-side: confirm we honour and report key-record flags t=s / t=y
  (testing) and that g= legacy granularity is correctly ignored per RFC 6376.

========================

GETTING STARTED / DOCS IMPROVEMENTS  [DONE]

README is thorough but reference-shaped; there is no short "sign your first
message in 5 minutes" path. Consider:

- [DONE] A docs/quickstart.md: minimal signing setup end to end — generate key,
  publish the DNS TXT line, ~6-line phoenixdkim.conf, wire to Postfix, send a
  test, verify with phoenixdkim-testmsg / phoenixdkim-testkey. README links to
  it from a new "Quick Start" section near the top. (Debian 13 focused; signs
  with two keys, Ed25519 + RSA-2048, via KeyTable + SigningTable.)
- [DONE] Added a "Verify it works" section (testkey against the published
  record; testmsg round-trip; real Postfix send) so a new user can confirm
  success.
- [DONE] Added docs/README.md as a docs index linking quickstart, key-rotation,
  multisigning, crypto-policy, and removed-features.

========================

CI / Github:
- use only one git commit key
- add release signing key to CI

========================

Compare upstream develop branch vs our master branch. They seem to have diverged many years before my fork. See what is missing in our branch, and what needs updating. I think OpenDKIM will eventually cut a new release from their develop branch and we want to be a drop in replacement. Don't port features we dont want. If any new features (eg FFR_CONDITIONAL) are present, or existing ones are changed or removed, explain what they do, and suggest if we want them for a modern, 2026 DKIM implementation.



