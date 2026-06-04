Remove libbsd dependency for Debian >= 13 (Trixie). strlcpy/strlcat are in
glibc 2.38, which ships with Debian 13 but not Debian 12. Once Debian 12
support is dropped, libbsd-dev can be removed from Build-Depends and the
cmake libbsd detection can be conditioned or dropped accordingly.
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

See ai/dkim2-readiness.md (new) — tracks DKIM2-core vs DKIM2-extended
requirements against where PhoenixDKIM actually is, with a "Latest check" date
to re-evaluate on a cadence. Headline findings worth acting on now (all are
also justified for DKIM1 today, so no bet on unstable wire format):

- Body-hash sharing across multiple signatures (also in the optimisation
  roadmap) — this is what makes dual-signing DKIM1+DKIM2 cheap. Highest value.
- Audit envelope-capture completeness: confirm mctx_rcptlist keeps EVERY
  RCPT TO (not just the first) through to EOM under multi-recipient and
  multiple-messages-per-connection, and MAIL FROM is preserved verbatim. This
  is the raw material for DKIM2 envelope binding and is free insurance now.
- Keep signature-header construction centralised so a second header type is a
  new emitter, not a fork of the existing path.
- Keep Authentication-Results emission table-driven so a future dkim2 method
  clause is a data change, not control flow.
- Reserve the WITH_DKIM2 compile-flag name and decide the config-keyword
  namespace, to mirror the existing optional-feature pattern.

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
  per-signature granularity is wanted; (c) optional embedded /metrics HTTP
  endpoint behind a future WITH_METRICS_HTTP if operators ask; (d) ship a
  contrib/grafana/ dashboard JSON.
- DKIM key-record DNSSEC reporting clarity: we already downgrade/penalise
  non-DNSSEC key records (UnprotectedKey). Confirm the AR output distinguishes
  "key record unprotected" from "validation unavailable" so operators can tell
  the two apart (the warning text exists; verify the AR comment does too).
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

=========================

FEATURES to consider:

 PhoenixDKIM — Feature Gap Analysis

  ---

  5. PKCS#11 / HSM key storage

  High-volume senders and regulated industries (banking, government mail servers) increasingly store signing keys in HSMs or cloud KMS services rather than files. The OpenSSL 3 provider
  model supports this cleanly via pkcs11-provider (or legacy libpkcs11-helper). A KeyFile value that accepts a pkcs11: URI, or an optional -DWITH_PKCS11=ON build flag, would open that use
  case without changing any crypto code — the EVP layer handles it transparently once the provider is loaded. This is worth at least documenting as a known gap.

  ---
  Tier 3 — Future scope (already noted or strategic)

  11. Prometheus / StatsD metrics — already in your SCOPE.md future notes. Worth adding: the minimum useful metric set would be dkim_signatures_total{result=pass|fail|none,algorithm=...}
  and dkim_dns_lookups_total{result=...}. StatsD is simpler to implement (one sendto()); Prometheus is more useful for modern stacks.

  13. DKIM2 (draft-ietf-dkim-next) — acknowledged. Nothing to do yet; the draft is still in flux.


