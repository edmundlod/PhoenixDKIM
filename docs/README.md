# PhoenixDKIM documentation

Guides and reference material for configuring and operating PhoenixDKIM. For
building and installing, see the top-level [README](../README.md).

## Getting started

- [quickstart.md](quickstart.md) — sign your first message: generate two keys
  (Ed25519 + RSA), publish DNS, configure, wire to Postfix, and verify.

## Operating

- [key-rotation.md](key-rotation.md) — rotate signing keys with no window in
  which mail fails verification.
- [multisigning.md](multisigning.md) — sign with several keys/algorithms at
  once, and how verifiers report mixed results.
- [crypto-policy.md](crypto-policy.md) — supported algorithms, key sizes, and
  the policy controls that enforce them.
- [metrics.md](metrics.md) — Prometheus and StatsD metrics, the per-message
  summary log line, and the exported series.
- [internationalization.md](internationalization.md) — RFC 8616 (EAI): UTF-8 in
  header bodies and tag values, and U-label signing domains resolved via
  libidn2.

## Protocols

- [DKIM2.md](DKIM2.md) — **experimental, off by default.** Design notes and
  roadmap for the in-progress DKIM2 (`draft-ietf-dkim-dkim2-spec`) chain-of-
  custody signature support, built in parallel to DKIM1 behind `WITH_DKIM2`.

## Reference

- [removed-features.md](removed-features.md) — subsystems dropped from pre-fork
  OpenDKIM and the rationale for each.
- [README.specs.html](README.specs.html) — index of the bundled RFC and draft
  specification documents.

Man pages are installed for `phoenixdkim(8)`, `phoenixdkim.conf(5)`,
`phoenixdkim-genkey(8)`, `phoenixdkim-genzone(8)`, `phoenixdkim-testkey(8)`,
`phoenixdkim-testmsg(8)`, and `phoenixdkim-lua(3)`.
