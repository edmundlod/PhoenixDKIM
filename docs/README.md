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

## Reference

- [removed-features.md](removed-features.md) — subsystems dropped from pre-fork
  OpenDKIM and the rationale for each.
- [README.specs.html](README.specs.html) — index of the bundled RFC and draft
  specification documents.

Man pages are installed for `phoenixdkim(8)`, `phoenixdkim.conf(5)`,
`phoenixdkim-genkey(8)`, `phoenixdkim-genzone(8)`, `phoenixdkim-testkey(8)`,
`phoenixdkim-testmsg(8)`, and `phoenixdkim-lua(3)`.
