# DKIM2 developer guide — continuing the work

This guide lets a new session pick up the DKIM2 work where it was paused. It
records what exists, how it is built and tested, the design invariants, and the
concrete remaining work. Pair it with [DKIM2.md](DKIM2.md) (the user-facing
design/roadmap) and the spec at
<https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/>.

## Status

**Done (on branch `feature/dkim2`, ~15 commits):** the complete DKIM2-**core**
profile as a library, plus standalone CLIs, CTest tests, and fuzz harnesses.

- Tag parser, base64-JSON helper (cJSON, for recipes only), body+header hashing,
  DKIM2-Signature / Message-Instance model, DNS key retrieval, RSA-SHA256 +
  Ed25519-SHA256 crypto, **DKIM2-core signing**, **DKIM2-core chain
  verification**, `phoenixdkim2-sign` / `phoenixdkim2-verify` CLIs.
- `t-dkim2-unit` (CTest) and five `fuzz-dkim2-*` targets. All build
  warning-clean under the strict + ASan/UBSan suite.

**Not done:**

- **Milter integration** (the one remaining planned commit — see below).
- **DKIM2-extended** (body recipes / Message-Instance rollback) — future
  milestone.

## Module map (`libphoenixdkim/`)

All compiled only under `WITH_DKIM2` (appended to `DKIM2_SOURCES` in
`libphoenixdkim/CMakeLists.txt`). Each has a focused header.

| file | purpose | key API |
|------|---------|---------|
| `dkim2-tags.{c,h}` | RFC 6376 tag=value list parser | `dkim2_taglist_parse/get/free` |
| `dkim2-json.{c,h}` | base64-JSON over cJSON (recipes only) | `dkim2_json_b64_decode/encode` |
| `dkim2-hash.{c,h}` | body (simple) + header (§5.2) SHA-256 | `dkim2_body_hash`, `dkim2_header_hash`, `dkim2_header_is_signed` |
| `dkim2-header.{c,h}` | DKIM2-Signature / Message-Instance model | `dkim2_signature_parse/format/free`, `dkim2_mi_*` |
| `dkim2-dns.{c,h}` | key record fetch + parse, override hook | `dkim2_dns_getkey`, `dkim2_keyrecord_parse`, `dkim2_dns_override` |
| `dkim2-crypto.{c,h}` | RSA/Ed25519 sign+verify, key loading | `dkim2_sign_data`, `dkim2_verify_data`, `dkim2_pubkey_load`, `dkim2_privkey_load_pem` |
| `dkim2-sign.{c,h}` | **DKIM2-core signing** + §8.5 canon | `dkim2_sign`, `dkim2_canon_field_85` |
| `dkim2-verify.{c,h}` | **DKIM2-core chain verification** | `dkim2_verify`, `dkim2_verify_result_clear` |
| `dkim2-eml.{c,h}` | `.eml` splitter (CLIs only, not the lib) | `dkim2_eml_parse` |
| `phoenixdkim2-{sign,verify}.c` | standalone CLIs | — |

Entry points: **`dkim2_sign()`** (`dkim2-sign.h`) and **`dkim2_verify()`**
(`dkim2-verify.h`). Both take headers as an array of `"Name: value"` strings
(folding preserved, no trailing CRLF) and the raw body — exactly what the milter
must hand them.

## Build, test, run

```bash
# configure with DKIM2 on (cjson-devel / libcjson-dev required)
cmake -S . -B build -DWITH_LUA=1 -DWITH_REDIS=1 -DWITH_DKIM2=ON
cmake --build build -j"$(nproc)"

# unit test (needs the t-setup/t-cleanup fixtures)
ctest --test-dir build -R 't-(setup|cleanup|dkim2-unit)' --output-on-failure

# strict + sanitizer build (must stay warning-clean) — see reference_strict-build
cmake -S . -B build-strict -DCMAKE_BUILD_TYPE=Debug -DWITH_LUA=1 -DWITH_REDIS=1 \
  -DWITH_DKIM2=ON -DPHOENIXDKIM_ENABLE_STRICT_C=ON \
  -DPHOENIXDKIM_ENABLE_EXTRA_WARNINGS=ON -DPHOENIXDKIM_ENABLE_UBSAN=ON \
  -DPHOENIXDKIM_ENABLE_ASAN=ON
cmake --build build-strict -j"$(nproc)" 2>&1 | tee build-warnings.txt

# fuzzers (clang + ASan)
CC=clang cmake -S . -B build-fuzz -DWITH_DKIM2=ON \
  -DPHOENIXDKIM_ENABLE_FUZZERS=ON -DPHOENIXDKIM_ENABLE_ASAN=ON
cmake --build build-fuzz --target fuzz-dkim2-sig
./build-fuzz/libphoenixdkim/fuzz/fuzz-dkim2-sig -max_total_time=30

# offline round trip through the CLIs
S=build/libphoenixdkim/phoenixdkim2-sign; V=build/libphoenixdkim/phoenixdkim2-verify
$S --key key.pem --domain d.example --selector sel --mail-from '<a@d.example>' \
   --rcpt-to '<b@x.example>' < msg.eml > signed.eml
# fixture zone line: "sel._domainkey.d.example\tv=DKIM1; k=rsa; p=<DER-SPKI-base64>"
$V --dns-fixture zone.txt < signed.eml   # exit 0 PASS / 1 FAIL / 2 PERMERROR / 3 TEMPERROR / 4 NONE
```

## Design invariants (do not break)

- **Parallel to DKIM1.** Never modify the DKIM1 sign/verify paths; DKIM2 lives in
  its own files and both can coexist on one message.
- **Gate.** Everything is behind `WITH_DKIM2` (default OFF, FATAL if cjson missing
  when ON). Keep new milter config keys default-off too.
- **cJSON is for recipes only.** Core tags are flat: `mf=`/`rt=` base64, `s=` =
  `selector:alg:sig` triples, `h=` = `sha256:hh:bh` triples. JSON appears only in
  `r=` (extended). Don't reach for cJSON in core paths.
- **Verify from raw bytes.** The §8.5 signing input is rebuilt by blanking the
  signature value(s) in the *raw received field* (`dkim2_blank_sig` +
  `dkim2_canon_field_85`), never by re-serialising a parsed struct.
- **No vendored interop data.** `github.com/dkim2wg/interop` has no licence — do
  not copy its code or `.eml` files. Use it only to resolve ambiguities; test
  with self-generated vectors and the live harness.
- **No ARC.** A draft moves ARC to Historic; DKIM2 supersedes it. Add no ARC.
- **LibreSSL-safe crypto spellings** (`EVP_PKEY_base_id`, not the `get_` alias)
  and POSIX resolver names (`ns_c_in`/`ns_t_txt`).

## Remaining: milter integration (commit 14)

Goal: sign outbound and verify inbound from within the milter, behind config
keys, DKIM1 path untouched. Files: `phoenixdkim/phoenixdkim.c` (large),
`phoenixdkim/config.c`, the sample `.conf`. Concrete steps:

1. **Config keys** (`config.c` + `phoenixdkim.conf.5`/sample), all default off:
   `DKIM2Mode` (off/sign/verify/both), `DKIM2Domain`, `DKIM2Selector`,
   `DKIM2KeyFile`, `DKIM2Algorithm` (default infer from key). Reuse existing
   config-table machinery; do not touch DKIM1 keys.
2. **Per-connection context** (the milter's message struct): capture the
   envelope. `mlfi_envfrom` → MAIL FROM, `mlfi_envrcpt` → each RCPT TO. Store as
   the raw `<path>` strings for `dkim2_sign` / `dkim2_verify` opts.
3. **Collect headers + body.** The milter already accumulates header fields and
   body for DKIM1; reuse that buffer. Convert the collected headers into the
   `"Name: value"` array `dkim2_*` expect (folding preserved, no trailing CRLF),
   and pass the body buffer. Look at how the DKIM1 path builds its header list to
   avoid duplicating buffering.
4. **Sign at EOM** (`mlfi_eom`), positioned **last** after other
   modifying milters: call `dkim2_sign()`; insert the returned `Message-Instance`
   and `DKIM2-Signature` with `smfi_insheader` at the top. Strip the
   `"Name: "` prefix the helpers include (or split on the first colon) since
   `smfi_insheader` takes name and value separately.
5. **Verify at EOM** on inbound: call `dkim2_verify()` with the captured
   envelope in `dkim2_verify_opts_t`. Map states to milter actions —
   PASS/NONE → continue; FAIL/PERMERROR → `SMFIS_REJECT` (5xx) if policy says
   reject; TEMPERROR → `SMFIS_TEMPFAIL` (4xx). Optionally add an
   `Authentication-Results` entry (note: doing so counts as a modification for
   any later DKIM2 signer).
6. **Resolver.** The override hook is for tests; in the milter let
   `dkim2_dns_getkey` use live `res_query`, or bridge to the project's resolver
   (`dkim-dns`) if DNSSEC/unbound parity is wanted later.
7. **Tests.** Add a `miltertest`-driven case if practical; at minimum keep the
   library/CLIs green.

## Future: DKIM2-extended

Body recipes + Message-Instance `r=` rollback, and the stateful milter handling
they need. The `r=` plumbing (base64-JSON via `dkim2-json`) and the cJSON
dependency already exist. New work: a `dkim2-recipe.{c,h}` implementing the
`{"c":[s,e]}` / `{"d":[...]}` copy/replace steps (spec §4), recipe generation on
modification, and `undo`/verification across instances (spec §9.2). Port
guidance from the interop references (C `dkim2_recipe.c`, Go `dkim2/mi.go`+
`recipe.go`, Perl `Mail::DKIM2::MessageInstance`/`MessageStore`) — read, don't
copy.

## Spec drift watch

Track `draft-ietf-dkim-dkim2-spec` (currently -02). The interop C/Go reference
moved to it; the older `draft-clayton-dkim2-spec-08` differs (envelope was a
JSON `m=` blob; the MI pointer tag was `v=`). When a new revision lands, re-check
§5 (hashing), §7 (tags), §8.5 (signing input), and §10 (verifier), and re-run the
CLIs against the interop harness.
