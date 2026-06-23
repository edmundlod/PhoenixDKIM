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

**Also done:** **milter integration** — DKIM2 signing and verification wired
into the daemon behind default-off config keys, with the DKIM1 paths untouched
(see [Milter integration](#milter-integration-done)).

**Not done:**

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

## Milter integration (done)

DKIM2 signing and verification are wired into the daemon behind default-off
config keys, in parallel to the DKIM1 paths (which are untouched). All of it is
guarded by `USE_DKIM2` (set in `build-config.h` when `WITH_DKIM2=ON`), so a
default build compiles the milter unchanged. Where it lives:

1. **Config keys** (`phoenixdkim-config.h` table + `dkimf_config_load()` in
   `phoenixdkim.c`, documented in `phoenixdkim.conf.5`/sample), all default off:
   `DKIM2Mode` (off/sign/verify/both), `DKIM2Domain`, `DKIM2Selector`,
   `DKIM2KeyFile`, `DKIM2Algorithm` (default infer from key), plus
   `DKIM2RejectOnFail` and `DKIM2AuthResults`. Parsed into the `conf_dkim2*`
   fields of `struct dkimf_config`; the private key is loaded once with
   `dkim2_privkey_load_pem()` and freed in `dkimf_config_free()`. DKIM1 keys are
   never touched.
2. **Envelope capture** (`struct msgctx`): `mlfi_envfrom` stores the raw
   `<path>` MAIL FROM in `mctx_dkim2mailfrom` (before the DKIM1 path strips the
   brackets); `mlfi_envrcpt` appends each raw RCPT TO to `mctx_dkim2rcpts`
   (a `struct addrlist`, delivery order preserved).
3. **Headers + body.** Headers reuse the DKIM1 `mctx_hqhead` queue — no second
   buffer. The body, which the DKIM1 path streams straight into the library and
   never retains, is accumulated in `mlfi_body` into `mctx_dkim2body` whenever
   DKIM2 is active (and the `SMFIS_SKIP` fast-paths are suppressed so the whole
   body arrives). `dkimf_dkim2_headers()` materialises the queue as the
   `"Name: value"` array the `dkim2_*` entry points want.
4. **EOM** (`dkimf_dkim2_eom()`, called from `mlfi_eom` after the DKIM1
   disposition is decided): verify first (so a chain failure can short-circuit
   before signing), then sign. `dkimf_dkim2_sign_msg()` calls `dkim2_sign()` and
   splits each returned `"Name: value"` field for `smfi_insheader(..., 0, ...)`.
   `dkimf_dkim2_verify_msg()` calls `dkim2_verify()` with the captured envelope
   and maps states to dispositions (FAIL/PERMERROR → `SMFIS_REJECT`,
   TEMPERROR → `SMFIS_TEMPFAIL`) only when `DKIM2RejectOnFail` is set; otherwise
   the result is just logged (and optionally added as `Authentication-Results`
   under `DKIM2AuthResults`).
5. **Resolver.** Verification uses `dkim2_dns_getkey`'s live `res_query`; the
   override hook remains test-only. Bridging to the project resolver
   (`dkim-dns`) for DNSSEC/unbound parity is still open.
6. **Test.** `phoenixdkim/tests/t-sign-dkim2{,.lua,.conf}` is a `miltertest`
   case (auto-discovered, gated on `WITH_DKIM2`) that drives the daemon in
   `DKIM2Mode=sign` and asserts the inserted `Message-Instance` /
   `DKIM2-Signature`. Library/CLIs stay green (`t-dkim2-unit`).

Still open here: live-DNS verification has no offline integration test (the
override hook is not reachable from the daemon), and resolver bridging as above.

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
