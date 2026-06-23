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

**Also done:** **DKIM2-extended** (body recipes / Message-Instance rollback) at
the library + CLI level — the recipe module, cross-instance hash verification,
modification signing, unit tests, and a fuzzer. See
[DKIM2-extended](#dkim2-extended-done) below for how it landed; the
deferred in-milter modification *engine* is still the only open piece.

**Not done:**

- **In-milter modification engine** — a daemon-side footer / subject-tag /
  header-rewrite that performs *and* records changes itself. See
  [Deferred follow-up](#deferred-follow-up-in-milter-modification-engine).

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
| `dkim2-recipe.{c,h}` | body/header recipes §4/§9.2 (extended) | `dkim2_recipe_parse/format/free/apply/generate` |
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

## DKIM2-extended (done)

Body recipes + cross-instance hash verification, at the library + CLI level.
**This landed** along the staging below; the rest of this section is the
implementation spec it was built from, kept as a reference for the still-deferred
in-milter engine and for anyone touching the recipe code.

**As built (deltas from the spec below worth knowing):**

- `dkim2-recipe.{c,h}` carries the model and the **single CRLF line-split
  convention** (`body_split_lines`/`body_join_lines`); `generate` does an LCS
  line-diff for the body and a per-field-name diff for headers (one `{"d":[…]}`
  of the old values per changed name — correct, if not the most compact).
- Header data literals are the **field value** (leading WSP trimmed); apply
  rebuilds `name: value`. The §5.2 header canon lowercases names and
  collapses/trims WSP, so reconstruction is hash-equal without byte-exactness.
- **§8.5 fix (important):** a signature's signing input must include only the
  Message-Instance fields it covers — those with `m <= sig.m=`. With one instance
  (core) this was a no-op, so the original `dkim2_build_input_85` emitted *all*
  MIs; multi-instance messages exposed it (sig `i=1` would wrongly hash `m=2`).
  Both the verifier (`dkim2_build_input_85`, filtered) and the signer (only ever
  references the highest `m`, so it was already correct) now agree. If you add a
  path that signs referencing a non-top instance, keep this filter in mind.
- **Missing-recipe PERMERROR is defensive, not test-reachable:** the recipe lives
  in a signed Message-Instance, so stripping `r=` breaks that hop's signature
  (checked at 10.6, before the 9.2 walk) and surfaces as FAIL. The unit test
  therefore exercises the reachable paths — tamper → FAIL, `"h":null` → PASS — and
  leaves the `mi_r == NULL` branch as a guard.

The `r=` plumbing already existed: `dkim2_mi_t.mi_r`
carries the base64-JSON recipe opaquely (`dkim2-header.c` parses/round-trips
it), `dkim2-json.{c,h}` (`dkim2_json_b64_decode/encode` over cJSON) moves between
that text and a cJSON tree, and `dkim2_header_is_signed()` already excludes
`Message-Instance` from the header hash. What's missing is the recipe model and
its use in sign/verify.

### Scope decision (agreed)

**This milestone = recipe library + cross-instance verification + CLI
generate/consume + unit tests + fuzzer.** That is the complete integration
surface for mailing-list operators and corporate gateways: *their* software
performs the modification and hands phoenixdkim the before- and after-message,
and phoenixdkim records the reversible diff (via the library API or the CLIs).

**Deferred to a later, clearly-scoped milestone: an in-milter modification
*engine*** (a configured footer / subject-tag / header-rewrite that the daemon
applies itself and records). It sits *on top of* this library and is the only
part introducing new message-modification surface in the daemon.

**Why generation is deferred — the before/after constraint.** A recipe is a
diff, so generating one needs *both* the pre- and post-modification message. A
milter only ever sees the message as it arrives: it cannot observe a
modification the MTA makes *after* the milter stage, and it cannot "diff against
the incoming chain" because the chain carries only the previous body's *hash*,
not its bytes — you cannot diff against a hash. phoenixdkim itself never
rewrites the body (it only inserts header fields, which are excluded from the
hash), so there is no in-daemon modification to record yet. Cross-instance
*verification*, by contrast, needs no new milter code: the daemon already calls
`dkim2_verify()`, so making that function recipe-aware reaches the verify path
for free.

### Recipe semantics (draft-ietf-dkim-dkim2-spec-02, §4 / §9.2)

Tracked from the live draft; **not vendored** (re-check on each revision, and
against the interop harness — read, don't copy).

- A recipe is a JSON object: `{"h": {"<field-name>": [ops]}, "b": [ops]}`.
  `"h": null` (or a null recipe) marks an **irreversible** modification.
- Operations are **line/field-ordinal based, not byte offsets**:
  - `{"c":[start,end]}` — **copy** field-instances (under `h`) or body **lines**
    (under `b`) numbered `start..end`, *inclusive*, from the *current* message.
  - `{"d":["literal", ...]}` — **insert literal data** present in the older
    version. For headers each array string is reconstructed as `Name: value`
    followed by CRLF.
- `r=` is the base64 of that JSON. The recipe lives on the **modifying (higher
  `m=`) Message-Instance** and reconstructs the **previous** instance; `m=`
  increments by exactly 1 per modification.
- A verifier walks **backward** (highest `m` → 1): take the current message,
  apply the highest instance's recipe to reconstruct the previous instance's
  headers+body, check that instance's `h=` hashes, then repeat one step down
  reusing each step's output as the next step's input.

Worked example — a list appends a footer and tags the subject:

```
original (m=1)            modified by list (m=2)
Subject: Hi               Subject: [list] Hi
                          
Hello                     Hello
Bye                       Bye
                          --
                          sent via list
```

The list's `Message-Instance; m=2` carries `r=` = base64 of
`{"h":{"subject":[{"d":["Hi"]}]},"b":[{"c":[1,2]}]}` — "Subject was `Hi`; for
the body keep only lines 1–2." A verifier applies that to the received message
to recover the m=1 body/headers and re-checks the originator's hashes.

### 1. New module `libphoenixdkim/dkim2-recipe.{c,h}`

Data model (flat structs + linked lists, matching `dkim2-header.h` style):

```c
typedef enum { DKIM2_ROP_COPY, DKIM2_ROP_DATA } dkim2_ropt_t;
typedef struct dkim2_recipe_op {
    dkim2_ropt_t  ro_type;
    size_t        ro_start, ro_end;        /* COPY: 1-based inclusive ordinals */
    char        **ro_data; size_t ro_ndata; /* DATA: literal strings */
    struct dkim2_recipe_op *ro_next;
} dkim2_recipe_op_t;
typedef struct dkim2_recipe_hdr {          /* per-field-name ops */
    char *rh_name;                         /* lowercased */
    dkim2_recipe_op_t *rh_ops;
    struct dkim2_recipe_hdr *rh_next;
} dkim2_recipe_hdr_t;
typedef struct dkim2_recipe {
    int re_null;                           /* 1 = irreversible */
    dkim2_recipe_hdr_t *re_hdrs;           /* header recipes (NULL = unchanged) */
    dkim2_recipe_op_t  *re_body;           /* body ops      (NULL = unchanged) */
} dkim2_recipe_t;
```

API:

- `dkim2_recipe_t *dkim2_recipe_parse(const char *b64, size_t len)` — decode via
  `dkim2_json_b64_decode()`, then walk the cJSON tree (`cJSON_GetObjectItem` /
  `cJSON_GetArrayItem`, `cJSON_IsArray/IsString/IsNumber`, as in
  `fuzz/fuzz-dkim2.c`). Reject malformed ops — this consumes untrusted input and
  must be fuzzed.
- `char *dkim2_recipe_format(const dkim2_recipe_t *)` — build a cJSON tree, then
  `dkim2_json_b64_encode()` (unformatted, signing-stable).
- `void dkim2_recipe_free(dkim2_recipe_t *)`.
- `int dkim2_recipe_apply(const dkim2_recipe_t *r, const char *const *cur_hdrs,
  size_t cur_nh, const char *cur_body, size_t cur_blen, char ***prev_hdrs,
  size_t *prev_nh, char **prev_body, size_t *prev_blen)` — reconstruct the
  previous instance from the current one. Body is split on CRLF into 1-based
  lines; `c`/`d` ops rebuild it. Headers: only the field names listed in
  `re_hdrs` have their instance-sequence rebuilt; every other field is copied
  through unchanged. Returns 0 ok, **1** when `re_null` (caller stops the
  backward walk), -1 on error / out-of-range ordinal. Output arrays/buffers are
  freshly allocated and owned by the caller.
- `dkim2_recipe_t *dkim2_recipe_generate(const char *const *old_hdrs,
  size_t old_nh, const char *old_body, size_t old_blen, const char *const
  *new_hdrs, size_t new_nh, const char *new_body, size_t new_blen)` — produce a
  recipe reconstructing **old from new**. LCS line-diff for the body: matched
  runs become `{"c":[s,e]}` over *new*'s lines, old-only runs become
  `{"d":[...]}`. Per-field-name diff for headers; emit an `re_hdrs` entry only
  for names whose instance-list differs. **Centralise the CRLF line-split and
  final-line handling here** (one place to keep consistent with interop).

Add `dkim2-recipe.c` to the `list(APPEND DKIM2_SOURCES ...)` block in
`libphoenixdkim/CMakeLists.txt` (currently the `dkim2-tags.c … dkim2-verify.c`
list). The CLIs link `phoenixdkim_static`, so no CLI link change is needed.

### 2. Cross-instance verification — `libphoenixdkim/dkim2-verify.c`

Today `dkim2_verify()` checks the body+header hashes of the **highest**
Message-Instance only (the §10.7 block near the end of the function). Add, after
that check passes, a backward loop over `k = nmi-1 … 1` (instances are already
`qsort`ed ascending by `mi_m` into `mis[]`):

- `mis[k].mi->mi_r == NULL` while a lower instance exists → a modifying instance
  must carry a recipe (or an explicit null one) → `DKIM2_V_PERMERROR`,
  `vr_i = k+1`.
- parse `mi_r` with `dkim2_recipe_parse`; if `re_null` → stop the walk (earlier
  instances are unreconstructable); leave the verified portion as PASS and note
  it in `vr_message`.
- otherwise `dkim2_recipe_apply()` to reconstruct instance `k`'s headers+body
  from instance `k+1`'s (start from the live message for the first step, then
  feed each step's output into the next); recompute with `dkim2_body_hash` /
  `dkim2_header_hash`; compare to `mis[k].mi->mi_h`. Mismatch → `DKIM2_V_FAIL`,
  `vr_i = k+1`.

The signature-verification loop (§10.5/10.6, `dkim2_build_input_85` +
`dkim2_blank_sig`) is **unchanged**: signatures still cover the MI fields
verbatim via §8.5; recipe checks are a separate hash-consistency layer.

### 3. Signing a modification — `libphoenixdkim/dkim2-sign.c`

Extend `dkim2_sign_params_t` (`dkim2-sign.h`) with optional previous-instance
inputs:

```c
const char *const *sp_orig_headers; size_t sp_orig_nheaders;
const char        *sp_orig_body;    size_t sp_orig_bodylen;  /* diff source */
const char        *sp_recipe;       /* explicit base64-JSON r=, alt to diffing */
```

In `dkim2_sign()`, the current branch is: originator (`nsig == 0`) adds
`Message-Instance m=1`; a re-signer adds *no* MI and references the top
instance. Add a third, **modifying** path: when existing instances are present
*and* (`sp_orig_*` or `sp_recipe` is set), add a new `Message-Instance`
`m = highest+1` whose `h=` covers the *current* message and whose `r=` is
`sp_recipe` (if given) else `dkim2_recipe_format(dkim2_recipe_generate(orig,
current))`; the new signature's `m=` references the new highest. Return the new
MI in `*mi_out`. The originator and plain-re-sign paths stay byte-for-byte
unchanged.

### 4. CLIs

- `phoenixdkim2-sign.c`: add `--orig <file>` (parse with `dkim2_eml_parse`, feed
  `sp_orig_*`) and `--recipe <file>` (read base64-JSON, feed `sp_recipe`).
  Support **both**; `--recipe` wins if both are given. Existing options and the
  arg-parsing style (plain `strcmp` loop, ~lines 72-95) are unchanged.
- `phoenixdkim2-verify.c`: **no new options** — cross-instance verification is
  automatic and the existing exit-code mapping already covers FAIL/PERMERROR.

### 5. Unit tests — `libphoenixdkim/tests/t-dkim2-unit.c`

Add a `test_recipe()` (and extend `test_components`) covering:

- recipe parse↔format round-trip, including `"h":null`.
- inverse property: `apply(generate(old,new), new)` reproduces `old`, for body
  and headers.
- full extended chain (reuse the existing `sign_hop` / `zone_add` /
  `dkim2_dns_override` harness): originator signs `m=1`; modify the body (+ a
  header) and re-sign with `sp_orig_*` to get `m=2` + recipe; `dkim2_verify` →
  PASS with the reconstructed `m=1` hashes matching. Then: tamper the recipe or
  a body line → FAIL; drop the recipe on `m=2` → PERMERROR; `"h":null` →
  PASS-with-note.

### 6. Fuzzer — `libphoenixdkim/fuzz/`

Add `fuzz-dkim2-recipe=6` to `_dkim2_fuzz_targets` in `fuzz/CMakeLists.txt`, a
`#define FUZZ_DKIM2_RECIPE 6` + include of `../dkim2-recipe.h` in `fuzz-dkim2.c`,
and a `FUZZ_DKIM2_TARGET == FUZZ_DKIM2_RECIPE` arm calling
`dkim2_recipe_free(dkim2_recipe_parse(s, size))`.

### Suggested commit staging (matches the core style)

1. `dkim2-recipe.{c,h}` + build wiring (parse/format/free/apply/generate).
2. `fuzz-dkim2-recipe` harness.
3. cross-instance verification in `dkim2-verify.c`.
4. modification signing in `dkim2-sign.c` + `--orig`/`--recipe` CLI options.
5. unit tests.
6. docs (flip the status lines here and in `DKIM2.md` from "designed" to "done").

### Verify end-to-end

```bash
ctest --test-dir build -R 't-(setup|cleanup|dkim2-unit)' --output-on-failure
cmake --build build-fuzz --target fuzz-dkim2-recipe \
  && ./build-fuzz/libphoenixdkim/fuzz/fuzz-dkim2-recipe -max_total_time=30
# round trip: sign m=1, modify, re-sign m=2 with a recipe, verify back to PASS
S=build/libphoenixdkim/phoenixdkim2-sign; V=build/libphoenixdkim/phoenixdkim2-verify
$S --key k1.pem --domain orig.example --selector s1 \
   --mail-from '<a@orig.example>' --rcpt-to '<b@x.example>' < msg.eml > m1.eml
# (modify m1.eml -> m1mod.eml)
$S --key k2.pem --domain list.example --selector s2 \
   --mail-from '<l@list.example>' --rcpt-to '<b@x.example>' \
   --orig m1.eml < m1mod.eml > m2.eml
$V --dns-fixture zone.txt < m2.eml          # expect PASS (exit 0)
```

Plus the live IETF interop harness (modified, multi-instance vectors) via the
CLIs. Then the Postfix milter verify path needs no new code: a delivered
multi-instance message should log `DKIM2 verify=pass` with recipe
reconstruction.

### Deferred follow-up: in-milter modification engine

Once the library lands, a separate milestone can add a daemon-side modification
engine (footer / subject-tag / header rewrite) behind new default-off config
keys, which performs the change, calls `dkim2_recipe_generate()` on the
before/after, and emits the new `Message-Instance` + `DKIM2-Signature` via the
existing `dkimf_dkim2_sign_msg()` path. This is what lets phoenixdkim itself act
as a recording list/gateway milter rather than a library a list/gateway calls.

## Spec drift watch

Track `draft-ietf-dkim-dkim2-spec` (currently -02). The interop C/Go reference
moved to it; the older `draft-clayton-dkim2-spec-08` differs (envelope was a
JSON `m=` blob; the MI pointer tag was `v=`). When a new revision lands, re-check
§5 (hashing), §7 (tags), §8.5 (signing input), §10 (verifier), and — for the
extended work — §4 (recipe JSON: `c`/`d` ops, line/field-ordinal granularity,
`null` for irreversible) and §9.2 (backward reconstruction / cross-instance
verification), then re-run the CLIs against the interop harness.
