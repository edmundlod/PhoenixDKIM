# DKIM2 spec-02 → spec-03 alignment

> Implementation plan — to be executed in a new session.
> Source diff: `docs/draft-ietf-dkim-dkim2-spec_diff-02-03.txt`.

## Context

PhoenixDKIM's DKIM2 implementation was built against
`draft-ietf-dkim-dkim2-spec-02`. spec-03 (published 2026-06-24) introduces four
implementor-facing changes. We need to bring the library and milter into
conformance so we correctly **accept and validate** mail from other DKIM2
networks, without yet taking on the larger emit/DSN work.

The four spec-03 changes and our disposition:

1. **`nd=` tag** — new "imaginary hop" / forward-signing tag, alternative to
   `mf=`+`rt=`. **Phase 1 (this plan): strict verification only** — read,
   accept, validate. Emitting `nd=` (a future `conf_dkim2_no_destination`
   knob for forwarding architectures) is **Phase 2, deferred**.
2. **DSN propagation rewrite** — no DSN/bounce code exists in the repo;
   **deferred**. But its sub-change does land now: **header recipes may no
   longer be `null`** (only body-null survives).
3. **`Delivered-To:` added to the ignore list** (and the ignore rules moved
   to their own spec section). One-line code change.
4. **`feedhere` flag** — new `f=` token. Flags are opaque pass-through, so
   this is recognition + docs.

Guiding principle from spec-03: **headers must be restorable, only bodies may
be destroyed.** An irreversible header change can no longer be papered over
with a null marker — the modifying hop simply signs the new state and is held
accountable from that point forward; the prior hop fails to re-verify.

## Changes

### 1. `nd=` tag — parse, validate, verify

**`libphoenixdkim/dkim2-header.h`** — add `char *sig_nd;` to
`dkim2_signature_t` (struct at ~line 37).

**`libphoenixdkim/dkim2-header.c` `dkim2_signature_parse()` (~217–288)** —
rework required-tag logic per spec-03 §8:
- Required: `i=`, `m=`, `t=`, `d=`, `s=` (unchanged for these).
- Read `nd=` (optional). Then enforce the XOR:
  - `nd=` present → `mf=` and `rt=` MUST be absent. If either is present,
    fail (maps to spec error *"tag=<y> was unexpected"*).
  - `nd=` absent → both `mf=` and `rt=` required (current behaviour).
- `dkim2_signature_free()` must free `sig_nd`.

**`libphoenixdkim/dkim2-header.c` `dkim2_signature_format()` (~290–337)** —
when `sig_nd` is set, emit `i=; m=; t=; nd=<dom>; d=; s=;` (omit `mf=`/`rt=`);
otherwise the existing `mf=`/`rt=` form. (Used for canonical reconstruction;
raw-byte signing path already covers `nd=` automatically — confirmed via
`dkim2_build_input_85`.)

**`libphoenixdkim/dkim2-verify.c` chain-of-custody loop (~505–571, spec §10.4)** —
for each signature in `i=` order:
- If it carries `nd=` (no `mf=`/`rt=`): skip the `mf=`→`d=` match; instead
  require an exact match between `nd=` and the `d=` of the **next** signature
  in sequence. No next signature, or mismatch → PERMERROR
  *"DKIM2-Signature i=<x> nd= does not match"*.
- Else: existing `mf=` decode / `dkim2_domain_match` logic.
- **Final-hop rule:** the highest-`i=` signature MUST carry `mf=`/`rt=` (not
  `nd=`). Enforce before the live-envelope match (which only applies to that
  top signature).
- Update the human-readable error strings to the spec-03 forms that prefix
  `DKIM2-Signature i=<x>` (MAIL FROM / RCPT TO / `d=` mismatches). The result
  struct already carries the `i=`.

### 2. Null recipe — forbid header-null, body-null only

**`libphoenixdkim/dkim2-recipe.c` parse (~370–381)** — split the all-or-nothing
`re_null`:
- `{"h":null}` → **reject** (invalid per spec-03 §5.1) — fail the parse.
- `{"b":null}` → set the body-null marker; header object still parsed normally.
- Allow a recipe that carries both a concrete `h` object **and** body-null.

**`libphoenixdkim/dkim2-recipe.c` format (~512–514)** — emit `{"b":null}` (not
`{"h":null}`) for the body-null case, alongside any `h` object present.

Represent this by letting the recipe hold header ops and a separate
`re_body_null` flag simultaneously (reinterpret the existing `re_null` field as
body-null, or add `re_body_null` — implementer's choice; keep it minimal).

### 3. Daemon irreversible-modify path → body-null

**`phoenixdkim/phoenixdkim.c` (~13530–13551)** — `conf_dkim2modifyirrev` no
longer fabricates a whole-recipe null. Instead:
- Header changes (e.g. the Subject-tag deliberate modifier) flow through the
  existing recipe generator (`dkim2_recipe_generate`, reversible) so the chain
  stays intact.
- The body change is marked body-null.

Cleanest wiring: add `int sp_body_null;` to `dkim2_sign_params_t`
(`dkim2-sign.h`); in `dkim2-sign.c`'s recipe-generation path (the
`sp_orig_*` branch) force the generated recipe's body to null when set. The
daemon then sets `sp_body_null = conf->conf_dkim2modifyirrev` and stops
building the manual `nullrec`. Result: `{"h":{…},"b":null}` when both change,
`{"b":null}` when only the body changes, `{"h":{…}}` when only a header
changes.

### 4. `Delivered-To:` ignored in header hash

**`libphoenixdkim/dkim2-hash.c` `dkim2_header_is_signed()` (~103–108)** — add
`strcasecmp(name, "delivered-to") == 0 ||`. Single chokepoint; covers both
signing and verification.

### 5. `feedhere` flag

Flags are opaque pass-through (`sig_f`), so emission already works via
`DKIM2Flags`. Add `feedhere` to the documented/recognised token list (comments
+ docs + man pages); no parser change required.

### 6. Docs, tests, reference

- **`libphoenixdkim/tests/t-dkim2-unit.c`** — add: valid `nd=` chain verifies;
  `nd=` mismatch with next `d=` → PERMERROR; `nd=` with `mf=` present → reject;
  `nd=`-only top signature → reject; `{"h":null}` rejected on parse;
  `{"b":null}` still accepted; `Delivered-To:` excluded from the header hash.
- **`docs/DKIM2.md`, `docs/dkim2-dev-guide.md`** — describe `nd=` verification,
  the header-restorable / body-destroyable rule, `Delivered-To` exclusion,
  `feedhere`; note DSN propagation and `nd=` emission as deferred. Update the
  spec reference from -02 to -03.
- Man pages (`phoenixdkim2-*.8`) — refresh the flag list if it enumerates
  tokens.

## Out of scope (deferred)

- **`nd=` emission** / forward-signing in the daemon (future
  `conf_dkim2_no_destination`).
- **DSN propagation** rewrite (§12) — no DSN code exists today.

## Verification

1. `make` / project build clean (clean rebuild before quoting any warning
   counts, per project convention).
2. `t-dkim2-unit` passes, including the new `nd=` and null-recipe cases.
3. Integration: the existing `phoenixdkim/tests/t-dkim2-*` (sign, resign,
   modify) still pass; the modify test now produces `{"b":null}` rather than
   `{"h":null}` for the irreversible case — update its expected fixture.
4. Hand-craft a 2-hop message using `nd=` (i=1 `nd=esp.tld`, i=2
   `mf=`/`rt=` signed by esp.tld) and verify with `phoenixdkim2-verify`;
   confirm a tampered `nd=` (≠ next `d=`) yields the new PERMERROR.
