# DKIM2 spec-03 follow-up — status & handoff

> Living status doc for the post-verification spec-03 work. spec-03 *verification*
> (accept/validate `nd=`, null-recipe tightening, `Delivered-To` ignore,
> `feedhere`) already landed in `dcf3d68a`. This tracks the four remaining items
> and is written so a new session can pick up mid-stream.
>
> Source diff: `docs/draft-ietf-dkim-dkim2-spec_diff-02-03.txt`.
> Reference impl: `dkim2wg/interop` `brong/` (Perl) — `Mail::DKIM2::*`.

## Status at a glance

| # | Item | State |
|---|------|-------|
| 1 | `nd=` emission (library primitive + knob) | **DONE** |
| 2 | DSN (§12): library + CLI + tests | **TODO** (next big push) |
| 3 | `docs/dkim2-implemented.md` status doc | TODO |
| 4 | Milestone git tags (spec02 / spec03) | TODO (needs operator present — GPG) |

## Cross-cutting decisions (settled — do not relitigate)

- **DSN delivery is not a milter job.** The reference milter
  (`DKIM2Sign`/`DKIM2Verify`) signs/verifies only; all DSN logic lives in the
  library + a CLI. Production "generate a DSN when delivery fails" is the **MTA's**
  responsibility (Bron: doable on Postfix with no core changes; demo not yet
  published). Generating a DSN is *option 5* — a capability, **not a delivery
  MUST** (an unverifiable message is rejected 5xx instead). So we ship the library
  + CLI; we do **not** build MTA wiring (documented as drift-watch).
- **DSN `d=`/`rt=` alignment: strict.** A DSN's `d=` MUST be the same as, or a
  subdomain of, the original highest-`i=` `rt=` domain. We rejected the looser
  "either direction" reading: with `mf=<>` the forward-path `mf=` pivot is gone, so
  allowing `d=` *above* `rt=` would let a hoster apex key forge bounces for any
  customer subdomain (the fake-bounce hole). Implement as a swappable predicate;
  it is also a flagged WG question (spec only says "aligned with").

---

## Item 1 — `nd=` emission ✅ DONE

Library-primitive-plus-knob, mirroring the reference `Signer.pm` `NextDomain`. The
full two-signature *delegated-key* forwarder orchestration (imaginary-hop sig
signed with an inbound-recipient-domain key **plus** the real outward `mf=`/`rt=`
sig in one pass — reference `Reflector::generate_brand`, draft §9.3) is
**deferred**.

Implemented in:
- `libphoenixdkim/dkim2-sign.h` — `sp_nd` field on `dkim2_sign_params_t`.
- `libphoenixdkim/dkim2-sign.c` — `dkim2_build_sig_value()` gained an `nd`
  parameter: when set, emit `nd=` and suppress `mf=`/`rt=`; threaded through both
  the incomplete and complete signing-input builds. (The verify/CLI serialiser
  `dkim2_signature_format()` in `dkim2-header.c` already handled `nd=`.)
- `phoenixdkim/phoenixdkim-config.h` + `phoenixdkim.c` — `DKIM2NoDestination`
  config key → `conf_dkim2nodest` → `p.sp_nd` in `dkimf_dkim2_sign_msg()`.
- `libphoenixdkim/phoenixdkim2-sign.c` — `--nd DOMAIN` flag (`--mail-from`
  optional when used).
- `libphoenixdkim/tests/t-dkim2-unit.c` — `test_nd()` now drives real emission via
  `sign_hop_nd()` (originator emits the `nd=` hop; full chain verifies PASS). The
  old manual `build_nd_sig()` helper was removed.
- Docs: `DKIM2NoDestination` in `phoenixdkim.conf.5`; `dkim2-dev-guide.md`
  drift-watch updated.

Verified: 7/7 DKIM2 ctests pass; clean in `build-dkim2` and `build-strict`.

---

## Item 2 — DSN (§12): library + CLI + offline tests  ← START HERE

Mirror `brong/lib/Mail/DKIM2/DSN.pm`. **No milter changes.**

**New `libphoenixdkim/dkim2-dsn.{c,h}`:**
- `dkim2_dsn_generate()` — fresh 3-part `multipart/report` (human text,
  `message/delivery-status`, `message/rfc822` original), `MAIL FROM <>`, signed as
  a **new** message (exactly one Message-Instance + one DKIM2-Signature). Addressed
  to top-sig `mf=` (else `From:`). Works for signed *and* unsigned inbound.
- `dkim2_dsn_propagate()` — §12.1.1: undo our own top MI modification, strip the
  DKIM2-Signature we added, rebuild the embedded original (`message/rfc822`, or
  `text/rfc822-headers` if the body is unrecoverable via a null recipe),
  re-address to the now-top `mf=`, re-sign as a new message.
- `dkim2_dsn_align()` — **isolated, swappable predicate**: DSN `d=` is
  same-or-subdomain of the embedded original's highest-`i=` `rt=` domain (strict).
  Used on generate (choose `d=`) and on inbound auth.
- Inbound auth (§12.1.2): verify embedded original via `dkim2_verify`, check
  `dkim2_dsn_align()`, validate our own signature in the quoted original.

**Reuse (do not reimplement):**
- `dkim2-recipe.c` — `dkim2_recipe_apply` / MI undo.
- `dkim2-verify.c` — `dkim2_verify`, `dkim2_domain_match` (exact-or-subdomain; the
  alignment helper).
- `dkim2-sign.c` — `dkim2_sign` (sign-as-new).
- `dkim2-header.c` — `dkim2_signature_parse`, `sig_i`, `sig_rt`, `sig_mf`.
- `phoenixdkim/phoenixdkim-dkim2store.{c,h}` — snapshot store already holds the
  keyed original; the DSN module *reads* it, no new persistence.
- `dkim2-eml.c` for splitting; a small `multipart/report` builder is the only
  genuinely new plumbing.

**New CLI `phoenixdkim2-dsn`** (+ `.8` man page) alongside
`phoenixdkim2-{sign,verify,undo}`: `generate` / `propagate` / `authenticate`.

**Tests** — new `libphoenixdkim/tests/t-dkim2-dsn.c` (or extend `t-dkim2-unit.c`),
mirror `brong/t/dsn.t`: one-MI/one-sig invariant, `multipart/report` +
`report-type`, generated DSN verifies `pass`, propagate addresses to upstream
`mf=`, alignment accept/reject. Add the `multipart/report` parser to
`fuzz-dkim2.c`.

**Out of scope (document in `dkim2-dev-guide.md` drift-watch, don't build):** the
Postfix `pipe(8)` / transport that invokes the CLI at runtime; mirror Bron's demo
once published.

---

## Item 3 — `docs/dkim2-implemented.md` status doc

spec-03 § → implementation map: **where** (file, not line spam), **how**
(exact-to-spec vs. implementer leeway), **why** for each choice/knob. Source: the
module map in `dkim2-dev-guide.md` + the spec diff. Must include an **"Open
questions for the DKIM WG"** section (same content as Appendix A):
- DSN `d=`/`rt=` alignment relation (we chose strict same-or-subdomain).
- End-MTA DSN generation: per-deployment custom pipe vs. native MTA support.
- Retention of the keyed original.

---

## Item 4 — Milestone git tags

Tags aren't branch-scoped, but you can tag the historical commit directly — no
rollback needed for tagging.
- `dkim2-spec02` → **`88cbd16f`** (parent of first spec-03 *code* commit
  `dcf3d68a`; docs-only over the last spec-02 code `64d8eb2d`, so its tree *is*
  spec-02).
- `dkim2-spec03` → `dcf3d68a` (or the tip once Items 1–3 land — decide at tag
  time).
- Annotated (`git tag -a`), GPG-signed per repo convention. Document the scheme in
  `dkim2-dev-guide.md`. **Run with the operator present** (GPG pinentry can time
  out).

---

## Verification (whole effort)

- Configure with `-DWITH_LUA=1 -DWITH_REDIS=1 -DWITH_DKIM2=1`; build dirs
  `build-dkim2` (functional) and `build-strict` (strict + sanitizers).
- `ctest -R dkim2` — `nd=` emission + new `t-dkim2-dsn` pass.
- CLI round-trips: `phoenixdkim2-sign --nd fwd.example …` → `phoenixdkim2-verify`
  accepts; `phoenixdkim2-dsn generate/propagate` output verifies `pass` and meets
  the one-MI/one-sig + alignment invariants.
- Cross-check generated/propagated DSNs against `dkim2wg/interop` where live.

---

## Appendix A — WG outreach (DSN open questions)

One question per thread (Bron prefers clean threading). Send Email 1 first (new
thread); send Email 2 as a reply into Hannah's existing "what does *aligned with*
mean" thread; hold the rest unless still open after.

### Email 1 — new thread
> **Subject:** DKIM2 DSNs: who actually generates them on a normal MTA?
>
> Implementing §12 in PhoenixDKIM (an OpenDKIM fork — milter plus library), and the
> practical question is where DSN generation is supposed to live.
>
> A milter can't do it: once we've answered `250` the session is gone and there's
> no milter in the async bounce path. And the MTA's own bounce generator knows
> nothing about DKIM2 — it won't undo recipe changes or sign the DSN as a fresh
> message with `mf=<>`. The suggestion has been that you can do this on Postfix
> today without core changes, presumably a pipe/transport that shells out to a
> DKIM2 library and re-injects.
>
> That works, but is the expectation really that every operator wires their own
> pipe, per MTA? That feels fragile and a good way to end up with a dozen subtly
> incompatible bounce paths. Is the intent that this eventually lands *in* the MTAs
> (Postfix/Exim/Sendmail), with the pipe just a stopgap? Even a one-line
> implementer's note — "yes, this belongs in the MTA, here's the rough shape" —
> would stop people reinventing it differently.

### Email 2 — reply into the existing alignment thread
> **Subject:** Re: <Hannah's alignment thread>
>
> Narrowing the "what does *aligned with* mean" question to the DSN case, since it
> loses the usual pivot:
>
> On the forward path alignment leans on `mf=` (new `mf=` ≤ some prior `rt=`, and
> `mf=` ≤ `d=`), so `d=` can sit anywhere comparable on that branch. A DSN has
> `mf=<>`, so there's nothing to pivot through — we have to state the `d=`↔`rt=`
> relation directly.
>
> I've gone strict for now: a DSN's `d=` must be the same as, or a subdomain of,
> the original highest-`i=` `rt=` domain. Allowing `d=` *above* `rt=` would let a
> hoster's apex key mint bounces for any customer subdomain under it — which hands
> back exactly the fake-bounce trick the alignment is there to stop. Is
> same-or-subdomain the intended relation, is exact match wanted, or is it
> genuinely either-direction? Happy to be told I'm over-tightening.

### Held drafts (send only if still open)
> **Inbound DSN authentication / key availability.** §12.1.2 has the receiver
> validate the embedded original and its own signature in it. But a safe DSN has to
> be signed by a key aligned to the recipient/`rt=` domain, which a forwarder often
> won't have. What exactly MUST a receiver check on an inbound DSN, and what's the
> right move when there's no aligned key — reject 5xx in-session, or just not
> produce a DSN?

> **Retention.** Generating or propagating a DSN means keeping the original (or
> derived) message around, keyed by Message-Instance. Any interop guidance on a
> minimum, or is that purely local policy?
