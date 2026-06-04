# DKIM2 Readiness Tracker

**Latest check: 2026-06-04**

This is a living document. It tracks what the emerging DKIM2 specification is
likely to require of a signing/verifying milter, and how close PhoenixDKIM
already is. Revisit it on a regular cadence (target: monthly, or whenever the
IETF DKIM WG posts a new draft revision), update the **Latest check** date at
the top, re-evaluate the readiness columns, and implement the small no-regret
items as we go so that DKIM2-core is a short hop when the RFC lands rather than
a large project.

> **Confidence caveat.** DKIM2 is an active, moving target. The requirements
> below are reconstructed from the published drafts and WG discussion as
> understood at the *Latest check* date, cross-referenced with `SCOPE.md`.
> Treat every "Likely required" row as provisional until confirmed against the
> then-current draft text. Do **not** ship wire-format DKIM2 code off this
> document alone — re-read the draft first. Nothing here authorises
> implementing DKIM2 wire output; per `SCOPE.md` that waits for Proposed
> Standard. This document is for *readiness*, not *implementation*.

---

## 1. Documents being tracked

Re-fetch and re-date these every check. Mailing list: `ietf-dkim@ietf.org`.
WG datatracker: <https://datatracker.ietf.org/wg/dkim/documents/>.

| Document | Role | What to watch for |
|---|---|---|
| `draft-ietf-dkim-dkim2-motivation` (a.k.a. problem statement) | Why DKIM2 exists | Scope changes that add/remove a core obligation |
| `draft-ietf-dkim-dkim2-spec` | **DKIM2-core** — the header, the chain, the algorithms | Header name, tag set, canonicalisation, mandatory algorithms, envelope-binding rules |
| `draft-ietf-dkim-dkim2-headers` (if split out) | Which headers are signed and how | Header oversigning obligations |
| `draft-ietf-dkim-dkim2-modification` / body recipes | **DKIM2-extended** — stateful forwarding, body diffs | Out of scope until WG settles open issues |
| `draft-moccia-dkim2-deployment-profile` | Milter deployment profile | Confirms milter callbacks suffice; watch for new callback/timing needs |

**Action each check:** record the latest revision number and date of
`draft-ietf-dkim-dkim2-spec` here so drift is visible.
Last recorded revision seen: *(unverified — confirm on next check)*.

---

## 2. DKIM2-core — likely requirements vs. our readiness

Legend: ✅ have it · 🟡 partial / adaptable · 🔴 not yet · ❔ depends on final draft

| # | Likely DKIM2-core requirement | PhoenixDKIM today | State | Notes |
|---|---|---|---|---|
| C1 | New header (`DKIM2-Signature` or numbered/sequence header), emitted in **parallel** with `DKIM-Signature` | `DKIM-Signature` build path is mature; signature-header construction is centralised | 🟡 | We construct one header type today; DKIM2 adds a second. The dstring builder, tag emission, and header-insertion plumbing are reusable. |
| C2 | tag=value header syntax (`v=`, `d=`, `s=`, `a=`, `bh=`, `b=`, plus DKIM2 additions) | RFC 6376 tag=value parser/serialiser in `libphoenixdkim` | ✅ | Same lexical shape. New tags are additive. |
| C3 | Mandatory modern algorithms: Ed25519 + RSA-SHA256; **no** rsa-sha1 | Ed25519 (RFC 8463) + RSA-SHA256 implemented; rsa-sha1 sign/verify already refused | ✅ | Already aligned with the algorithm posture DKIM2 is expected to mandate. See `[[project_rsa_sha1_policy]]`. |
| C4 | Body + header hashing, relaxed/simple canonicalisation | `dkim-canon.c` implements both | ✅ | Body-hash *sharing* across multiple signatures is **already implemented** and verified: `dkim_add_canon()` (`libphoenixdkim/dkim-canon.c:734-751`) dedups body canons on `(canon_hdr, hashtype, canon, length)` and returns the existing `DKIM_CANON`, so the body is fed through `EVP_DigestUpdate` exactly once regardless of signature count. See `ai/optimisation-roadmap.md` §2.1. Directly satisfies the "two headers, one body hash" need for C1/C11. |
| C5 | **Envelope binding** — sign MAIL FROM and **all** RCPT TO into the header | MAIL FROM captured unconditionally; RCPT TO list captured **only when certain features are enabled** (see audit in §4.2) | 🟡 | Closer than from scratch, but *not* "fully in hand". `mctx_envfrom` is always captured (normalised, see §4.2). `mctx_rcptlist` is built **only** when `dontsigntodb`/`bldb`/`redirect`/`resigndb`/a Lua script is configured (`phoenixdkim.c:10799-10823`); a plain signer retains no recipients. Making the list available for envelope binding means capturing it unconditionally (or gated on a DKIM2/envelope switch) — a small, *bounded* change, but real, not zero. |
| C6 | **Timestamp binding** for replay prevention | `t=` timestamp already emitted; `x=` expiry supported | 🟡 | Mechanism exists; DKIM2 may mandate presence and tighten semantics. |
| C7 | **Chain of custody** — each forwarding MTA adds its own signature over the prior state | Single-pass signing; `resign` feature can re-sign in one pass | 🔴 | DKIM2 chaining is ordered and references the previous hop's signature. `resign` is a starting point but not the chain model. Real work. |
| C8 | Verify a *sequence* of DKIM2 headers and validate the chain ordering | Verifier validates independent signatures; no inter-signature ordering | 🔴 | New verifier logic. Reuses per-signature verify primitives. |
| C9 | Same DNS record structure (`selector._domainkey.domain`, same keys) | `dkim-dns.c` + `phoenixdkim-dns.c` | ✅ | DKIM2 explicitly reuses DKIM1 key infrastructure — no new record types. |
| C10 | `Authentication-Results` reporting of DKIM2 outcomes | `dkimf_add_ar_fields` / `dkimf_ar_all_sigs` already emit AR | 🟡 | Emission framework (sig-list iteration) is reusable, but the method token is a hardcoded literal and the result mapping is an `if/else` chain, **not** table-driven — see §4.5. A `method=dkim2` clause needs a small emission refactor, not just data. |
| C11 | Dual-signing transition (DKIM1 + DKIM2 on every message, no flag day) | We already emit multiple signatures per message (multisigning, Vault multi-selector) | ✅ | The multi-signature path is the exact shape dual-signing needs. |
| C12 | Opt-in compile flag for DKIM2 initially (`-DWITH_DKIM2=ON`, default OFF) | n/a (name + config namespace now reserved, §4.4) | 🔴 | Flag `WITH_DKIM2` and a `Dkim2*` config-keyword namespace are reserved (§4.4). Trivial to wire up when implementation starts; mirrors existing optional-feature pattern. |

### Reading of the table

The DKIM1 substrate DKIM2 builds on is **already present and modern**: tag=value
parsing, both canonicalisations (with body-hash sharing already implemented),
Ed25519 + RSA-SHA256, DNS key lookup, multiple signatures per message, and AR
emission. The milter captures MAIL FROM on every message and *can* capture the
full recipient list — but only when a recipient-consuming feature is enabled
(§4.2). That conditional capture is the one envelope-binding gap; the rest of
DKIM2's headline-feature raw material is in place.

The genuinely *new* engineering is the **chain model** (C7/C8): ordered,
hop-referencing signatures and chain validation. That is the part to leave until
the draft stabilises, because its wire details are the most likely to change.

---

## 3. DKIM2-extended ("dkim2extras") — out of scope, watch only

Per `SCOPE.md`, DKIM2-extended waits until the WG resolves its open design
issues. Tracked here only so the surface is known.

| Feature | Sketch | Why it's deferred |
|---|---|---|
| Body recipes / modification diffs | Forwarders record content edits so the chain still validates after list-server munging | Wire format and the diff algebra are the least settled part of the whole effort |
| Stateful intermediate signing | Forwarders keep per-message state across the chain | Architectural weight; needs the core chain model first |
| Built-in bounce/return handling | DKIM2 folds in return-path / reporting semantics | Depends on core envelope binding being final |

No PhoenixDKIM work here yet. Do not start until DKIM2-core has shipped and the
extended drafts are past their open issues.

---

## 4. No-regret preparation — audit results (2026-06-04)

These help DKIM2 **and** stand on their own merits for DKIM1, so they carry no
risk of betting on draft details that may change. Each item below has now been
*checked against the tree*; the state is recorded so a future check doesn't
re-do the investigation. None of this requires reading unstable wire format.

### 4.1 Body-hash sharing across signatures — ✅ DONE (verified)

Already implemented; not pending work. `dkim_add_canon()`
(`libphoenixdkim/dkim-canon.c:734-751`): when a *body* canon is requested it
walks `dkim_canonhead` and, on a match of `(canon_hdr == FALSE, canon_hashtype,
canon_canon, canon_length)`, returns the existing `DKIM_CANON` via `*cout`
instead of allocating a new one. So N signatures sharing body-canon parameters
share one `EVP_MD_CTX` and the body is hashed once. Dual-signing
RSA-SHA256 + Ed25519 today — and DKIM1 + DKIM2 later — both hit this path.
Cross-ref `ai/optimisation-roadmap.md` §2.1. **No action.**

### 4.2 Envelope-capture completeness — ✅ AUDITED (one gap found)

Audit of `phoenixdkim.c` (`mlfi_envfrom` ~10702, `mlfi_envrcpt` ~10782,
`dkimf_cleanup` ~8509):

- **MAIL FROM (`mctx_envfrom`):** captured on *every* message, unconditionally.
  *Not* byte-verbatim, though — surrounding `<>` are stripped
  (`phoenixdkim.c:10743-10754`) and the value is `strlcpy`-truncated at
  `MAXADDRESS`. ESMTP parameters (`envfrom[1..]`) are discarded. For envelope
  binding this is the normalised address, which is almost certainly what the
  spec will bind, but signer and verifier must agree on the *same* normalisation
  — flag this when the draft text is read.
- **RCPT TO (`mctx_rcptlist`):** the one real gap. It is built **only** inside
  the `dontsigntodb || bldb || redirect || resigndb || (Lua setup/screen/final)`
  guard (`phoenixdkim.c:10799-10823`). A plain signer with none of those enabled
  reaches EOM with an **empty** recipient list. **Within** that guard every RCPT
  *is* retained (no truncation to "first only"), so the "keeps every recipient"
  worry is unfounded — but two caveats: addresses are bracket-stripped, and the
  list is built **LIFO** (`a->a_next = list; list = a`), i.e. reverse arrival
  order. DKIM2 envelope binding may require canonical/arrival ordering, so a
  reversal-or-sort step will be needed at signing time.
- **Multi-message-per-connection:** correct. `mlfi_envfrom` calls
  `dkimf_cleanup()` + `dkimf_initcontext()`, giving a fresh `dfc` (and fresh
  empty `mctx_rcptlist` / `mctx_envfrom`) for each `MAIL FROM`. No leakage of one
  message's envelope into the next.

**Conclusion:** no code change is warranted *now* — unconditional recipient
capture has a cost/footprint that DKIM1 alone doesn't justify, and SCOPE gates
the DKIM2 feature itself. The deliverable of this audit is the corrected C5 row
and this record. When DKIM2 work begins, the envelope-binding step must (a) make
recipient capture unconditional or gate it on the DKIM2 switch, (b) normalise
ordering, and (c) pin the MAIL FROM normalisation to the draft.

### 4.3 Signature-header construction is centralised — ✅ CONFIRMED

There is a single emit site: the loop over `mctx_srhead` in `mlfi_eom`
(`phoenixdkim.c:13326-13352`) calls `dkim_getsighdr_d()` and inserts via
`dkimf_insheader(ctx, 0, DKIM_SIGNHEADER, …)`. A second header type is therefore
a *parameterisation* of this loop (header name + the matching `getsighdr`
variant), not a fork. The header name is currently the hardcoded `DKIM_SIGNHEADER`
constant — the one spot to generalise. **No action; documented.**

### 4.4 Reserve `WITH_DKIM2` flag + config namespace — DECISION RECORDED

- Compile flag: **`WITH_DKIM2`** (CMake `option(WITH_DKIM2 … OFF)`), mirroring the
  existing `WITH_*` optional-feature pattern. Default OFF until Proposed Standard.
- Config keywords: use a **`Dkim2*` prefix** for new config options
  (e.g. `Dkim2Signing`, `Dkim2EnvelopeBinding`) rather than overloading existing
  keywords, so DKIM1 behaviour is untouched when the feature is compiled out and
  the namespace is self-documenting in `phoenixdkim.conf.5`.

These are reservations only — nothing is wired up yet.

### 4.5 AR emission — ⚠️ NOT actually table-driven for *emission*

Correction to the earlier optimistic note. AR *parsing* has a method table
(`phoenixdkim-ar.c:55`, `ares_method[]`), but AR *emission* writes the method
token as a literal: `"…; dkim=%s (%s)"` (`phoenixdkim.c:12470`) and
`"dkim=none"` (`13089`), and the per-signature result is mapped by an `if/else`
chain in `dkimf_ar_all_sigs` (~9979). The iteration over the sig list is generic
and reusable, but adding a `method=dkim2` clause would today be a new
format-string branch, **not** a pure data change. Making the method token and
result mapping table-driven is a small, self-contained refactor that would be
justified when DKIM2 AR clauses are added — noted, not done (no DKIM1 benefit on
its own, and it touches the verifier-reporting path).

---

## 5. Re-evaluation checklist (run each check)

- [ ] Pull the latest `draft-ietf-dkim-dkim2-spec`; record its revision + date in §1.
- [ ] Diff the header name, tag set, and mandatory algorithms against §2 C1–C3.
- [ ] Confirm envelope-binding semantics (C5) haven't changed shape.
- [ ] Note any new milter-timing/callback requirement from the deployment profile.
- [ ] Check whether the WG has set a Proposed Standard / shepherd / IESG date —
      that is the `SCOPE.md` trigger to begin implementation.
- [ ] Update the readiness states; move any newly-safe prep item into `TODO.md`.
- [ ] Bump the **Latest check** date at the top.

---

## 6. DKIM2-core implementation checklist (shovel-ready, gated)

**Do not start this until the §5 trigger fires** (`draft-ietf-dkim-dkim2-spec`
at Proposed Standard with a shepherd/IESG date — the `SCOPE.md` gate). This
section exists so that, the day the gate opens, the work is a sequence of small
PRs rather than a design exercise. Everything below lives behind
`#ifdef WITH_DKIM2` / `option(WITH_DKIM2 … OFF)`; with the flag off the build and
behaviour are byte-identical to today.

Each phase is independently shippable and leaves the tree green. Phases 0–3 are
infrastructure that contains **no wire-format bytes** and could in principle be
merged even slightly ahead of the gate; phases 4+ encode draft-specific format
and MUST be (re-)checked against the then-current draft text first. Every phase
marked **[DRAFT-PINNED]** must not be coded from this document — re-read the
draft.

### Phase 0 — Build & config scaffolding (no behaviour)
Mirror the existing `WITH_REDIS` plumbing exactly:
- [ ] Add `option(WITH_DKIM2 "DKIM2-core support (experimental)" OFF)` in
      `phoenixdkim/CMakeLists.txt` (alongside the other `option(WITH_…)` at ~L61),
      and add `WITH_DKIM2` to the propagation `foreach(_opt …)` at ~L218.
- [ ] Add `#cmakedefine WITH_DKIM2 1` to `libphoenixdkim/build-config.h.cmake.in`
      (next to `WITH_REDIS` at ~L80).
- [ ] Reserve the `Dkim2*` config-keyword namespace in `phoenixdkim/config.c`
      with every keyword `#ifdef WITH_DKIM2`. Minimum set to stub:
      `Dkim2Signing` (bool), `Dkim2EnvelopeBinding` (bool),
      `Dkim2SelectorKeyFile` / reuse existing key plumbing.
- [ ] Document the namespace in `phoenixdkim.conf.5` under an "Experimental"
      heading, clearly marked not-for-production.
- [ ] CI: add one build matrix entry with `-DWITH_DKIM2=ON` that must at least
      compile and pass the existing DKIM1 suite unchanged.

### Phase 1 — Envelope capture made unconditional under the flag
Closes the C5 / §4.2 gap. **No wire format involved** — pure data retention.
- [ ] In `mlfi_envrcpt` (`phoenixdkim.c:10799-10823`) add `conf->conf_dkim2signing`
      (or the resolved `Dkim2EnvelopeBinding`) to the capture guard so the RCPT
      list is retained when DKIM2 is active, independent of the DKIM1 feature
      switches. Keep the existing DKIM1 conditions intact.
- [ ] Decide and record recipient **ordering**: the list is built LIFO today.
      Reverse-on-read at signing time (cheap) rather than changing the hot insert
      path. Add a helper `dkimf_rcptlist_in_order()` and a unit/integration test
      asserting arrival order for N recipients across multiple `RCPT TO`.
- [ ] Confirm (test) the per-message reset still holds with the flag on:
      `dkimf_cleanup` + `dkimf_initcontext` in `mlfi_envfrom` gives a fresh empty
      list per message on a reused connection.
- [ ] Leave MAIL FROM capture as-is for now; record the exact normalisation
      (bracket-strip, `MAXADDRESS` cap) as the binding input — pin to draft in
      Phase 4.

### Phase 2 — AR emission made method-token-driven (DKIM1-safe refactor)
Removes the §4.5 wart. Behaviour-neutral for DKIM1; precondition for C10.
- [ ] In `dkimf_ar_all_sigs` (`phoenixdkim.c:~9979`) and the `"dkim=%s"` sites
      (`12470`, `13089`), parameterise the method token via a small table /enum
      instead of the literal `"dkim"`. DKIM1 output must be byte-identical
      (assert with a golden AR test).
- [ ] Lift the `if/else` result-string mapping into a `{ sigerror → result }`
      table so a DKIM2 result set is a data addition. Verify against existing AR
      tests (frozen — raise discrepancies, don't edit tests).

### Phase 3 — Signature-header emitter generalised
Precondition for C1; **no DKIM2 bytes yet**.
- [ ] Parameterise the emit loop (`phoenixdkim.c:13326-13352`) by header name +
      a `getsighdr` variant, so `DKIM_SIGNHEADER` is no longer hardcoded. DKIM1
      path unchanged (still emits `DKIM-Signature`).
- [ ] Confirm body-hash sharing (`dkim_add_canon`) is exercised when both a DKIM1
      and a (stub) DKIM2 signreq request the same body canon — add a test that
      asserts a single `DKIM_CANON` for the body. (Validates §4.1 holds for the
      dual-sign shape.)

### Phase 4 — DKIM2-Signature header construction **[DRAFT-PINNED]**
First phase that writes spec bytes. **Re-read the draft before any line here.**
- [ ] Confirm from the draft: exact header name, tag set, tag order/oversigning,
      canonicalisation, mandatory algorithms (expect Ed25519 + RSA-SHA256, no
      sha1 — already our posture, `[[project_rsa_sha1_policy]]`).
- [ ] Implement a `dkim2` emitter in `libphoenixdkim` reusing the existing
      tag=value dstring builder (C2) and the shared body hash (C4/§4.1).
- [ ] Encode envelope binding: canonicalise MAIL FROM + ordered RCPT list (from
      Phase 1) into the signed tag set per the draft's exact rules.
- [ ] Encode timestamp binding (`t=`/expiry) to the draft's mandated semantics.

### Phase 5 — Dual-signing wiring **[DRAFT-PINNED]**
- [ ] Add a DKIM2 signreq alongside the DKIM1 one on the `mctx_srhead` list so
      both headers are emitted in one pass over one body hash (C11). Default:
      emit both when `Dkim2Signing` is on; never a flag day.
- [ ] Golden test: a message signed with both, DKIM1 verifier sees a valid
      `DKIM-Signature`, DKIM2 verifier sees a valid `DKIM2-Signature`, neither
      perturbs the other.

### Phase 6 — DKIM2 verification + AR reporting **[DRAFT-PINNED]**
- [ ] Verify a single `DKIM2-Signature` (reuse per-signature verify primitives).
- [ ] Emit `method=dkim2` AR clauses via the Phase 2 table.
- [ ] **Chain validation (C7/C8) is the genuinely new, least-settled work** —
      ordered, hop-referencing signatures and sequence validation. Treat as its
      own sub-project; do not fold into Phase 6 until the chain wire details in
      the draft are stable.

### Out of scope for this checklist
DKIM2-extended (body recipes / modification diffs, stateful intermediate
signing, built-in bounce handling) — see §3. Do not begin until DKIM2-core has
shipped and the extended drafts clear their open issues.

---

*Owner note:* `SCOPE.md` Goal 10 references this file. Keep them consistent —
if the strategic posture in `SCOPE.md` changes, reflect it here, and vice versa.
