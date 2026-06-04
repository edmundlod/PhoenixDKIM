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
| C4 | Body + header hashing, relaxed/simple canonicalisation | `dkim-canon.c` implements both | ✅ | Body-hash *sharing* across multiple signatures is the optimisation that makes dual-signing cheap — see `ai/optimisation-roadmap.md`. Directly relevant to C1 (two headers, one body hash). |
| C5 | **Envelope binding** — sign MAIL FROM and **all** RCPT TO into the header | Milter already captures `mctx_envfrom` and the full `mctx_rcptlist` (`phoenixdkim.c`) | 🟡 | The *data is already in hand* at signing time. What's missing is canonicalising it into the signed tag set — a new feature, not new plumbing. This is the single biggest "we're closer than it looks" item. |
| C6 | **Timestamp binding** for replay prevention | `t=` timestamp already emitted; `x=` expiry supported | 🟡 | Mechanism exists; DKIM2 may mandate presence and tighten semantics. |
| C7 | **Chain of custody** — each forwarding MTA adds its own signature over the prior state | Single-pass signing; `resign` feature can re-sign in one pass | 🔴 | DKIM2 chaining is ordered and references the previous hop's signature. `resign` is a starting point but not the chain model. Real work. |
| C8 | Verify a *sequence* of DKIM2 headers and validate the chain ordering | Verifier validates independent signatures; no inter-signature ordering | 🔴 | New verifier logic. Reuses per-signature verify primitives. |
| C9 | Same DNS record structure (`selector._domainkey.domain`, same keys) | `dkim-dns.c` + `phoenixdkim-dns.c` | ✅ | DKIM2 explicitly reuses DKIM1 key infrastructure — no new record types. |
| C10 | `Authentication-Results` reporting of DKIM2 outcomes | `dkimf_add_ar_fields` / `dkimf_ar_all_sigs` already emit AR | 🟡 | New `method=dkim2` (or similar) AR clauses; the emission framework is in place. |
| C11 | Dual-signing transition (DKIM1 + DKIM2 on every message, no flag day) | We already emit multiple signatures per message (multisigning, Vault multi-selector) | ✅ | The multi-signature path is the exact shape dual-signing needs. |
| C12 | Opt-in compile flag for DKIM2 initially (`-DWITH_DKIM2=ON`, default OFF) | n/a | 🔴 | Trivial to add when implementation starts; mirrors existing optional-feature pattern. |

### Reading of the table

The DKIM1 substrate DKIM2 builds on is **already present and modern**: tag=value
parsing, both canonicalisations, Ed25519 + RSA-SHA256, DNS key lookup, multiple
signatures per message, and AR emission. The milter even captures the full
envelope (MAIL FROM + every RCPT TO) today, which is the data DKIM2's headline
feature (envelope binding) needs.

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

## 4. No-regret preparation we *can* do now

These help DKIM2 **and** stand on their own merits for DKIM1 today, so they carry
no risk of betting on draft details that may change. Promote them into `TODO.md`
as normal work items.

1. **Body-hash sharing across signatures** (already on the optimisation roadmap).
   Dual-signing DKIM1+DKIM2 means two headers over one body; sharing the body
   digest is what keeps that cheap. Highest-value, fully DKIM1-justified today.
2. **Audit envelope capture completeness.** Confirm `mctx_rcptlist` retains
   *every* RCPT TO (not just the first) through to EOM under multi-recipient and
   multi-message-per-connection cases, and that MAIL FROM is preserved verbatim.
   This is the raw material for C5; verifying it now is free insurance.
3. **Centralise signature-header construction** so a second header type (C1) is a
   new emitter, not a fork of the existing path. If the dstring builder is
   already factored, document that; if not, note the refactor.
4. **Reserve a compile flag name and config-keyword namespace** (`WITH_DKIM2`,
   and decide whether DKIM2 controls are new keywords or `Dkim2*` variants) so
   the eventual switch slots into the existing optional-feature pattern.
5. **Keep AR emission table-driven** so adding a `dkim2` method clause (C10) is a
   data change, not a control-flow change.

None of these require reading unstable wire format; all are justified by DKIM1
correctness/performance on their own.

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

*Owner note:* `SCOPE.md` Goal 10 references this file. Keep them consistent —
if the strategic posture in `SCOPE.md` changes, reflect it here, and vice versa.
