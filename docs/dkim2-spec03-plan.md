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

## Make a plan for:

1. **`nd=` emission** / forward-signing in the daemon (future
  `conf_dkim2_no_destination`).
2. **DSN propagation** rewrite (§12) — no DSN code exists today.


# Additional tasks to plan

## 1. Create an implemented-doc
  Create a doc with a comparison between the current spec (spec-03)
  and what/how/where we have implemented this. The purpose is to know what
  part(s) (it should be all!) of the DKIM2 are implemented, how, and where.
  No need to go into great technical details or list all line numbers; just
  a brief indication where to look.
  Besides, some parts of the spec will be very precise - we ought to have
  implemented those exactly according to spec and reference (Perl).
  Other parts leave room for interpretation, or leeway for the implementer /
  sysadmin (perhaps with a knob). In that case, what did we choose, or what
  knobs did we implement, and why did we choose that path?
  The final document should give a very clear overview of the status of our
  DKIM2 implementation, and perhaps result in questions to be asked to the
  DKIM WG for further information.

## 2. Can we create tags in git that belong only to a specific branch?
  The idea would be to have a tag for spec-02 (when it was fully implemented;
  we would have to temporarily roll back a few spec-03 commits), then a
  working spec-03 tag, etc etc. Gives a nice roll-back in the future if wanted.
