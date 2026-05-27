# Task: triage and clear the conversion-family strict warnings

## Scope

`build-strict/` (strict C + extra warnings + UBSan/ASan; see the strict-build
line, output in `build-warnings.txt`) currently emits **973** warnings:

| Category               | Count | Disposition |
|------------------------|-------|-------------|
| -Wsign-conversion      |  519  | THIS TASK   |
| -Wconversion           |  327  | THIS TASK   |
| -Wfloat-conversion     |   13  | THIS TASK   |
| -Wcast-qual            |   66  | OUT — already triaged/annotated in a prior pass |
| -Wformat-truncation=   |   45  | OUT — SKIP policy, all verified safe (one real site hardened: opendkim.c dkimf_sigreport) |
| -Wformat=              |    3  | STALE — the config.c:800 %p UB, already fixed; regenerate build-warnings.txt to clear |

So this task is the **859** conversion-family warnings only. Do NOT touch
-Wcast-qual or -Wformat-truncation here.

## Verdict: NOT a one-sweep fix

A blind cast sweep would silence the compiler but mask real bugs — the
warnings span ~30 distinct type-pair patterns across 20+ files, and a subset
are exactly the sign-flip cases where a latent bug hides. Work it as buckets,
hand-auditing the dangerous group.

### Buckets (by pattern, descending)

1. **`size_t ← int` / `unsigned long ← int` / `u_int ← int` sign-change**
   (~325: 239 + 44 + 42). Mostly passing signed lengths/indices into unsigned
   params. Usually safe, but each cluster must be confirmed the source can't be
   negative. Where safe, an explicit cast at the call site documents intent.
2. **`size_t → int` value-change** (127) and **`long int → int`** (26).
   Narrowing. Safe only if the value provably fits in `int` (≤ INT_MAX); confirm
   per cluster, then cast.
3. **Byte-extraction: `int`/`uint16_t`/`uint32_t`/`long` → `unsigned char`/`char`**
   (~100: 37 + 31 + 20 + …). Almost all intentional byte masking. This bucket is
   the closest to a mechanical sweep — an explicit `(unsigned char)` / `(char)`
   cast — but spot-check that each really is a deliberate low-byte grab.
4. **File-offset / socklen: `size_t ← __off_t`, `size_t → socklen_t`** (~50).
   Platform-type boundaries; cast after confirming range.
5. **`lua_Number` → int/uint/ulong (-Wfloat-conversion)** (13). Lua API
   boundary; make truncation explicit with a documented cast.
6. **⚠ MUST HAND-AUDIT — sign flips to/from the all-ones value** (~22):
   `int → size_t changes value from '-1' to '18446744073709551615'` (18),
   `unsigned long → ssize_t '…' to '-1'` (2), and similar. These are where a
   negative/error return silently becomes a huge unsigned (or vice-versa).
   Each is *either* an intentional sentinel (like the `dkim_signlen`/`(ssize_t)
   -1` case already fixed) *or* a missing error check — decide individually. Do
   NOT cast these away blindly.

## Constraints

- One bucket (or one file) per commit; "Fix:" prefix; no Co-Authored-By line.
- **Stop and ask before any API signature/typedef change** — that decision is
  the user's (precedent: the prior pass changed `dkim_sigkey_t` and split
  `dkim_options` only after explicit approval).
- Prefer fixing the underlying type over casting when the type is clearly wrong
  and local; annotate/cast when it's a forced external-boundary conversion.
- After a batch lands, regenerate `build-warnings.txt` (strict-build line) to
  re-measure; the file is a snapshot and lags the tree.
- awk/sed are fine for locating/measuring; edits should be reviewed, not blind
  global substitutions.

## Suggested order

Bucket 3 (byte-extraction, mechanical) → bucket 6 (audit, highest bug value,
small) → buckets 1/2 (bulk, per-cluster) → buckets 4/5 (boundaries).
