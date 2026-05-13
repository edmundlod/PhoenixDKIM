# PATCHES.md — External patch/issue review for opendkim-ng

Generated: 2026-05-13. Sources: upstream GitHub issues (open + recently closed),
Debian `salsa.debian.org/debian/opendkim` patch queue, FreeBSD ports rc script,
OpenBSD ports Makefile + rc script, Gentoo initd (404 — file not found at
enumerated path).

Cross-referenced against:
- SCOPE.md goals
- `git log --oneline 92951a3a..HEAD` (our fork history)
- Working tree (grep/source inspection)

---

## 1. Prioritised table

### Apply — security bugs first

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 1 | Debian patch | `cve-2020-12272.patch` | Missing character-set validation on the `d=` tag value in DKIM-Signature header. A crafted signature with illegal chars (e.g. newline, NUL, shell metachar) passes through `dkim_process_set()` unrejected. | **Apply** to `libopendkim/dkim.c` around the `d=` NULL check (~line 712). Add loop: reject any char not in `[A-Za-z0-9._-]`. | Upstream never merged this Debian-specific patch. Our tree has no such loop — verified by grep. |
| 2 | GitHub issue | #260 / CVE-2020-35766 | Heap buffer over-read in `readhead()`. PR linked to issue #113. Claims a memory-safety defect distinct from CVE-2022-48521 (which we fixed in f238cdcd). | **Investigate** `libopendkim/dkim.c` `readhead()` / header-parsing path. Determine if the over-read is a separate site from f238cdcd. | The PR (#260) proposes a fix. Needs source diff review before applying. |
| 3 | GitHub issue | #185 | `Authentication-Results` headers from external sources are stripped using wrong ordinal numbering, allowing a crafted inbound message to survive with a fake A-R header that OpenDKIM believes it already removed. Security bypass in verification mode. | **Investigate** `mlfi_eoh()` A-R removal loop for off-by-one in ordinal counting. | Still open upstream. Relevant to both signing and verifying deployments. |

### Apply — crashes and correctness

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 4 | Debian patch | `conf_refcnt.patch` | `dkimf_config_free()` contains `assert(conf->conf_refcnt == 0)` at `opendkim/opendkim.c:5394`. Under certain reload/close timing the count may be non-zero, aborting the daemon. | **Apply**: remove the assert (or replace with a `syslog(LOG_CRIT, …); return;` guard). | Confirmed present in working tree at line 5394. Debian patch simply removes the assert with no replacement — consider a logged error instead. |
| 5 | Debian patch | `mlfi_close.patch` | `#ifdef QUERY_CACHE` block in `mlfi_close()` (`opendkim.c:12811`) dereferences `cc->cctx_config` **after** the `if (cc != NULL)` block that decrements the refcount and frees `cc`. Use-after-free when `cc` is NULL. | **Apply** by deleting the entire `#ifdef QUERY_CACHE … #endif` block (3 occurrences in opendkim.c). `QUERY_CACHE` is part of the stats subsystem removed per SCOPE.md. | Confirmed: the block sits outside the `cc != NULL` guard at line 12811. No `QUERY_CACHE` define is set in CMakeLists so the block is currently inert, but the dead code should be removed. |
| 6 | Debian patch | `insheader.patch` | All calls to `dkimf_insheader(ctx, 1, …)` should be `dkimf_insheader(ctx, 0, …)`. Index 1 inserts *after* the first existing header; index 0 inserts *before all* headers. Affects `Authentication-Results`, `DKIM-Signature`, and `X-OpenDKIM` insertion order. | **Apply** to `opendkim/opendkim.c` lines 3292, 3726, 11809, 12638, 12688. Change all `dkimf_insheader(ctx, 1,` → `dkimf_insheader(ctx, 0,`. | Confirmed: all five call sites still use index 1. The Debian patch covers identical lines. |
| 7 | Debian patch | `fix-miltertest-data.patch` | `miltertest/miltertest.c`: the `mt.data()` function asserts `STATE_DATA` (wrong — it transitions *to* DATA from ENVRCPT) and the `mt.header()` function asserts `STATE_ENVRCPT` (wrong — headers come after DATA). The two state checks are swapped. | **Apply**: in `mt.data()` (~line 2614) change `STATE_DATA` → `STATE_ENVRCPT`; in `mt.header()` (~line 2711) change `STATE_ENVRCPT` → `STATE_DATA`. | Confirmed present. Causes misleading test-framework error messages and may hide milter sequencing bugs in integration tests. |
| 8 | Debian patch | `fix-miltertest-eom-check-smtpreply.patch` | `miltertest.c:3693–3694`: when `MT_SMTPREPLY` is checked, `esc` and `text` are passed directly to `snprintf` even when NULL. Undefined behaviour (NULL pointer in `%s` format argument is not guaranteed to produce `"(null)"` on all platforms). | **Apply**: change `esc` → `esc == NULL ? "" : esc` and `text` → `text == NULL ? "" : text`. | Confirmed at miltertest.c:3693. One-line fix per pointer. |
| 9 | GitHub issue | #222 / #223 | Segfault when `Minimum 100%` is set in config and an inbound message has an empty body. The `l=` tag body-limit handling does not guard against zero-length body before computing the percentage ratio. | **Investigate** `opendkim.c` around `conf_minimum` / `Minimum` config parsing (~line 5759 / 6920) and the body-canonicalisation path. Check for division by zero or NULL body pointer dereference. | Issue #223 is the proposed fix PR. Still open upstream. |
| 10 | GitHub issue | #229 / #230 | `dkimf_config_load()` sign-table consistency walk: `dkimf_db_walk()` error return is not checked correctly, causing the walk to continue on error and potentially produce a false "config OK" result. | **Investigate** `opendkim.c` signing-table validation walk in `dkimf_config_load()`. Verify that `dkimf_db_walk()` return codes are handled for both `SigningTable` and `KeyTable`. | PR #230 proposes the fix. Still open upstream. |
| 11 | GitHub issue | #262 | `DKIM_STAT_KEYFAIL` error from `dkim_eoh()` is handled in `mlfi_eom()` error path but the matching path in `mlfi_eoh()` itself (around line 10378) may not surface the error correctly, causing the milter to continue processing a message whose key retrieval already failed. | **Investigate** `mlfi_eoh()` return path when `dkimf_libstatus()` returns `DKIM_STAT_KEYFAIL`. Confirm that the milter returns `SMFIS_TEMPFAIL` rather than `SMFIS_CONTINUE`. | PR #262 addresses this. Still open upstream. |

### Investigate — lower priority

| Priority | Source | ID / File | Summary | Recommendation | Notes |
|----------|--------|-----------|---------|----------------|-------|
| 12 | GitHub issue | #233 / #234 | When a `DKIM_SIGFLAG_IGNORE`-marked signature is encountered, OpenDKIM records `dkim=fail` in `Authentication-Results` instead of `dkim=policy`. RFC 8601 §2.7.1 distinguishes these results. | **Investigate** `mlfi_eom()` result-string selection logic. | PR #234 proposes the one-line fix. Correctness issue affecting downstream policy evaluation. |
| 13 | GitHub issue | #244 | Enhanced compiler warnings on Debian/Fedora expose string-pointer aliasing issues in `opendkim.c` (vbr.c is already removed). Mis-used string pointers can produce wrong signing domain under pathological conditions. | **Investigate** with `-Wextra -Waddress` on `opendkim.c`. | PR #244 is open upstream. Low practical risk but worth auditing given the compiler warning evidence. |
| 14 | Debian patch | `nsupdate_output.patch` | `opendkim-genzone -u` (nsupdate mode) outputs bare key data without the required `v=DKIM1; k=rsa;` prefix, and does not chunk the key into 255-byte DNS TXT strings. Also adds `-M` flag to restrict key to email use (`s=email`). | **Investigate** `opendkim-genzone.c` nsupdate output path. The fix is mechanical; verify our code has the same defect before applying. | Our genzone.c has no `mailrestrict` or `subdomains` variable — the patch adds both. Apply only the nsupdate format fix; skip the `subdomains` block (that logic differs from ours). |
| 15 | Debian patch | `suppress-brackets-syslog.patch` | Startup syslog message `opendkim vX.Y.Z starting ()` prints empty parentheses when no arguments are logged. | **Apply** cosmetically: guard the `(%s)` format with a ternary, or omit parens when `argstr` is empty. | Confirmed at `opendkim.c:14484`. One-line fix. Low priority. |

### Skip

| Source | ID / File | Reason |
|--------|-----------|--------|
| Debian patch | `fix-RSA_Sign-call.patch` | Patches `RSA_sign()` type mismatch — function replaced by EVP APIs in our fork (Session 6). |
| Debian patch | `2048bit-genkey.patch` | Default key size already enforced at 2048 bits in our fork (`MinKeyBits`, commit `0e4aad7d`). |
| Debian patch | `replace-headers.patch` | Adds `ReplaceHeaders` config inside `#ifdef _FFR_REPLACE_RULES`. Feature removed per SCOPE.md. |
| Debian patch | `fix-genzone-subdomains.patch` | Fixes a `subdomains` flag logic block in `opendkim-genzone.c`. Our genzone has no `subdomains` variable — the feature was not ported. N/A. |
| Debian patch | `lua-5.3.patch` | `lua_dump()` extra-arg and `luaL_newlib` already handled in our Lua 5.4 port (commit `a87e550b`, `opendkim-lua.c:538` confirmed). |
| Debian patch | `ares-missing-space.patch` | c-ares / libar removed per SCOPE.md (commit `c3f6e3f9`). |
| Debian patch | `rev-ares-deletion.patch` | libar removed. |
| Debian patch | `opendkim-genkey-typo.patch` | Upstream man-page typo in `.8.in` — we have rewritten man pages, not the autotools `.in` versions. |
| GitHub issue | #255, #235, #236 | Website / opendkim.org dead links. Not software. |
| GitHub issue | #258, #257 | `SingleAuthResult` in sample config — already absent from our `opendkim.conf.sample`. |
| GitHub issue | #248, #251 | MySQL password / auth plugin issues — MySQL backend removed per SCOPE.md. |
| GitHub issue | #224 | `librbl/rbl.c` typo — librbl removed per SCOPE.md. |
| GitHub issue | #237 | Python `twisted.internet.defer.returnValue` — not C code, not in scope. |
| GitHub issue | #249 | macOS port group membership issue — macOS is not a target platform. |
| GitHub issue | #253 | VSZ memory growth under load test — operational question, not a code defect. |
| GitHub issue | #165 | Systemd `network-online.target` — already in our `debian/opendkim.service`. |
| GitHub issue | #38 | `/var/run` vs `/run` path — already resolved by `RuntimeDirectory=opendkim` in our service unit. |
| GitHub issue | #242 | `AlwaysAddARHeader` default — feature request, out of scope for this session. |
| GitHub issue | #241 | Lua `final` hook header mutation — feature request, out of scope. |
| GitHub issue | #232 | Config option to require `d=` matches `From:` — feature request, out of scope. |
| GitHub issue | #246 | Ed25519 in opendkim-genkey — already added in our fork (commit `3858b88d`). |
| GitHub issue | #243 | Ed25519 tests — partially addressed; `dkim_free()` memory leak subpoint needs separate investigation. |
| GitHub issue | #221 | Config option case sensitivity — documentation / user question, not a defect. |
| GitHub issue | #225 | Test failures on upstream autotools build — our CMake build passes. Not applicable. |

---

## 2. RC/init patterns worth adopting

Comparing **FreeBSD** `milter-opendkim.in` and **OpenBSD** `opendkim.rc` against our
`debian/opendkim.service`. Items marked ★ are currently missing from our service unit.

- **★ Additional systemd hardening directives.** Our unit has `ProtectSystem=strict` and
  `ProtectHome=true` but is missing `NoNewPrivileges=true`, `PrivateTmp=true`,
  `LockPersonality=true`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, and
  `MemoryDenyWriteExecute=true`. FreeBSD and OpenBSD achieve equivalent isolation
  through `jail(8)` and `pledge(2)` — on Linux, systemd sandboxing directives are the
  idiomatic equivalent.

- **Socket cleanup on stop.** FreeBSD's `stop_postcmd` unconditionally removes the Unix
  domain socket file (`rm -f "$socket"`) when `socket_type == local|unix`. Our
  `RuntimeDirectory=opendkim` causes systemd to clean `/run/opendkim/` on stop, so this
  is already covered on systemd systems. Worth documenting for any future non-systemd
  init script (e.g. OpenRC for Gentoo/Alpine).

- **PidFile auto-detection from opendkim.conf.** FreeBSD reads the `PidFile` value
  directly from the config file at rc-script runtime (`get_pidfile_from_conf`), rather
  than hardcoding `/var/run/milteropendkim/pid`. This avoids divergence when the admin
  changes `PidFile` in opendkim.conf. Our systemd unit does not manage a pidfile
  (`Type=simple`), so this is irrelevant for systemd but matters for portable rc scripts.

- **★ Multi-instance / profile support.** FreeBSD supports running several opendkim
  instances under different `rc.conf` profiles (e.g. `milteropendkim_profiles="sign
  verify"`), each with its own socket and config. This maps directly to SCOPE.md's
  `resign` / multi-tenant use cases. Worth documenting as an rc.conf pattern even if
  we do not ship a FreeBSD rc script initially.

- **Socket directory and permission creation with `install -d`.** FreeBSD uses
  `install -d -o uid -g gid -m mode dir` to atomically create the socket directory with
  correct ownership in a single command, rather than the common `mkdir -p; chown; chmod`
  three-step. Safer against TOCTOU races on tmpfs. Our `RuntimeDirectory=opendkim` + 
  `RuntimeDirectoryMode=0750` does this atomically on systemd — the same principle.

- **★ `_opendkim` account name.** OpenBSD and Debian both use an underscore-prefixed
  (`_opendkim`) or unprefixed (`opendkim`) system account. OpenBSD convention is
  underscore-prefix for all system daemons to distinguish them from login accounts
  (`_nsd`, `_smtpd`, etc.). Our Debian package uses `opendkim` without a prefix.
  FreeBSD defaults to `mailnull:mailnull`. Adopt `_opendkim` if we ever ship an
  OpenBSD port.

- **OpenBSD disables reload (`rc_reload=NO`).** OpenBSD's rc script has no `USR1`
  reload — it simply restarts. Our systemd unit implements `ExecReload=/bin/kill -USR1
  $MAINPID` which is the correct behaviour for live config reload without dropping
  connections. Do not follow OpenBSD's simplification here.

- **Privilege drop via daemon `-u` flag vs. init-system `User=`.** OpenBSD passes
  `-u _opendkim` on the command line; FreeBSD passes `-u uid:gid`. Our unit uses
  `User=opendkim` (systemd). The daemon's own `-u` flag works on all platforms and is a
  useful fallback for deployments without systemd (e.g. Docker, manual invocation). Keep
  `-u` as a documented CLI option even on systemd deployments.
