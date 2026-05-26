  Continue porting upstream OpenDKIM fixes into PhoenixDKIM, working from the
  audit file ai/upstream-develop-audit--COPY-for-TODO.md.

  ORDER — oldest to newest. Do NOT go top-to-bottom in the file (it's listed
  newest-first, which causes out-of-order cherry-pick conflicts). Instead get
  the true upstream order with:
      git log --reverse --format='%h %cI %s' 5c539587..upstream/develop
  Walk that list oldest-first. For each commit hash, act on it only if it's
  still labeled TODO or REVIEW in the audit file. Skip ADOPTED / NOT NEEDED /
  SKIPPED / DONE. (The audit's labels are the source of truth for what's left.)

  PER ITEM:
  1. Read the upstream commit (git show <hash>).
  2. Decide using the FILTER below whether to port it.
  3. If porting: adapt to our fork's divergences (CMake build, const-
     correctness, struct nametable / `algorithms` vs upstream's
     dkim_table_*, and the many removed subsystems — see fork memory). Apply
     the upstream hunk directly (git cherry-pick -n or git apply) when it's
     clean; hand-adapt when it isn't. awk/sed are allowed.
  4. Build to verify:
         cmake -S . -B /tmp/pdkim-build -DWITH_LUA=1 -DWITH_REDIS=1   (once)
         cmake --build /tmp/pdkim-build --target opendkim -j4
     (build the miltertest target too if you touched miltertest.)
  5. Commit CODE ONLY, one issue per commit. Commit-message style: subject
     starts with "Fix:" (or a plain descriptive subject for non-fixes), body
     explains why + mechanism (~72 col wrap), and ATTRIBUTES the upstream
     commit hash + issue, e.g. "Ports upstream trusteddomainproject/OpenDKIM
     commit <hash> (closes #NN)." If the fix is only inspired by (not copied
     from) upstream, say so and just acknowledge the issue. NEVER add a
     Co-Authored-By / Claude line. Author is Edmund Lodewijks. Commits are
     GPG-signed; do not bypass signing.
  6. Flip the item's label TODO/REVIEW -> ADOPTED in the audit file's working
     tree, but NEVER git add / commit ai/ — that file is ephemeral.

  FILTER (the fork is a deliberate slim, OpenSSL-only rewrite; 100% upstream
  compat is explicitly NOT a goal):
  - PORT: correctness, security, memory-safety, RFC-compliance, and crypto
    fixes in code we KEPT (libopendkim canon/sign/verify/dns/keys, core
    opendkim.c milter paths, opendkim-db.c, miltertest).
  - SKIP and mark NOT NEEDED (with a one-line reason): anything touching
    removed subsystems (LDAP, SQL, VBR, RBL, reputation, stats, ATPS, GnuTLS,
    _FFR_*, conditional sigs, QUERY_CACHE, memcache, libut), pure refactors/
    style/warning churn with no behavior change, and fixes whose code path is
    unreachable in our fork (e.g. ed25519/sha256 are mandated, both
    DKIM_FEATURE_* added unconditionally).
  - For interdependent clusters (e.g. the PR #309 keyfail/DNS-timeout set:
    43fccdb8, 6eff7cbb, 2f4a6850, 2d4e5b33, 85d2a958, 192bccb9), port the
    whole cluster as one deliberate unit, not piecemeal.

  If an item needs a judgment call (scope, divergence, reachability), pause
  and ask rather than forcing a port.

  A couple of notes on what's already in flight from this session, so the next run isn't surprised:

  - 83f6754e (miltertest SMTPREPLY) is already committed, but the earlier 6c74a8a0 (miltertest body-overflow, #66) is not — applying it now conflicts (3 small hunks in mt_milter_read).
  Going oldest-first won't undo that since 83f6754e is already in; the next run will need to resolve those conflicts by hand. It's a real crash fix worth doing.
  - The PR #309 cluster is deferred as a unit (temperror-vs-permerror correctness win, but interdependent).
  - a45be931/44af8255 are marked NOT NEEDED (unreachable: fork mandates ed25519+sha256).


# Upstream OpenDKIM `develop` — PhoenixDKIM Audit

**Branch point:** `5c539587` (2018-02-25) — merge-base of `upstream/master` and `upstream/develop`
**Total commits on develop since branch point:** 384
**Audit date:** 2026-05-26

## Verdicts

| Label | Meaning |
|---|---|
| **ADOPTED** | Already applied to PhoenixDKIM (identical or equivalent fix committed) |
| **TODO** | Relevant code; not yet ported; should be assessed for inclusion |
| **REVIEW** | Needs closer examination — touches removed deps, overlapping work, or uncertain scope |
| **NOT NEEDED** | Removed subsystem / dependency / FFR (librbl, libvbr, reputation, stats, LDAP, GnuTLS, autoconf, etc.) |
| **SKIPPED** | No actionable code change: CI, autoconf/Makefile.am, changelogs, merge-only, housekeeping |

---

## NEW — upstream restart (2026-05-22 to 2026-05-26)

Upstream went quiet after 2026-05-06 and restarted on 2026-05-22 with a large batch of
merged PRs, many of which had been waiting for years. ~200 commits over 4 days.

`4961ef96` 2026-05-25 — ADOPTED — opendkim-db: treat leading '[' as bracketed IPv6 address, not a type prefix (closes #319)
`30bc6c11` 2026-05-25 — ADOPTED — SoftwareHeader: include milter hostname when different from MTA hostname (closes #349)
`fe5b8216` 2026-05-25 — REVIEW — Embed git hash in version string for development builds (closes #350); uses configure.ac; CMake equivalent feasible but needs separate implementation
`7b5ccd7d` 2026-05-25 — REVIEW — Runtime detection of SHA1 signing availability via dkim_init() probe; we already disable SHA1 signing at build/runtime — compare approach
`28524911` 2026-05-25 — REVIEW — libopendkim: handle SHA1 unavailability gracefully in sign and verify paths; overlaps with our SHA1 stance; check if runtime probe logic differs meaningfully
`b3041247` 2026-05-25 — REVIEW — tests: fix misplaced SKIP_IF_NO_SHA1() in 7 remaining SHA1 tests; test infrastructure for SHA1-skip; review once SHA1 handling approach is settled
`5a926733` 2026-05-25 — REVIEW — tests: skip SHA1-dependent tests when SHA1 signing is unavailable; same as above
`e1729bac` 2026-05-25 — REVIEW — opendkim: print configure arguments in -V output (issue #357); useful diagnostics; CMake equivalent needed (see also 2fd7dae6)
`29bfcd2f` 2026-05-25 — DONE — Fix compiler warnings: -Wincompatible-pointer-types, -Wformat-truncation (#360); touches libopendkim/dkim-util.c, opendkim.c, opendkim-genzone.c
`2fd7dae6` 2026-05-25 — REVIEW — opendkim: print configure arguments in -v output (issue #357); depends on configure.ac string; need CMake equivalent
`d8082e5a` 2026-05-25 — ADOPTED — opendkim: fix overlapping buffer in SubDomains domain walk (#356)
`6e0e7f4e` 2026-05-25 — REVIEW — Mis-used string pointers in opendkim.c and vbr.c (#244); vbr.c NOT NEEDED; inspect if the opendkim.c portion has a real fix independent of vbr
`d5ec946f` 2026-05-25 — ADOPTED — opendkim: distinguish 'no From/Date field' from 'multiple From/Date fields' in RequiredHeaders
`79014c9f` 2026-05-26 — ADOPTED — opendkim-ar: accept AR header with no-result as valid syntax; parser robustness
`f3d0e4e1` 2026-05-25 — DONE — opendkim: add sd_notify() readiness signal for systemd Type=notify; we have systemd hardening but not sd_notify; autoconf parts SKIPPED, libsystemd detection needs CMake equivalent
`fd648015` 2026-05-25 — ADOPTED — Skip DNAME RRs in DNS answers (#353); the dkim-keys.c portion is relevant; dkim-atps.c NOT NEEDED (ATPS removed); dkim-report.c REVIEW (RFC 6651 deferred); librbl/rbl.c NOT NEEDED
`0a247d31` 2026-05-25 — ADOPTED — opendkim: use comma instead of semicolon in AR header key comment (minor formatting)
`383618b6` 2023-01-02 — REVIEW — OpenSSL 3: Restore compat with OpenSSL 1.1.1 (merged May 2026 via PR #351); our EVP3 migration supersedes; verify no specific fixes were missed
`a171c130` 2022-12-28 — REVIEW — OpenSSL 3: Update cryptographic functions (PR #351); our EVP3 migration covers this; cross-check dkim-types.h changes
`0531e372` 2022-12-21 — REVIEW — OpenSSL 3: Update message digest functions (PR #351); dkim-atps.c NOT NEEDED; remainder covered by our EVP3 migration
`1fb7199a` 2024-01-19 — TODO — Fix screen.lua.sample off-by-one error and function name (PR #195/348, merged May 2026)
`6f5c3b9c` 2023-04-20 — TODO — Fix spelling in docs/code comments (PR #180, merged May 2026); touches live code: libopendkim/dkim-mailparse.c, dkim.c, dkim.h, opendkim/config.c, opendkim-db.c, opendkim.c; also touches removed: libvbr, reputation, www (ignore those parts)
`7f07f1cc` 2026-05-25 — ADOPTED (already present) — opendkim: insert A-R and DKIM-Signature headers at index 0 (issue #24); all dkimf_insheader() calls in our fork already use index 0 — no code change needed
`a6665347` 2026-05-24 — ADOPTED — opendkim: don't add A-R header in sign-only mode when sender unresolvable (issue #130)
`abe113d5` 2026-05-24 — ADOPTED — opendkim: improve too-much-header-data log and SMTP reply (issue #143)
`de5ac8c8` 2026-05-24 — ADOPTED (already present) — opendkim: fix always-false NULL check on mctx_domain array (issue #88); our fork already uses mctx_domain[0] == '\0'
`726bcc5f` 2026-05-24 — ADOPTED — libopendkim/tests: update t-test149 for issue #45 fix (missing CRLF with l= tag)
`83f6754e` 2026-05-24 — ADOPTED — miltertest: allow MT_SMTPREPLY check after any callback, not just EOM; miltertest improvement
`73cd6e50` 2026-05-24 — ADOPTED — dkim.c: remove fixed BUFRSZ limit from SignHeaders/SkipHeaders regex buffers
`42ca523f` 2026-05-24 — ADOPTED — libopendkim: don't error on missing CRLF when l= body length tag is used
`97492417` 2026-05-24 — ADOPTED — libopendkim: set sig_signalg before feature checks in dkim_siglist_setup(); ordering fix
`0035df5d` 2026-05-24 — ADOPTED — opendkim: remove smfi_insheader() stub, require libmilter >= sendmail 8.13.0
`b63ba64e` 2026-05-24 — TODO — libopendkim/tests: fix t-test205 expected return value
`192bccb9` 2026-05-24 — ADOPTED (already present) — fork already defines DKIMF_STATUS_KEYFAIL (=3, "key retrieval timeout"), maps it in mlfi_eom dispatch + AR all-sigs condition; KEYFAIL→temperror handled via dkimf_ar_all_sigs sigerror path
`6c74a8a0` 2026-05-24 — TODO — miltertest: fix stack overflow when milter replaces body > BUFRSZ bytes; crash fix
`71210bfc` 2026-05-25 — ADOPTED (already present) — Lua 5.5 support: better seed for lua_newstate; we target 5.4; forward-compat with 5.5 is worth considering
`d8bb9e61` 2026-05-24 — TODO — libopendkim/tests: add multi-signing unit tests (t-test204, t-test205); Makefile.am parts SKIPPED, C test files TODO
`9dfe6ec3` 2024-10-07 — ADOPTED (already present) — fork's CheckSigningTable verify loop (opendkim.c:7271-7318) already sets signer field DKIMF_DB_DATA_OPTIONAL (initial + in-loop reset) and checks dkimf_db_walk()==-1 (`_walkret`)
`62bc29c9` 2023-01-10 — NOT NEEDED — feature (not a fix); upstream impl is a ~1500-line invasive rewrite threading conf into all 179 syslog sites. Our systemd Type=notify+`-f` already routes syslog to journald. Better modern approach captured in ai/modern-logging-initiative.md (future, out of audit scope).
`f63fdc18` 2026-05-24 — ADOPTED — opendkim: improve error messages for KeyTable/SafeKeys failures (#164)
`0b858692` 2025-03-14 — ADOPTED — ed25519 tests, perf test fix, dkim_free() memory leak, dkim_sig_keybits() (PR #321, merged May 2026); we have ed25519 test coverage; verify dkim_free() leak and dkim_sig_keybits() are also covered
`e0e0812a` 2026-05-24 — ADOPTED (already present) — libopendkim/util.c already includes <stdio.h> (line 21); libvbr NOT NEEDED
`adc79404` 2026-05-24 — ADOPTED — opendkim.conf.5: document IPv6 inline limitation and workaround for PeerList
`4edd0ed7` 2026-05-24 — ADOPTED (already present) — fork's contrib/systemd/opendkim.service has the full hardening block (CapabilityBoundingSet, ProtectSystem=strict, PrivateUsers, RestrictAddressFamilies, SystemCallFilter, NoExecPaths/ExecPaths + ReportAddress comment, ReadWritePaths, RuntimeDirectory) and foreground ExecStart; uses Type=notify+WatchdogSec (sd_notify), exceeding upstream's Type=simple
`b95f9b4b` 2026-05-24 — ADOPTED (already present) — fork's unit has After=network-online.target nss-lookup.target syslog.target and Wants=network-online.target
`ab00e071` 2026-05-24 — ADOPTED — libopendkim: fix assert in dkim_canon_selecthdrs when all headers are skipped
`c0c8d6f3` 2026-05-24 — ADOPTED (merge of ab81db9b) — Fix Lua odkim.del_header to use correct header index (no files listed; see also ab81db9b)
`5c1f0dd2` 2026-05-24 — ADOPTED — issue #49: distinguish NXDOMAIN from DNS error in stub resolver
`aac24740` 2026-05-24 — ADOPTED — issue #240: warn when KeyFile is set alongside KeyTable; useful config validation
`85d2a958` 2026-05-06 — ADOPTED (already present) — mlfi_eoh has DKIM_STAT_KEYFAIL case setting mctx_status=KEYFAIL+addheader and returning SMFIS_CONTINUE (postpones to mlfi_eom)
`2d4e5b33` 2026-05-06 — ADOPTED (already present) — mlfi_eom inits `sfsistat ret = SMFIS_ACCEPT`, uses `ret = dkimf_libstatus(...,"dkim_eom()",status)`, no leftover redundant ret assignment
`2f4a6850` 2026-05-06 — ADOPTED (already present) — mlfi_eoh screen-script hook uses a local `hkstat` distinct from `status`
`6eff7cbb` 2026-05-05 — ADOPTED (already present) — dkimf_libstatus sets replytxt "DKIM key retrieval timeout" (KEYFAIL) vs "...failed" (NOKEY) and picks dnserr vs nokey handling
`43fccdb8` 2026-05-05 — ADOPTED (adapted) — dkimf_libstatus error log now distinguishes KEYFAIL ("key retrieval timeout") from NOKEY; selected from DKIM_STAT directly, NOT upstream's dkimf_lookup_inttostr(status,...) which mismatches the DKIMF_STATUS-keyed table
`282fac87` 2026-05-24 — ADOPTED — issue #103: quote authserv-id when AuthservIDWithJobID is set
`c7ad899e` 2026-05-24 — ADOPTED — issue #178: relax OpenSSL version check to ignore patch letter and status; runtime version comparison improvement
`f6c4fc10` 2026-05-24 — ADOPTED — issue #181: make libunbound use /etc/resolv.conf nameservers by default
`2793d891` 2026-05-24 — ADOPTED — issue #108: fix always-false header character validity check (tautology)
`453b30db` 2024-10-29 — ADOPTED (already present) — fork's dkimf_ar_all_sigs already caches sigflag and returns "policy" for DKIM_SIGFLAG_IGNORE
`6cfb4864` 2026-05-24 — ADOPTED — issue #40: preserve user's primary group when explicit group given in UserID
`37caadbe` 2026-05-24 — NOT NEEDED — documents a limitation absent from our fork: dkim_privkey_load() (libopendkim/dkim.c:1058-1086) auto-detects key type from the loaded key and overrides dkim_signalg, so Ed25519 KeyFile/KeyTable keys are signed ed25519-sha256 even with default SignatureAlgorithm. Documenting the upstream "must set explicitly" caveat would be wrong here.
`1be8a046` 2024-03-24 — ADOPTED — issue #183: opendkim-testkey: support ed25519 key (PR #299, merged May 2026)
`49ca6b59` 2026-05-23 — ADOPTED — libopendkim, librbl: fix syntax errors in dkim_res_nslist/rbl_res_nslist; libopendkim/dkim-dns.c part is relevant; librbl/rbl.c NOT NEEDED
`cb9a4f1a` 2026-05-23 — ADOPTED — libopendkim: use first TXT record when multiple DKIM key records found; DNS parsing fix
`4d483a9c` 2026-05-23 — ADOPTED (equivalent) — fork's dkimf_config_free already replaced the hard assert(conf_refcnt==0) with a soft LOG_CRIT-and-return guard; avoids the SIGTERM crash (#22) and is safer (won't free a still-referenced config)
`ffa75521` 2026-05-23 — ADOPTED — opendkim.conf.5: improve SignHeaders documentation
`cbb22fea` 2026-05-23 — ADOPTED — opendkim: fix SafeKeys error message reporting username instead of path
`4197a6e4` 2026-05-23 — ADOPTED — opendkim.conf.5: document that parameter names are case-insensitive
`520338d2` 2026-05-23 — ADOPTED (already present) — fork's t-testdata.h already uses relative KEYFILE "testkeys" (not /tmp); CVE-2020-35766 already mitigated
`402f657c` 2026-05-23 — NOT NEEDED — assert(0) crash needs MEMCACHE/SOCKET DB type for SigningTable; fork has neither (types: FILE/REFILE/CSL/LUA/MDB/REDIS). REFILE+LUA return -1 early in dkimf_db_walk; rest handled in switch — default assert(0) unreachable
`ac6f968f` 2026-05-23 — ADOPTED — opendkim-genkey: let openssl write errors to stderr; our genkey is a CMake-generated script — apply same improvement
`2a56e223` 2026-05-23 — ADOPTED — opendkim: fix FD leak from missing endpwent() in key safety checks
`6e65b22e` 2026-05-23 — ADOPTED — librbl, libopendkim: fix struct state -> struct __res_state typo; only libopendkim/dkim-dns.c portion is relevant (librbl NOT NEEDED)
`f8a12c04` 2026-05-23 — ADOPTED — Fix doc nits in CheckSigningTable option (opendkim.8.in, opendkim.conf.sample)
`eb2bae3c` 2026-05-23 — NOT NEEDED — fix is entirely inside #ifdef QUERY_CACHE; fork removed QUERY_CACHE (mlfi_close has no such block, bug unreachable)
`eee1b73d` 2026-05-23 — ADOPTED — opendkim.c: fix leaks on OOM error paths (issue #272)
`3b9d4ce9` 2026-05-23 — ADOPTED — opendkim.c: free cfg on deprecated-setting abort in dkimf_config_reload (issue #272)
`a8ddd1bb` 2026-05-23 — ADOPTED — opendkim-db.c: fix leak in dkimf_db_mkarray_base (issue #272)
`898c5e58` 2026-05-23 — ADOPTED — opendkim.c: close conf_remardb in dkimf_config_free (issue #272)
`a0c630c9` 2026-05-23 — ADOPTED — opendkim.c: fix orphaned signreq list entries with MultipleSignatures (issue #272)
`30ec6329` 2026-05-23 — ADOPTED — opendkim.c: fix leak of lg_name in Lua global cleanup (issue #272)
`f9508f12` 2026-05-23 — ADOPTED — opendkim.conf.5.in: add dual-algorithm signing example and caveats to KeyTable docs; relevant since we adopted the 4-field KeyTable
`438e0136` 2026-05-23 — ADOPTED — opendkim.c: validate KeyTable sign algorithm field at config load
`8d6205dd` 2026-05-23 — ADOPTED — opendkim.conf.5.in: fix typos in KeyTable algorithm field docs
`613f18bb` 2026-05-23 — ADOPTED — Lua fixes for dkimf_lua_writer and lua_pop placement; miltertest.c + opendkim-lua.c
`32788118` 2026-05-23 — ADOPTED — Lua 5.5 C API compatibility (closes #265); miltertest.c + opendkim-lua.c; we target 5.4 but 5.5 forward-compat may be worthwhile
`d56050bc` 2025-12-31 — ADOPTED — issue #257: Remove obsolete config option SingleAuthResult from sample config; check if we should also drop it from our config handling

---

## OLD — develop history (2015–2026-05-06)

Commits made directly to develop before the May 2026 restart.
Listed newest-first.

`dfa3dfef` 2024-10-11 — ADOPTED — documentation place -G after -g (opendkim.8.in)
`ac1d2c65` 2024-10-11 — ADOPTED — improve documentation and fix typo (opendkim.8.in + opendkim.conf.5.in)
`745ebee7` 2024-10-10 — ADOPTED — change -C to -G to match the opposite of -g; part of CheckSigningTable CLI option series
`5dcb091b` 2024-10-06 — ADOPTED — opendkim.8.in: Update descriptions for -C and -g options (CheckSigningTable)
`78367709` 2024-10-06 — ADOPTED — opendkim: Implement -C option, just opposite of -g (CheckSigningTable CLI series)
`9f996425` 2024-10-06 — ADOPTED — opendkim: -g option overrides CheckSigningTable setting in config file
`c7d845bd` 2024-09-18 — ADOPTED — SigningTable: improve man page
`3dabd5fc` 2024-09-18 — ADOPTED — CheckSigningTable: improve man page
`3fc8cb72` 2024-09-16 — ADOPTED — CheckSigningTable: add -g arg to opendkim(8) man page
`ee40b427` 2024-09-15 — ADOPTED — CheckSigningTable: use arg -g instead of -C
`35f13b11` 2024-09-15 — ADOPTED — CheckSigningTable: make option always available (remove FFR gate)
`898f6ec9` 2024-09-15 — ADOPTED — CheckSigningTable option as -C argument
`906a8b48` 2024-09-15 — ADOPTED — CheckSigningTable: improve documentation (opendkim.conf.5.in + sample)
`cd0a7f42` 2024-09-15 — ADOPTED — conf_checksigningtable: use !=FALSE instead of ==TRUE
`552aba76` 2024-09-15 — ADOPTED — add CheckSigningTable config option; new feature: validate signing table at startup; consider for PhoenixDKIM
`e66b94d0` 2024-08-25 — ADOPTED (already present) — issue #222: Don't treat empty body as partial if "Minimum" option is set
`ec765ea0` 2024-04-22 — NOT NEEDED — same _FFR_DEFAULT_SENDER block as 514ed108; removed from fork (unreachable)
`514ed108` 2024-04-22 — NOT NEEDED — both hunks are inside #ifdef _FFR_DEFAULT_SENDER; fork removed all _FFR_ and has no conf_defsender (unreachable)
`ab81db9b` 2024-04-05 — ADOPTED — Fix Lua odkim.del_header() to actually delete the requested header number instead of the first one (see also c0c8d6f3)
`436070b3` 2024-04-02 — ADOPTED — Enforce SMFIF_ADDRCPT, SMFIF_DELRCPT, SMFIF_CHGHDRS and SMFIF_QUARANTINE if FinalPolicyScript is set
`a05fead2` 2024-03-16 — ADOPTED (already present) — Update opendkim.conf manual for KeyTable extension (4th field docs)
`6e75699c` 2024-03-23 — ADOPTED — opendkim-testkey: Support sign algorithm field in KeyTable
`2b84a15f` 2024-03-01 — ADOPTED — Extend KeyTable value field to store sign algorithm in 4th field
`e421a4d7` 2024-03-18 — NOT NEEDED — dedup refactor (use libopendkim tables vs local dkimf_canon/dkimf_sign); functionally equivalent, depends on NOT-NEEDED 7bedf536
`756a38fa` 2024-03-22 — NOT NEEDED — unit test for the DKIM_NAMETABLE iterator API which we did not adopt (see 7bedf536)
`7bedf536` 2024-03-11 — NOT NEEDED — pure API-exposure refactor (struct nametable -> public DKIM_NAMETABLE + iterator API); no behavior change, nothing in fork needs the new public API
`4bee1f73` 2024-03-01 — ADOPTED — Extend structure signreq to hold signing algorithm per request
`7c70ee7c` 2023-10-14 — ADOPTED (already present) — Delete Authentication-Results headers in reverse (PR #287/125); ordering fix for A-R header removal
`ce8a278f` 2021-12-20 — ADOPTED (equivalent) — fork's genkey.in runs genpkey -out file then verifies by extracting pubkey (openssl pkey), which fails non-zero on empty/invalid key
`72136aa9` 2021-12-20 — ADOPTED (equivalent) — fork's genkey.in has no hardcoded "openssl 1.1.1" check; it functionally runs genpkey -algorithm ed25519 and checks status+signal
`14d54524` 2021-03-16 — ADOPTED (already present) — dkim_process_set validates d= chars (line 753 "malformed \"d=\""); t-test159 present and registered
`c0f9ddb9` 2021-03-15 — ADOPTED (already present) — dkim_mail_parse_multi has `case '"'` quote toggle, `|| quoted` guard, and NULL-terminated uout/dout
`0a0a0672` 2020-10-31 — ADOPTED — documented 2-param MT_HDRDELETE (name+index) form; our mt_eom_check supports idx at gettop==4
`4dd763b6` 2020-10-13 — ADOPTED — ed25519 support in opendkim-genkey; we have our own genkey with ed25519 (8.in and .in shell script)
`3e9a43b3` 2020-06-25 — ADOPTED — genkey(8) --restricted -> --restrict (matches script's GetOptions 'r|restrict!')
`b1fca873` 2020-06-21 — ADOPTED — opendkim-genzone: logical error fix (negates subdomain match predicate); folded into the ce640c31 -s port
`fd5c3307` 2020-06-21 — ADOPTED — removed "auto-generated ... at <ctime>" comment line from genzone header for reproducible output
`a8d74158` 2020-05-01 — ADOPTED — opendkim.conf: Add paragraph breaks in PeerList (opendkim.conf.5.in)
`292a90c5` 2020-05-01 — ADOPTED — opendkim.conf: Note more caveats for IP addresses in PeerList
`4d05b437` 2020-04-26 — ADOPTED (already present) — fork uses `LUA_VERSION_NUM >= 502` throughout and 4-arg lua_dump(...,0) unconditionally (targets 5.4+, even has 505 paths)
`da809168` 2019-11-26 — ADOPTED (already present) — dkim_canon_gethashes returns DKIM_STAT_INVALID when hdc/bdc NULL (1857)
`e3c16128` 2019-11-26 — ADOPTED (equivalent) — fork's EVP3 dkim_sig_process sets sig_keybits in both branches: ed25519 `8*sig_keylen` (5465), RSA `8*rsa_keysize` (5567)
`64fddf99` 2020-02-27 — ADOPTED (already present) — A-R snprintf prepends `cctx_noleadspc ? " " : ""`
`c8ccbcee` 2020-02-06 — ADOPTED (already present) — startup syslog uses `starting%s%s%s` with noargs guard
`95e17711` 2020-01-02 — ADOPTED (already present) — sample has /run/opendkim, unbound.conf(5)-style, SMTPURI, and UnboundConfigFile removed
`c674feed` 2020-01-02 — ADOPTED (already present) — mt_eom_check snprintf guards esc/text with `== NULL ? "" : x` on both args
`0010ca71` 2019-12-31 — ADOPTED (already present) — dkimf_unbound_cb bogus path calls ub_resolve_free(result)
`66111850` 2019-12-27 — ADOPTED (already present) — mt_data asserts STATE_ENVRCPT, mt_header asserts STATE_DATA
`edc5677f` 2018-11-05 — ADOPTED (already present) — RequiredHeaders reject uses dkimf_setreply 550 "5.0.0"
`da8215ca` 2018-11-05 — ADOPTED (already present) — RequiredHeaders sets per-error msg, logs it, dkimf_setreply 550 + SMFIS_REJECT (also has d5ec946f no/multiple distinction)
`1db96511` 2018-11-03 — ADOPTED (already present) — mlfi_body already uses combined predicate: SMFIS_SKIP only when both srhead and dkimv don't need more body
`011e1b06` 2018-11-03 — ADOPTED (already present) — standard resolver already DNSSEC-aware (RES_USE_DNSSEC, res_nquery, rq_dnssec SECURE/INSECURE); key-actions/A-R dnssec/test.c all ungated from USE_UNBOUND
`327954bf` 2018-11-03 — NOT NEEDED — issue #9 leaks all in removed subsystems: librbl/rbl.c (gone); opendkim.c leak is inside `#ifdef _FFR_REPLACE_RULES` mlfi_header path; util.c dkimf_load_replist (ReplaceRules) removed
`ea171129` 2018-11-03 — ADOPTED — added [\-s] to genzone(8) synopsis (body desc already present from -s impl)
`5b292034` 2018-11-03 — ADOPTED (already present) — SyslogName option fully wired: config table, dkimf_init_syslog(name,facility), config_load, manpage, sample all present
`939d83ae` 2018-11-02 — ADOPTED — Issue #16: Remove redundant defaults; correction in MinimumKeyBits; other doc edits (opendkim.conf.5); StatisticsPolicyScript/ReplaceRules hunks omitted (removed subsystems)
`cb0691cb` 2018-11-02 — ADOPTED (already present) — Issue #8: password file critical section; our dkimf_securefile already unlocks pwdb_lock after strlcpy(myname,...) in both REALPATH and non-REALPATH branches
`17db0b56` 2018-11-02 — NOT NEEDED — pure tidying, no behavior change: removed free(copy) is in the copy==NULL branch (free(NULL) no-op, not a double-free; we keep the real free(copy) on the addrlist-malloc-fail path); rest is unused include/global, doc typo, cosmetic log string, stats.c (removed)
`a928851d` 2018-11-02 — ADOPTED (already present) — opendkim-dns.c already has ub_config_lock, with lock/unlock around ub_ctx_config and init/destroy
`fda8a318` 2018-08-31 — ADOPTED (already present) — test.c already has the `newline` flag and conditional CRLF append in dkimf_testfile
`4a773348` 2018-08-31 — ADOPTED (already present) — dkim_canon_init already calls dkim_dstring_new(dkim, BUFRSZ, 0) (unbounded) at dkim-canon.c:576; t-test158 present; t-test155 never imported (N/A)
`37c77160` 2018-05-23 — ADOPTED (equivalent) — fork already nulls the struct-member BIO (rsa->rsa_keydata) after every free in dkim_eom_sign; keybio/key in privkey_load & sig_process are locals freed on immediately-returning paths, so no dangling-member double-free exists to fix
`74bf5b08` 2018-05-19 — ADOPTED (already present) — DKIM_FEATURE_MAX already 10 (matches our highest feature, ED25519=10; no CONDITIONAL); conf manpage already says "normally"
`720cc931` 2018-05-16 — ADOPTED (already present) — dkim_sig_getalgorithm already casts dkim_code_to_name() result to (unsigned char *)
`27a26c5e` 2018-05-16 — ADOPTED (already present) — dkim_sig_getalgorithm() exists and A-R header already emits header.a=; only un-ported bits are cosmetic a= additions to two syslog diag lines
`84d985c3` 2018-05-16 — NOT NEEDED — only adds #ifdef HAVE_ED25519 / USE_GNUTLS guards; fork mandates ed25519 and is OpenSSL-only, so the absent-ed25519 path is unreachable
`35bf6c90` 2018-05-16 — ADOPTED — Add support for ED25519 signing (original implementation; in our fork via upstream master)
`41a85087` 2018-02-07 — ADOPTED (already present) — header.s in AR stamp; our dkimf_ar_all_sigs APPEND already emits header.s= (and header.a=)
`3bd41c1d` 2017-03-04 — ADOPTED (already present) — Patch #34: length checks in t-test102/138/68 already use the correct strlen() args in our fork
`ce640c31` 2015-10-07 — ADOPTED — TOOLS: genzone -s option to match subdomains (#187); ported WITH the b1fca873 logic-inversion fix folded in (matching records kept, not skipped)
`8144a97a` 2015-10-07 — ADOPTED (already present) — #190 non-printable domain/selector rejection; fork has dkim_strisprint (const-correct, isprint(*p)) + dkim_sign check, fixing upstream's isprint(p)/unused-var bugs
`a6544216` 2015-10-07 — ADOPTED (already present) — bug #226 re-fix; dkim_canon_header_string "skip all spaces before first word" loop already uses DKIM_ISLWSP (dkim-canon.c:324)
`8ba85113` 2015-10-06 — ADOPTED (already present) — "oops" fixes the broken header.b ternary syntax from feccce9a; our fork already has the correct `? "\"" : ""` form
`59594e2d` 2015-10-06 — ADOPTED (already present) — bug #233 duplicate-sig header.b constraint; dkim_get_sigsubstring already has the `strcmp(b1,b2)==0 break` guard
`feccce9a` 2015-10-06 — ADOPTED — bug #235 slash-quoting already present; ported the conf_noheaderb gating (NoHeaderB option was parsed but never applied)
`c1fa5e53` 2015-10-06 — NOT NEEDED — documents SQL DSN "filter" clause; SQL/DSN dataset section does not exist in our opendkim.8 (backend removed)
`843a9527` 2015-10-06 — NOT NEEDED — dkimf_db_nextpunct() only parses dsn: data-source connection strings (SQL/ODBX backends); function and DSN parsing removed from fork
`825b1e2e` 2015-10-06 — NOT NEEDED — SoftStart only applies to LDAP/ODBX (SQL) backends, both removed; no conf_softstart/SoftStart code in fork
`af3c67f9` 2015-10-06 — ADOPTED — odkim.internal_ip() is available everywhere now (opendkim-lua.3 doc); added to FINAL list (screen/setup already had it)
`9c777a43` 2015-10-06 — ADOPTED (already present) — Make odkim.internal_ip() available to all Lua hooks; our setup/screen/final tables already include internal_ip (stats table removed)


---

## Summary

| Verdict | Count (approx) |
|---|---|
| ADOPTED | ~18 |
| TODO | ~90 |
| REVIEW | ~15 |
| NOT NEEDED | ~35 |
| SKIPPED | ~226 |
| **Total** | **384** |

### TODO clusters worth batching

- **Memory/resource leaks (issue #272 series)**: `30ec6329`, `a0c630c9`, `898c5e58`, `a8ddd1bb`, `3b9d4ce9`, `eee1b73d` — all opendkim.c/db.c cleanup
- **Keyfail/DNS timeout handling (PR #309)**: `43fccdb8`, `6eff7cbb`, `2f4a6850`, `2d4e5b33`, `85d2a958` — mlfi_eoh/eom status confusion
- **CheckSigningTable CLI feature (2024)**: `552aba76` through `745ebee7` — new -g/-C option series; entire feature is a coherent block
- **KeyTable nametable exposure (2024)**: `7bedf536`, `4bee1f73`, `2b84a15f`, `e421a4d7` — prerequisite chain for per-key algorithm
- **Lua fixes**: `4d05b437`, `613f18bb`, `9c777a43`, `ab81db9b` — various Lua hook and odkim.* fixes
- **miltertest fixes**: `66111850`, `c674feed`, `6c74a8a0`, `83f6754e` — miltertest robustness
- **opendkim-genzone fixes**: `b1fca873`, `fd5c3307`, `ce640c31` — genzone correctness and features
