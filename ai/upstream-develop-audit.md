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

`2b76de00` 2026-05-25 — SKIPPED: housekeeping — gitignore: untrack .claude/settings.json
`39c756a7` 2026-05-25 — SKIPPED: housekeeping — gitignore: add .claude
`ffea7cf7` 2026-05-25 — SKIPPED: changelog — Update CHANGES
`474cfb40` 2026-05-25 — SKIPPED: changelog — CHANGES: update issue count to ~35, flesh out Community Requests section
`f65bb374` 2026-05-25 — SKIPPED: changelog — CHANGES: running log of develop branch changes (pre-2.11.0)
`d01b1232` 2026-05-25 — SKIPPED: merge only — Merge pull request #370 (auto-detect SignatureAlgorithm)
`6f91881f` 2026-05-25 — SKIPPED: Already implemented
`2fc12b99` 2026-05-25 — SKIPPED: merge only — Merge pull request #368 (IPv6 bracket inline)
`4961ef96` 2026-05-25 — TODO — opendkim-db: treat leading '[' as bracketed IPv6 address, not a type prefix (closes #319)
`28b10334` 2026-05-25 — SKIPPED: merge only — Merge pull request #367 (SoftwareHeader milter hostname)
`30bc6c11` 2026-05-25 — TODO — SoftwareHeader: include milter hostname when different from MTA hostname (closes #349)
`6e24c7de` 2026-05-25 — SKIPPED: merge only — Merge pull request #366 (git hash in version string)
`fe5b8216` 2026-05-25 — REVIEW — Embed git hash in version string for development builds (closes #350); uses configure.ac; CMake equivalent feasible but needs separate implementation
`4075425c` 2026-05-25 — SKIPPED: merge only — Merge pull request #365 (SHA1 platform handling)
`7b5ccd7d` 2026-05-25 — REVIEW — Runtime detection of SHA1 signing availability via dkim_init() probe; we already disable SHA1 signing at build/runtime — compare approach
`28524911` 2026-05-25 — REVIEW — libopendkim: handle SHA1 unavailability gracefully in sign and verify paths; overlaps with our SHA1 stance; check if runtime probe logic differs meaningfully
`b3041247` 2026-05-25 — REVIEW — tests: fix misplaced SKIP_IF_NO_SHA1() in 7 remaining SHA1 tests; test infrastructure for SHA1-skip; review once SHA1 handling approach is settled
`5a926733` 2026-05-25 — REVIEW — tests: skip SHA1-dependent tests when SHA1 signing is unavailable; same as above
`6ec8f118` 2026-05-25 — SKIPPED: autoconf — configure.ac: fix SHA1 signing check being silently skipped
`41ab8ef8` 2026-05-25 — SKIPPED: autoconf — configure.ac: test SHA1 signing via EVP_PKEY_sign, matching library code path
`07c86192` 2026-05-25 — SKIPPED: autoconf — Handle platform-disabled SHA1 signing gracefully (issue #364); Makefile.am + test header — the t-sha1.h test infrastructure is REVIEW
`2b5b758e` 2026-05-25 — SKIPPED: merge only — Merge pull request #362 (res_ninit header prereqs)
`6faa9946` 2026-05-23 — SKIPPED: autoconf — configure.ac: include prerequisite headers before checking for res_ninit()
`e1729bac` 2026-05-25 — REVIEW — opendkim: print configure arguments in -V output (issue #357); useful diagnostics; CMake equivalent needed (see also 2fd7dae6)
`29bfcd2f` 2026-05-25 — DONE — Fix compiler warnings: -Wincompatible-pointer-types, -Wformat-truncation (#360); touches libopendkim/dkim-util.c, opendkim.c, opendkim-genzone.c
`2fd7dae6` 2026-05-25 — REVIEW — opendkim: print configure arguments in -v output (issue #357); depends on configure.ac string; need CMake equivalent
`d8082e5a` 2026-05-25 — TODO — opendkim: fix overlapping buffer in SubDomains domain walk (#356)
`b960206a` 2026-05-25 — SKIPPED: style — opendkim/util: convert dkimf_base64_encode_file to ANSI C prototype (already ANSI in our codebase)
`6e0e7f4e` 2026-05-25 — REVIEW — Mis-used string pointers in opendkim.c and vbr.c (#244); vbr.c NOT NEEDED; inspect if the opendkim.c portion has a real fix independent of vbr
`d5ec946f` 2026-05-25 — TODO — opendkim: distinguish 'no From/Date field' from 'multiple From/Date fields' in RequiredHeaders
`6430a63d` 2026-05-25 — SKIPPED: CI — ci: add workflow_dispatch for manual CI triggering (#355)
`79014c9f` 2026-05-26 — TODO — opendkim-ar: accept AR header with no-result as valid syntax; parser robustness
`f3d0e4e1` 2026-05-25 — DONE — opendkim: add sd_notify() readiness signal for systemd Type=notify; we have systemd hardening but not sd_notify; autoconf parts SKIPPED, libsystemd detection needs CMake equivalent
`2b09998d` 2026-05-26 — NOT NEEDED: reputation subsystem removed — contrib/repute: replace defer.returnValue() with plain return for Python 3
`fd648015` 2026-05-25 — TODO — Skip DNAME RRs in DNS answers (#353); the dkim-keys.c portion is relevant; dkim-atps.c NOT NEEDED (ATPS removed); dkim-report.c REVIEW (RFC 6651 deferred); librbl/rbl.c NOT NEEDED
`0a247d31` 2026-05-25 — TODO — opendkim: use comma instead of semicolon in AR header key comment (minor formatting)
`52971c40` 2026-05-25 — SKIPPED: merge only — Merge pull request #135 (genkey ed25519 OpenSSL 3); content commit has older date — see REVIEW note on PR #351 OpenSSL 3 series
`cba18774` 2026-05-25 — SKIPPED: merge only — Merge pull request #351 (OpenSSL 3 rebase)
`383618b6` 2023-01-02 — REVIEW — OpenSSL 3: Restore compat with OpenSSL 1.1.1 (merged May 2026 via PR #351); our EVP3 migration supersedes; verify no specific fixes were missed
`a171c130` 2022-12-28 — REVIEW — OpenSSL 3: Update cryptographic functions (PR #351); our EVP3 migration covers this; cross-check dkim-types.h changes
`0531e372` 2022-12-21 — REVIEW — OpenSSL 3: Update message digest functions (PR #351); dkim-atps.c NOT NEEDED; remainder covered by our EVP3 migration
`ee829e5e` 2026-05-25 — SKIPPED: merge only — Merge pull request #125 (replace-headers); see 7c70ee7c
`56e95bb6` 2026-05-25 — SKIPPED: merge only — Merge pull request #317 (OpenSSL 1.1 configure fix); SKIPPED: autoconf
`f6a44a27` 2026-05-25 — SKIPPED: merge only — Merge pull request #346 (insheader index)
`c9ba3aae` 2026-05-25 — SKIPPED: merge only — Merge pull request #347 (spelling fixes); see 6f5c3b9c
`8725df40` 2026-05-25 — SKIPPED: merge only — Merge pull request #348 (screen.lua.sample fix); see 1fb7199a
`01bbf38c` 2026-05-25 — SKIPPED: merge only — Merge pull request #192 (SASL/LDAP pkgconfig); NOT NEEDED: LDAP removed
`9382be20` 2026-05-25 — SKIPPED: merge only — Merge pull request #171 (configure.ac C standard); SKIPPED: autoconf
`e4c7a986` 2026-05-25 — SKIPPED: merge only — Merge pull request #104 (miltertest hdrdelete doc); see 0a0a0672
`1fb7199a` 2024-01-19 — TODO — Fix screen.lua.sample off-by-one error and function name (PR #195/348, merged May 2026)
`6f5c3b9c` 2023-04-20 — TODO — Fix spelling in docs/code comments (PR #180, merged May 2026); touches live code: libopendkim/dkim-mailparse.c, dkim.c, dkim.h, opendkim/config.c, opendkim-db.c, opendkim.c; also touches removed: libvbr, reputation, www (ignore those parts)
`1951b65b` 2026-05-25 — SKIPPED: merge only — Merge pull request #214 (incompatible-pointer-types); see 29bfcd2f
`d1b5a38d` 2026-05-25 — SKIPPED: merge only — Merge pull request #345 (sign-only AR header)
`7f07f1cc` 2026-05-25 — TODO — opendkim: insert A-R and DKIM-Signature headers at index 0 (issue #24); header insertion order fix
`9d9d276a` 2026-05-24 — SKIPPED: merge only — Merge pull request #291 (zdecode strlcpy)
`a6665347` 2026-05-24 — ADOPTED — opendkim: don't add A-R header in sign-only mode when sender unresolvable (issue #130)
`04b8c99d` 2026-05-24 — SKIPPED: merge only — Merge pull request #344 (too-much-header-data)
`e0d7e146` 2026-05-24 — SKIPPED: merge only — Merge pull request #343 (mctx-domain null check)
`abe113d5` 2026-05-24 — ADOPTED — opendkim: improve too-much-header-data log and SMTP reply (issue #143)
`de5ac8c8` 2026-05-24 — TODO — opendkim: fix always-false NULL check on mctx_domain array (issue #88)
`fb2ac9f3` 2026-05-24 — SKIPPED: merge only — Merge pull request #342 (smtpreply any callback)
`92f5c669` 2026-05-24 — SKIPPED: merge only — Merge pull request #341 (signhdrs length limit)
`d9362138` 2026-05-24 — SKIPPED: merge only — Merge pull request #340 (miltertest replbody overflow)
`8ba09156` 2026-05-24 — SKIPPED: merge only — Merge pull request #339 (l-tag CRLF)
`726bcc5f` 2026-05-24 — ADOPTED — libopendkim/tests: update t-test149 for issue #45 fix (missing CRLF with l= tag)
`83f6754e` 2026-05-24 — TODO — miltertest: allow MT_SMTPREPLY check after any callback, not just EOM; miltertest improvement
`223a931b` 2026-05-24 — SKIPPED: merge only — Merge pull request #328 (Lua 5.5 newstate seed)
`6ce67257` 2026-05-24 — SKIPPED: merge only — Merge pull request #327 (configure respect LUA env vars)
`8be3c667` 2026-05-24 — SKIPPED: merge only — Merge pull request #338 (update HowToRelease)
`73cd6e50` 2026-05-24 — ADOPTED — dkim.c: remove fixed BUFRSZ limit from SignHeaders/SkipHeaders regex buffers
`42ca523f` 2026-05-24 — ADOPTED — libopendkim: don't error on missing CRLF when l= body length tag is used
`5bd24401` 2026-05-24 — SKIPPED: merge only — Merge pull request #336 (milter explicit path)
`ee316a24` 2026-05-24 — SKIPPED: project process — HowToRelease: modernize for GitHub
`d271e9ff` 2026-05-24 — SKIPPED: merge only — Merge pull request #335 (install libxml2 fix)
`259b64ab` 2026-05-24 — SKIPPED: autoconf — configure.ac: trust explicit --with-milter path without link test
`eb869dce` 2026-05-24 — SKIPPED: docs — INSTALL: remove reference to unimplemented --with-libxml2 option
`0de811f9` 2026-05-24 — SKIPPED: merge only — Merge pull request #334 (sig signalg early assign)
`3851af3d` 2026-05-24 — SKIPPED: merge only — Merge pull request #333 (smfi_insheader stub)
`44af8255` 2026-05-24 — TODO — opendkim: fix missing dfc in dkimf_ar_all_sigs() warning log
`a45be931` 2026-05-24 — TODO — libopendkim,opendkim: add DKIM_SIGERROR_UNSUPPORTED_A and warn when skipping unsupported algorithm; useful diagnostic
`97492417` 2026-05-24 — TODO — libopendkim: set sig_signalg before feature checks in dkim_siglist_setup(); ordering fix
`0035df5d` 2026-05-24 — ADOPTED — opendkim: remove smfi_insheader() stub, require libmilter >= sendmail 8.13.0
`ecf7d404` 2026-05-24 — SKIPPED: merge only — Merge pull request #332 (add Linux CI)
`70bc0459` 2026-05-24 — SKIPPED: CI — ci: add GitHub Actions workflow for Linux build and test
`fc78c006` 2026-05-24 — SKIPPED: merge only — Merge pull request #330 (multisign tests)
`b63ba64e` 2026-05-24 — TODO — libopendkim/tests: fix t-test205 expected return value
`7f5ea053` 2026-05-24 — SKIPPED: merge only — Merge pull request #329 (fix dkimf-status-keyfail)
`192bccb9` 2026-05-24 — TODO — opendkim: add missing DKIMF_STATUS_KEYFAIL define and handle it
`6c74a8a0` 2026-05-24 — TODO — miltertest: fix stack overflow when milter replaces body > BUFRSZ bytes; crash fix
`71210bcf` 2026-05-25 — REVIEW — Lua 5.5 support: better seed for lua_newstate; we target 5.4; forward-compat with 5.5 is worth considering
`ab80ec5e` 2026-05-25 — SKIPPED: autoconf — configure.ac: respect LUA_CFLAGS and LUA_LIBS variables
`f9ad07a5` 2026-05-24 — SKIPPED: merge only — Merge pull request #326 (multisign tests)
`d8bb9e61` 2026-05-24 — TODO — libopendkim/tests: add multi-signing unit tests (t-test204, t-test205); Makefile.am parts SKIPPED, C test files TODO
`c119d379` 2026-05-24 — SKIPPED: merge only — Merge pull request #325 (signingtable consistency)
`9dfe6ec3` 2024-10-07 — TODO — Fix issue 229: fix db handling on verification of SigningTable in dkimf_config_load (PR #325, merged May 2026)
`c9c4904b` 2024-12-23 — SKIPPED: autoconf — opendkim/tests/t-sign-rs-tables-bad.conf: change type of signing table (test config only)
`ab367406` 2026-05-24 — SKIPPED: merge only — Merge pull request #323 (stdout logging)
`62bc29c9` 2023-01-10 — TODO — Add opendkim -O option and StdoutLog config parameter for use in Docker/containers (PR #153, merged May 2026)
`ef622e74` 2026-05-24 — SKIPPED: merge only — Merge pull request #316 (systemd service improvements)
`aa7c445e` 2026-05-24 — SKIPPED: merge only — Merge pull request #322 (keytable error messages)
`f63fdc18` 2026-05-24 — TODO — opendkim: improve error messages for KeyTable/SafeKeys failures (#164)
`10b0d1fe` 2026-05-24 — SKIPPED: merge only — Merge pull request #320 (include stdio.h)
`863e1e3a` 2026-05-24 — SKIPPED: merge only — Merge pull request #321 (ed25519 tests)
`0b858692` 2025-03-14 — ADOPTED — ed25519 tests, perf test fix, dkim_free() memory leak, dkim_sig_keybits() (PR #321, merged May 2026); we have ed25519 test coverage; verify dkim_free() leak and dkim_sig_keybits() are also covered
`e0e0812a` 2026-05-24 — TODO — libopendkim/util.c,libvbr/vbr.c: include stdio.h; only the libopendkim/util.c part is relevant (libvbr NOT NEEDED)
`76015434` 2026-05-24 — SKIPPED: merge only — Merge pull request #318 (peerlist IPv6 docs)
`adc79404` 2026-05-24 — TODO — opendkim.conf.5: document IPv6 inline limitation and workaround for PeerList
`357c6268` 2026-05-24 — SKIPPED: autoconf — configure.ac: fix libssl detection for OpenSSL 1.1.0+
`4edd0ed7` 2026-05-24 — REVIEW — contrib/systemd: Type=simple, network-online.target, hardening options; we already committed systemd hardening — verify our version has all of these
`a882b9fd` 2026-05-24 — SKIPPED: merge only — Merge pull request #315 (network-online.target)
`b95f9b4b` 2026-05-24 — REVIEW — contrib/systemd: use network-online.target for reliable startup; check our systemd unit includes After=network-online.target
`03a7c4cb` 2026-05-24 — SKIPPED: merge only — Merge pull request #314 (ldapi URI)
`bd3418fe` 2026-05-24 — NOT NEEDED: LDAP removed — opendkim-db: fix ldapi:// URI reconstruction dropping socket path
`be678bcd` 2026-05-24 — SKIPPED: merge only — Merge pull request #313 (selecthdrs nptrs zero)
`ab00e071` 2026-05-24 — ADOPTED — libopendkim: fix assert in dkim_canon_selecthdrs when all headers are skipped
`c0c8d6f3` 2026-05-24 — TODO — Fix Lua odkim.del_header to use correct header index (no files listed; see also ab81db9b)
`41221efc` 2026-05-24 — SKIPPED: merge only — Merge pull request #312 (NXDOMAIN handling)
`5c1f0dd2` 2026-05-24 — ADOPTED — issue #49: distinguish NXDOMAIN from DNS error in stub resolver
`7e39da76` 2026-05-24 — SKIPPED: merge only — Merge pull request #311 (remove ldns flag)
`93330233` 2026-05-24 — SKIPPED: autoconf — issue #169: remove obsolete --with-ldns configure flag
`2ccf6e5b` 2026-05-24 — SKIPPED: merge only — Merge pull request #310 (keytable keyfile warning)
`aac24740` 2026-05-24 — TODO — issue #240: warn when KeyFile is set alongside KeyTable; useful config validation
`d9995e4b` 2026-05-24 — SKIPPED: merge only — Merge pull request #309 (keyfail handling)
`85d2a958` 2026-05-06 — TODO — opendkim: mlfi_eoh: postpone handling of key retrieval timeout case (PR #309, merged May 2026)
`2d4e5b33` 2026-05-06 — TODO — opendkim: mlfi_eom: fix confusion between ret and status (PR #309)
`2f4a6850` 2026-05-06 — TODO — opendkim.c: unbreak results of dkimf_msr_eoh()/dkim_eoh() via Lua script in mlfi_eoh() (PR #309)
`6eff7cbb` 2026-05-05 — TODO — opendkim: distinguish reply text between no key and DNS timeout (PR #309)
`43fccdb8` 2026-05-05 — TODO — opendkim: distinguish error log between no key and DNS timeout (PR #309)
`076eb9ed` 2026-05-24 — SKIPPED: merge only — Merge pull request #308 (authservid quoting)
`282fac87` 2026-05-24 — ADOPTED — issue #103: quote authserv-id when AuthservIDWithJobID is set
`26305116` 2026-05-24 — SKIPPED: merge only — Merge pull request #307 (OpenSSL version check)
`c7ad899e` 2026-05-24 — TODO — issue #178: relax OpenSSL version check to ignore patch letter and status; runtime version comparison improvement
`d43adbb0` 2026-05-24 — SKIPPED: merge only — Merge pull request #306 (relax autoconf version)
`c85b1183` 2026-05-24 — SKIPPED: merge only — Merge pull request #304 (fix options docs)
`e0d1beec` 2026-05-22 — SKIPPED: autoconf — configure.ac: Relax configure version to >= 2.69
`3d2cc8f9` 2026-05-24 — SKIPPED: merge only — Merge pull request #305 (unbound resolv.conf)
`f6c4fc10` 2026-05-24 — ADOPTED — issue #181: make libunbound use /etc/resolv.conf nameservers by default
`48e091d0` 2026-05-24 — SKIPPED: docs — issue #179: fix incorrect "ordered" label in dkim_options.html (HTML API doc)
`c13c6d8f` 2026-05-24 — SKIPPED: merge only — Merge pull request #303 (header char check)
`2793d891` 2026-05-24 — ADOPTED — issue #108: fix always-false header character validity check (tautology)
`4103f01c` 2026-05-24 — SKIPPED: merge only — Merge pull request #302 (policy for ignored sigs)
`453b30db` 2024-10-29 — TODO — opendkim: use "policy" for dkim result of ignored sig, instead of "fail" (PR #302, merged May 2026)
`bdca4149` 2026-05-24 — SKIPPED: merge only — Merge pull request #301 (supplemental groups)
`6cfb4864` 2026-05-24 — ADOPTED — issue #40: preserve user's primary group when explicit group given in UserID
`31443cc3` 2026-05-24 — SKIPPED: merge only — Merge pull request #300 (SignatureAlgorithm docs)
`37caadbe` 2026-05-24 — TODO — issue #107: document that SignatureAlgorithm must be set for Ed25519 keys (opendkim.conf.5.in); our manpages need this note too
`4b87afeb` 2026-05-24 — SKIPPED: merge only — Merge pull request #299 (testkey ed25519)
`1be8a046` 2024-03-24 — ADOPTED — issue #183: opendkim-testkey: support ed25519 key (PR #299, merged May 2026)
`23a92ae6` 2026-05-23 — SKIPPED: merge only — Merge pull request #298 (fix res-setservers syntax)
`49ca6b59` 2026-05-23 — TODO — libopendkim, librbl: fix syntax errors in dkim_res_nslist/rbl_res_nslist; libopendkim/dkim-dns.c part is relevant; librbl/rbl.c NOT NEEDED
`50de8f6b` 2026-05-23 — SKIPPED: autoconf — Revert "Merge pull request #296" (parallel tests — reverted immediately)
`d78ac2ad` 2026-05-23 — SKIPPED: merge only — Merge pull request #296 (fix parallel tests — reverted)
`0693e5ea` 2026-05-23 — SKIPPED: autoconf — libopendkim/tests: fix make -j check failures (Makefile.am only)
`34945386` 2026-05-23 — SKIPPED: merge only — Merge pull request #295 (multiple DKIM keys)
`3c6b2e70` 2026-05-23 — SKIPPED: merge only — Merge pull request #293 (duplicate comment)
`cb9a4f1a` 2026-05-23 — TODO — libopendkim: use first TXT record when multiple DKIM key records found; DNS parsing fix
`c4b3c20d` 2026-05-23 — SKIPPED: merge only — Merge pull request #294 (config refcnt assert)
`4d483a9c` 2026-05-23 — TODO — opendkim: remove assert on conf_refcnt in dkimf_config_free()
`0e22040d` 2026-05-23 — SKIPPED: comment — libopendkim: remove duplicate /* opening a block comment
`23bec1a5` 2026-05-23 — SKIPPED: merge only — Merge pull request #292 (signheaders docs)
`ffa75521` 2026-05-23 — TODO — opendkim.conf.5: improve SignHeaders documentation
`ceb74d2e` 2026-05-23 — NOT NEEDED: _FFR_DIFFHEADERS removed (depends on tre) — libopendkim: fix strlcpy destination size in dkim_diffheaders()
`3350e6b3` 2026-05-23 — SKIPPED: merge only — Merge pull request #290 (SafeKeys error message)
`cbb22fea` 2026-05-23 — TODO — opendkim: fix SafeKeys error message reporting username instead of path
`9105eec1` 2026-05-23 — SKIPPED: merge only — Merge pull request #289 (config case-insensitive docs)
`4197a6e4` 2026-05-23 — TODO — opendkim.conf.5: document that parameter names are case-insensitive
`15154e15` 2026-05-23 — SKIPPED: merge only — Merge pull request #258 (remove SingleAuthResult)
`7145affc` 2026-05-23 — SKIPPED: merge only — Merge pull request #287 (authres deletion); see 7c70ee7c below for content
`61a8e18b` 2026-05-23 — SKIPPED: merge only — Merge pull request #288 (CVE-2020-35766 testkeys)
`520338d2` 2026-05-23 — TODO — tests: use ./testkeys instead of /tmp/testkeys (CVE-2020-35766 mitigation in test harness)
`e67c33e1` 2026-05-23 — SKIPPED: merge — Merge commit 'refs/glts/pr189' into fix-authres-deletion
`e8b539c0` 2026-05-23 — SKIPPED: merge only — Merge pull request #286 (fix db-walk-memcache)
`402f657c` 2026-05-23 — REVIEW — opendkim-db: fix assert(0) crash when using memcache for SigningTable; memcache backend unclear status in our fork
`6cc27600` 2026-05-23 — SKIPPED: merge only — Merge pull request #285 (genkey stderr)
`ac6f968f` 2026-05-23 — TODO — opendkim-genkey: let openssl write errors to stderr; our genkey is a CMake-generated script — apply same improvement
`7818f294` 2026-05-23 — SKIPPED: merge only — Merge pull request #284 (fd leak endpwent)
`2a56e223` 2026-05-23 — TODO — opendkim: fix FD leak from missing endpwent() in key safety checks
`861bde46` 2026-05-23 — SKIPPED: merge only — Merge pull request #283 (res-state type fix)
`6e65b22e` 2026-05-23 — TODO — librbl, libopendkim: fix struct state -> struct __res_state typo; only libopendkim/dkim-dns.c portion is relevant (librbl NOT NEEDED)
`3fd5e81f` 2026-05-23 — SKIPPED: merge only — Merge pull request #282 (GnuTLS ed25519 verify)
`f323c1e5` 2026-05-23 — NOT NEEDED: GnuTLS removed — libopendkim: verify ed25519-sha256 signatures with GnuTLS
`32798989` 2026-05-23 — SKIPPED: merge only — Merge pull request #281 (CheckSigningTable startup)
`f8a12c04` 2026-05-23 — TODO — Fix doc nits in CheckSigningTable option (opendkim.8.in, opendkim.conf.sample)
`e848eeac` 2026-05-23 — SKIPPED: merge — Merge commit 'refs/razvan/pr228' into fix-check-signing-table-startup
`56ed5138` 2026-05-23 — SKIPPED: merge only — Merge pull request #223 (Minimum empty body)
`93511eb4` 2026-05-23 — SKIPPED: merge only — Merge pull request #280 (mlfi_close UAF)
`eb2bae3c` 2026-05-23 — REVIEW — opendkim.c: fix use-after-free in mlfi_close under QUERY_CACHE (issue #272); determine if we have QUERY_CACHE feature
`ceceb4e7` 2026-05-23 — SKIPPED: merge only — Merge pull request #279 (OOM leaks)
`eee1b73d` 2026-05-23 — TODO — opendkim.c: fix leaks on OOM error paths (issue #272)
`ad0c067f` 2026-05-23 — SKIPPED: merge only — Merge pull request #278 (config reload cfg leak)
`3b9d4ce9` 2026-05-23 — TODO — opendkim.c: free cfg on deprecated-setting abort in dkimf_config_reload (issue #272)
`78956a3f` 2026-05-23 — SKIPPED: merge only — Merge pull request #277 (GnuTLS hash leak)
`fdc43583` 2026-05-23 — NOT NEEDED: GnuTLS removed — opendkim.c: deinit GnuTLS hash context in dkimf_cleanup (issue #272)
`9c7ed39e` 2026-05-23 — SKIPPED: merge only — Merge pull request #276 (mkarray-base leak)
`a8ddd1bb` 2026-05-23 — TODO — opendkim-db.c: fix leak in dkimf_db_mkarray_base (issue #272)
`730a28b3` 2026-05-23 — SKIPPED: merge only — Merge pull request #275 (remardb leak)
`898c5e58` 2026-05-23 — TODO — opendkim.c: close conf_remardb in dkimf_config_free (issue #272)
`9c27b592` 2026-05-23 — SKIPPED: merge only — Merge pull request #274 (signreq list tail)
`a0c630c9` 2026-05-23 — TODO — opendkim.c: fix orphaned signreq list entries with MultipleSignatures (issue #272)
`64ed461a` 2026-05-23 — SKIPPED: merge only — Merge pull request #273 (Lua global name leak)
`30ec6329` 2026-05-23 — TODO — opendkim.c: fix leak of lg_name in Lua global cleanup (issue #272)
`d729a3cf` 2026-05-23 — SKIPPED: merge only — Merge pull request #270 (keytable multisig docs)
`f9508f12` 2026-05-23 — TODO — opendkim.conf.5.in: add dual-algorithm signing example and caveats to KeyTable docs; relevant since we adopted the 4-field KeyTable
`5174b2f4` 2026-05-23 — SKIPPED: merge only — Merge pull request #269 (per-key sign algorithm)
`438e0136` 2026-05-23 — ADOPTED — opendkim.c: validate KeyTable sign algorithm field at config load
`8d6205dd` 2026-05-23 — ADOPTED — opendkim.conf.5.in: fix typos in KeyTable algorithm field docs
`2713e770` 2026-05-23 — SKIPPED: merge — Merge commit 'refs/futatuki/pr202' into issue-6-per-key-sign-algorithm
`c4248199` 2026-05-23 — SKIPPED: merge only — Merge pull request #207 (expose nametables); see 7bedf536 in OLD section
`ed1c2794` 2026-05-23 — SKIPPED: merge only — Merge pull request #268 (Lua 5.5 fixups)
`613f18bb` 2026-05-23 — TODO — Lua fixes for dkimf_lua_writer and lua_pop placement; miltertest.c + opendkim-lua.c
`517db53a` 2026-05-23 — SKIPPED: merge only — Merge pull request #211 (lua_fixes)
`a3788948` 2026-05-23 — SKIPPED: merge only — Merge pull request #267 (Lua 5.5 compat)
`32788118` 2026-05-23 — REVIEW — Lua 5.5 C API compatibility (closes #265); miltertest.c + opendkim-lua.c; we target 5.4 but 5.5 forward-compat may be worthwhile
`054b9838` 2026-05-23 — SKIPPED: merge only — Merge pull request #266 (Lua detection)
`0a3793d0` 2026-05-23 — SKIPPED: autoconf — configure.ac: Improve Lua detection (closes #111); CMake handles this
`d56050bc` 2025-12-31 — REVIEW — issue #257: Remove obsolete config option SingleAuthResult from sample config; check if we should also drop it from our config handling

---

## OLD — develop history (2015–2026-05-06)

Commits made directly to develop before the May 2026 restart.
Listed newest-first.

`5236d478` 2024-10-16 — SKIPPED: cosmetic — reorder parameter list for brevity (opendkim.c)
`dfa3dfef` 2024-10-11 — TODO — documentation place -G after -g (opendkim.8.in)
`ac1d2c65` 2024-10-11 — TODO — improve documentation and fix typo (opendkim.8.in + opendkim.conf.5.in)
`745ebee7` 2024-10-10 — TODO — change -C to -G to match the opposite of -g; part of CheckSigningTable CLI option series
`c2ec0d8b` 2024-10-10 — SKIPPED: merge only — Merge pull request #2 from futatuki/check-signingtable-only
`5dcb091b` 2024-10-06 — TODO — opendkim.8.in: Update descriptions for -C and -g options (CheckSigningTable)
`78367709` 2024-10-06 — TODO — opendkim: Implement -C option, just opposite of -g (CheckSigningTable CLI series)
`9f996425` 2024-10-06 — TODO — opendkim: -g option overrides CheckSigningTable setting in config file
`6bea2fa8` 2024-09-22 — SKIPPED: cosmetic — remove extra line (opendkim.c)
`c7d845bd` 2024-09-18 — TODO — SigningTable: improve man page
`3dabd5fc` 2024-09-18 — TODO — CheckSigningTable: improve man page
`3fc8cb72` 2024-09-16 — TODO — CheckSigningTable: add -g arg to opendkim(8) man page
`ee40b427` 2024-09-15 — TODO — CheckSigningTable: use arg -g instead of -C
`35f13b11` 2024-09-15 — TODO — CheckSigningTable: make option always available (remove FFR gate)
`898f6ec9` 2024-09-15 — TODO — CheckSigningTable option as -C argument
`906a8b48` 2024-09-15 — TODO — CheckSigningTable: improve documentation (opendkim.conf.5.in + sample)
`cd0a7f42` 2024-09-15 — TODO — conf_checksigningtable: use !=FALSE instead of ==TRUE
`552aba76` 2024-09-15 — TODO — add CheckSigningTable config option; new feature: validate signing table at startup; consider for PhoenixDKIM
`8f83e5f3` 2024-08-25 — SKIPPED: changelog — Record fix of issue #222 (RELEASE_NOTES)
`e66b94d0` 2024-08-25 — TODO — issue #222: Don't treat empty body as partial if "Minimum" option is set
`ec765ea0` 2024-04-22 — TODO — opendkim.c: replace a strlcpy() with dkimf_dstring_copy()
`514ed108` 2024-04-22 — TODO — opendkim.c: add two missing dkimf_dstring_get() calls
`ab81db9b` 2024-04-05 — TODO — Fix Lua odkim.del_header() to actually delete the requested header number instead of the first one (see also c0c8d6f3)
`436070b3` 2024-04-02 — TODO — Enforce SMFIF_ADDRCPT, SMFIF_DELRCPT, SMFIF_CHGHDRS and SMFIF_QUARANTINE if FinalPolicyScript is set
`a05fead2` 2024-03-16 — TODO — Update opendkim.conf manual for KeyTable extension (4th field docs)
`6e75699c` 2024-03-23 — ADOPTED — opendkim-testkey: Support sign algorithm field in KeyTable
`2b84a15f` 2024-03-01 — ADOPTED — Extend KeyTable value field to store sign algorithm in 4th field
`e421a4d7` 2024-03-18 — TODO — opendkim.c: Use dkim_table_canonicalizations and dkim_table_algorithms from libopendkim instead of local dkimf_canon/dkimf_sign; depends on exposed nametables (see 7bedf536)
`2471d3e2` 2024-03-21 — SKIPPED: docs — libopendkim: Updating API documents (HTML files)
`756a38fa` 2024-03-22 — TODO — libopendkim: Add test for DKIM_NAMETABLE routines (t-test160); Makefile.am SKIPPED, test C file TODO
`7bedf536` 2024-03-11 — TODO — libopendkim: Expose nametables by adding dkim_table_ prefix; API addition needed for e421a4d7; Makefile.am parts SKIPPED
`4bee1f73` 2024-03-01 — ADOPTED — Extend structure signreq to hold signing algorithm per request
`12b14033` 2023-12-02 — SKIPPED: autoconf — configure.ac: update Cyrus SASL's pkgconfig name (SASL only needed for LDAP, removed)
`f203e0a0` 2023-12-02 — SKIPPED: autoconf + NOT NEEDED: LDAP removed — configure.ac: update OpenLDAP's pkgconfig name
`7c70ee7c` 2023-10-14 — TODO — Delete Authentication-Results headers in reverse (PR #287/125); ordering fix for A-R header removal
`1f551737` 2023-02-23 — NOT NEEDED: libvbr removed — libvbr/vbr.c: modernize vbr_strlcpy() signature
`2d6db022` 2023-02-23 — SKIPPED: autoconf — configure.ac: update main() signatures to conform to the standard
`551ab382` 2022-12-29 — SKIPPED: merge only — Merge pull request #163 (autoconf 2.71 update)
`2967a105` 2022-12-29 — SKIPPED: autoconf — Update autoconf for 2.71
`ce8a278f` 2021-12-20 — TODO — Verify genpkey output since very old openssl without genpkey returns 0; genkey robustness
`72136aa9` 2021-12-20 — TODO — Use functional test for OpenSSL ed25519 support rather than hardcoded version check (genkey)
`25359fb4` 2021-04-13 — NOT NEEDED: _FFR_REPLACE_RULES removed — Add missing ReplaceHeaders definition (opendkim-config.h)
`14d54524` 2021-03-16 — TODO — LIBOPENDKIM: Confirm that the value of "d=" is properly formed; validation + test t-test159
`c0f9ddb9` 2021-03-15 — TODO — LIBOPENDKIM: Fix parsing bug in dkim_mail_parse_multi() where quotes were not properly handled
`0a0a0672` 2020-10-31 — TODO — miltertest: Correct MT_HDRDELETE doc in man page (miltertest.8)
`835834ea` 2020-10-29 — SKIPPED: merge only — Merge pull request #101 (opendkim-genkey ed25519 support)
`266fcb90` 2020-10-16 — SKIPPED: merge only — Merge pull request #55 (fix-miltertest-data)
`cb5f3bc5` 2020-10-16 — SKIPPED: merge only — Merge pull request #34 (fix-unknown-operator-configure)
`9e8f1648` 2020-10-16 — SKIPPED: merge only — Merge branch 'develop' into fix-unknown-operator-configure
`feb9fccd` 2020-10-16 — SKIPPED: merge only — Merge pull request #57 (fix-leak-unbound-callback); see 0010ca71
`e322a84a` 2020-10-16 — SKIPPED: merge only — Merge pull request #58 (fix-miltertest-eom-check); see c674feed
`c83b2cad` 2020-10-16 — SKIPPED: merge only — Merge pull request #60 (minor-doc-fixes)
`85178c45` 2020-10-16 — SKIPPED: merge only — Merge pull request #65 (suppress-brackets-syslog); see c8ccbcee
`31283c31` 2020-10-16 — SKIPPED: merge only — Merge pull request #81 (opendkim-genzone logical error fix); see b1fca873
`4dd763b6` 2020-10-13 — ADOPTED — ed25519 support in opendkim-genkey; we have our own genkey with ed25519 (8.in and .in shell script)
`d96d09fe` 2020-10-11 — SKIPPED: merge only — Merge branch 'develop' into opendkim-genzone-logical-error-fix
`d687a3f4` 2020-08-21 — SKIPPED: merge only — Merge pull request #63 (lua pkgconfig check); SKIPPED: autoconf
`33771219` 2020-08-21 — SKIPPED: merge only — Merge pull request #74 (libvbr __P() macro); NOT NEEDED: libvbr removed
`a6c3ea0b` 2020-08-21 — SKIPPED: merge only — Merge pull request #67 (add-space-results-header); see 64fddf99
`6a0075f7` 2020-08-21 — SKIPPED: merge only — Merge pull request #76 (LDAP schema update); NOT NEEDED: LDAP removed
`74c191e6` 2020-08-21 — SKIPPED: merge only — Merge pull request #78 (opendkim-genzone nodate); see fd5c3307
`854f847a` 2020-07-14 — SKIPPED: merge only — Merge pull request #92 (genkey-man-restrict typo); see 3e9a43b3
`3e9a43b3` 2020-06-25 — TODO — opendkim-genkey(8): Fixed typo "restricted" to "restrict"
`b1fca873` 2020-06-21 — TODO — opendkim-genzone: logical error fix
`fd5c3307` 2020-06-21 — TODO — opendkim-genzone: make output comparable, avoid variable timestamp data
`bbf9c6cb` 2020-01-26 — SKIPPED: autoconf — configure.ac: check for "lua" with pkg-config in addition to "lua5.1"
`c133f2d4` 2020-06-18 — NOT NEEDED: LDAP removed — make the ldap class STRUCTURAL and DKIMDomain subsearchable (contrib/ldap/)
`a3fbe331` 2020-06-10 — NOT NEEDED: libvbr removed — Define __P() macro in libvbr (libvbr/vbr.h)
`6e91df3b` 2020-06-04 — SKIPPED: merge only — Merge pull request #72 (opendkim.conf ip caveats); see 292a90c5
`c370752c` 2020-06-04 — SKIPPED: merge only — Merge pull request #68 (fix_keybits_ed25519); see e3c16128
`a8d74158` 2020-05-01 — TODO — opendkim.conf: Add paragraph breaks in PeerList (opendkim.conf.5.in)
`292a90c5` 2020-05-01 — TODO — opendkim.conf: Note more caveats for IP addresses in PeerList
`4bcb4ffc` 2020-06-04 — SKIPPED: merge only — Merge pull request #69 (fix_dkimcanon_assert); see da809168
`4c360b10` 2020-06-04 — SKIPPED: merge only — Merge pull request #70 (lua-5.3); see 4d05b437
`4d05b437` 2020-04-26 — TODO — Minor updates for Lua 5.3; miltertest.c + opendkim-lua.c; we target 5.4 — verify these 5.3 fixes are already covered by our 5.4 work or still needed
`da809168` 2019-11-26 — TODO — dkim-canon: fix missing check before assert in dkim_sig_gethashes
`e3c16128` 2019-11-26 — TODO — fix calculation of keybit_len in ed25519 case (libopendkim/dkim.c)
`64fddf99` 2020-02-27 — TODO — Add missing space in Authentication-Results header (opendkim.c)
`c8ccbcee` 2020-02-06 — TODO — Suppress empty brackets in syslog startup message (opendkim.c)
`95e17711` 2020-01-02 — TODO — Minor doc updates in sample opendkim.conf
`c4e02c8a` 2020-01-02 — SKIPPED: license file — Typo in LICENSE.Sendmail
`c674feed` 2020-01-02 — TODO — miltertest: Fix undefined behaviour in mt.eom_check() with MT_SMTPREPLY
`0010ca71` 2019-12-31 — TODO — Fix leak in Unbound callback (opendkim/opendkim-dns.c)
`66111850` 2019-12-27 — TODO — miltertest: Fix broken mt.data() function
`6c46f094` 2019-01-02 — SKIPPED: autoconf — Fix unknown operator in configure.ac
`ba29fa57` 2018-11-14 — SKIPPED: merge only — Merge branch 'develop' of github.com:...
`1ec9f0ae` 2018-11-14 — NOT NEEDED: GnuTLS removed — Issue #29: Fix GNUTLS code (libopendkim/dkim.c)
`9b79dbba` 2018-11-14 — SKIPPED: autoconf — Fix res_ninit() detection with glibc (#2) (configure.ac)
`edc5677f` 2018-11-05 — TODO — Change enhanced status code used for RequiredHeaders rejections to 5.0.0
`da8215ca` 2018-11-05 — TODO — Fix issue #28: RequiredHeaders should report and log the specific error and reject, as documented
`37ca2067` 2018-11-05 — NOT NEEDED: GnuTLS removed — Issue #19 (reopened): Fix build errors in GnuTLS path (libopendkim/dkim.c)
`2a267b03` 2018-11-05 — SKIPPED: docs — Issue #17: Document known sendmail rewrite issues (opendkim/README)
`de4e44e9` 2018-11-03 — SKIPPED: changelog — RELEASE_NOTES entry for bind DNSSEC patch
`aa9c6005` 2018-11-03 — SKIPPED: merge only — Merge branch 'develop' of github.com:...
`1db96511` 2018-11-03 — TODO — Fix issue #15: Don't automatically skip the body when one mode (sign or verify) doesn't need it
`011e1b06` 2018-11-03 — TODO — Make the standard resolver DNSSEC aware (#1); libopendkim/dkim-dns.c + opendkim.c; DNSSEC validation support
`05da8d38` 2018-11-03 — SKIPPED: merge only — Merge branch 'develop' of github.com:...
`327954bf` 2018-11-03 — TODO — Fix issue #9: Plug a few failure mode memory leaks; librbl/rbl.c NOT NEEDED; opendkim.c and util.c parts are relevant
`ea171129` 2018-11-03 — TODO — document subdomain feature in opendkim-genzone manpage (#20)
`5b292034` 2018-11-03 — TODO — implement "SyslogName" configuration option (#21); new config option to set syslog ident
`939d83ae` 2018-11-02 — TODO — Issue #16: Remove redundant defaults; correction in MinimumKeyBits; other doc edits (opendkim.conf.5.in)
`9e567828` 2018-11-02 — SKIPPED: changelog — Credit for issue #8's patch (RELEASE_NOTES)
`cb0691cb` 2018-11-02 — TODO — Issue #8: The password file critical section isn't big enough (threading fix)
`17db0b56` 2018-11-02 — TODO — Issue #7: Code tidying (opendkim-db.c + opendkim.c); stats.c part NOT NEEDED
`a928851d` 2018-11-02 — TODO — Issue #14: Protect calls to ub_ctx_config() with a mutex (opendkim/opendkim-dns.c)
`86b1f4f4` 2018-11-02 — SKIPPED: autoconf — Issue #11: Remove poll feature references (configure.ac + autobuild + util.c); util.c change worth verifying is benign
`fa570a81` 2018-11-02 — NOT NEEDED: reputation subsystem removed — CONTRIB: Simplify logic in contrib/repute (repute.py)
`0aaa4a9a` 2018-11-02 — NOT NEEDED: GnuTLS removed — Issue #19: Add GNUTLS 3.4 support (part II) (libopendkim/dkim.c)
`5bac4f93` 2018-11-02 — NOT NEEDED: GnuTLS removed — Issue #19: Add GNUTLS 3.4 support (libopendkim/dkim.c)
`75925bae` 2018-11-02 — SKIPPED: docs — Notes on Postfix from Dilyan Palauzov (opendkim/README)
`fda8a318` 2018-08-31 — TODO — Fix test.c newline parsing (opendkim/test.c)
`4a773348` 2018-08-31 — TODO — LIBOPENDKIM: Fix bug #270: Don't set an upper bound on canonicalization buffer size; important fix for oversized input lines (dkim-canon.c + tests t-test155/t-test158)
`ba032e77` 2018-05-23 — SKIPPED: housekeeping — Update release process (.gitignore, configure, dkim.h)
`37c77160` 2018-05-23 — TODO — Always clobber, never free (libopendkim/dkim.c); memory handling fix
`ab73cf1d` 2018-05-20 — SKIPPED: merge only — Merge pull request #13 (andreasschulze)
`74bf5b08` 2018-05-19 — TODO — trivial fixes (libopendkim/dkim.h + opendkim.conf.5.in); header and doc tweaks
`0fb53f84` 2018-05-16 — SKIPPED: changelog — Update for 2.11.0 Beta0 (RELEASE_NOTES)
`720cc931` 2018-05-16 — TODO — Silence a warning (libopendkim/dkim.c)
`b9fa591a` 2018-05-16 — SKIPPED: housekeeping — Update copyright (many files)
`27a26c5e` 2018-05-16 — TODO — Add "a" tags to Authentication-Results header (libopendkim/dkim.c + dkim.h + opendkim.c)
`84d985c3` 2018-05-16 — TODO — Fix build when ED25519 is not present (libopendkim/dkim.c); may be moot if we mandate ed25519
`35bf6c90` 2018-05-16 — ADOPTED — Add support for ED25519 signing (original implementation; in our fork via upstream master)
`0d4a5866` 2018-03-14 — SKIPPED: merge only — Merge pull request #4 from ValiMail/feature-vme-1522
`82049dfc` 2018-03-13 — SKIPPED: cosmetic — [VME-1522] Rename var "sel" to "selector" (opendkim.c)
`41a85087` 2018-02-07 — TODO — [VME-1522] Add header.s to OpenDKIM AR stamp (opendkim.c + tests); adds selector to Authentication-Results header
`3deafe9a` 2017-03-04 — NOT NEEDED: OpenSSL 1.x compat superseded by EVP3 migration — CONFIG: Add compatibility with openssl-1.1.0 (configure.ac + opendkim-crypto.c)
`70e8914b` 2017-03-04 — SKIPPED: autoconf — Check for strl.h in another location (configure.ac)
`3bd41c1d` 2017-03-04 — TODO — Patch #34: Fix a few length checks in unit tests (t-test102, t-test138, t-test68)
`222ab0f8` 2017-03-04 — SKIPPED: changelog — Revise release date (RELEASE_NOTES)
`1b677a5c` 2016-02-11 — SKIPPED: docs — Modernize a bit (README)
`23c70d2b` 2015-11-01 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Fix conditional signature (t-test155)
`613e5ccd` 2015-10-22 — SKIPPED: docs — wrapping (opendkim/README)
`0fc1de48` 2015-10-21 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Oops (t-test156)
`4cf91f33` 2015-10-21 — NOT NEEDED: _FFR_CONDITIONAL not in scope — FFR_CONDITIONAL runtime fixes (dkim.h + tests)
`6162fc86` 2015-10-21 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Fix build without _FFR_CONDITIONAL (libopendkim/dkim.c)
`70ac3045` 2015-10-21 — SKIPPED: changelog — Wrapping (RELEASE_NOTES)
`4e059052` 2015-10-19 — SKIPPED: housekeeping — Update copyright (many files)
`ce640c31` 2015-10-07 — TODO — TOOLS: Add option to match subdomains when generating zone files (#187) (opendkim-genzone.8.in + opendkim-genzone.c)
`682e5f51` 2015-10-07 — SKIPPED: changelog — Ordering (RELEASE_NOTES)
`7bcfd822` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — comments (t-sign-ss-conditional.lua)
`5232e9a7` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Add unit tests for conditional signatures
`8b78c16f` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — append signing request for conditional signature
`ff49055b` 2015-10-07 — SKIPPED: changelog — _FFR_CONDITIONAL (RELEASE_NOTES)
`48030886` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — dkimf_check_conditional() stub (opendkim.c)
`70a0b3b7` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — DKIM_FEATURE_CONDITIONAL (libopendkim/dkim.c + dkim.h)
`dcfe0e30` 2015-10-07 — NOT NEEDED: _FFR_CONDITIONAL not in scope — That was silly (libopendkim/util.c)
`749ffbca` 2015-10-07 — SKIPPED: autoconf — Bump library version (configure.ac)
`c37998a8` 2015-10-07 — SKIPPED: merge only — Merge branch 'exp-msk-conditional' into develop
`8144a97a` 2015-10-07 — TODO — LIBOPENDKIM: Reject signature object requests where domain name or selector includes non-printable characters (#190); security validation (dkim.c + util.c)
`a6544216` 2015-10-07 — TODO — LIBOPENDKIM: Re-fix bug #226: Deal with header fields that are wrapped before there's any content (dkim-canon.c)
`276d67b3` 2015-10-07 — SKIPPED: docs — Add section on handling 8-bit stuff (opendkim/README)
`8ba85113` 2015-10-06 — REVIEW — oops (opendkim.c); one-line fix — check context to understand what it corrects
`59594e2d` 2015-10-06 — TODO — LIBOPENDKIM: Fix bug #233: In duplicate signature case, constrain size of "header.b" value (libopendkim/dkim.c)
`c5903f9e` 2015-10-06 — SKIPPED: changelog — Credit for #234 (RELEASE_NOTES)
`feccce9a` 2015-10-06 — TODO — Fix bug #235: Quote "header.b" values containing a slash (opendkim.c)
`c1fa5e53` 2015-10-06 — TODO — Document DSN "filter" feature (opendkim.8.in)
`843a9527` 2015-10-06 — TODO — dkimf_db_nextpunct() could incorrectly identify an encoded hex digit as a value delimiter (opendkim-db.c)
`825b1e2e` 2015-10-06 — TODO — Fix bug #237: Fix processing of "SoftStart" (opendkim.c)
`af3c67f9` 2015-10-06 — TODO — odkim.internal_ip() is available everywhere now (opendkim-lua.3.in doc)
`2b7bc8c7` 2015-10-06 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Add ConditionalSignatures table (opendkim-config.h + opendkim.c)
`b1e5acbf` 2015-10-06 — SKIPPED: autoconf — Change to v2.11.0 (configure.ac)
`9c777a43` 2015-10-06 — TODO — Make odkim.internal_ip() available to all Lua hooks (opendkim-lua.c); currently only available in some hooks
`2bbd2d1c` 2015-05-13 — SKIPPED: changelog — Wrapping (RELEASE_NOTES)
`4568f422` 2015-05-12 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Select v=2 signing if extra tags were mandatory (libopendkim/dkim.c)
`fbd88c62` 2015-05-11 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Restrict conditional signature recursion (libopendkim files)
`f3947ad6` 2015-05-11 — NOT NEEDED: _FFR_CONDITIONAL not in scope — "!fs" is now "!cd"; confirm mandatory parameter support (libopendkim)
`23f53f39` 2015-05-11 — NOT NEEDED: _FFR_CONDITIONAL not in scope — Export signatures (v= and l=) properly; unit tests (libopendkim)
`e848a615` 2015-05-10 — NOT NEEDED: _FFR_CONDITIONAL not in scope — First draft at doing conditional signatures (libopendkim + opendkim)

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
