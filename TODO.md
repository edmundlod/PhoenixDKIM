Audit opendkim-db.c for more dead code

========================

Configure COPR for RPM builds (Fedora/RHEL/CentOS/AlmaLinux).
Set up a .spec file and wire the CI to dispatch to COPR on tag push,
similar to the Debian apt dispatch step.

========================

CI / Github:
- use only one git commit key
- add release signing key to CI

========================

Compare upstream develop branch vs our master branch. They seem to have diverged many years before my fork. See what is missing in our branch, and what needs updating. I think OpenDKIM will eventually cut a new release from their develop branch and we want to be a drop in replacement. Don't port features we dont want. If any new features (eg FFR_CONDITIONAL) are present, or existing ones are changed or removed, explain what they do, and suggest if we want them for a modern, 2026 DKIM implementation.


https://github.com/trusteddomainproject/OpenDKIM/issues/140 -  Remove __P macros for musl

https://github.com/trusteddomainproject/OpenDKIM/pull/330 -- fix t-test205. We dont even have t-test205

https://github.com/trusteddomainproject/OpenDKIM/issues/242#issuecomment-4529370070 -- consider changing AlwaysAddARHeader to On

https://github.com/trusteddomainproject/OpenDKIM/issues/107 -- autodetect signature. perhaps can PR this.
    see: https://github.com/edmundlod/PhoenixDKIM/commit/4aa9a008188356c158bf00ee46fbf8e3519be05f
    
https://github.com/trusteddomainproject/OpenDKIM/pull/284 -- FD leak 

=========================

FEATURES to consider:

 PhoenixDKIM — Feature Gap Analysis
  
  Overall the project is in very good shape. What follows is organised by tier: things that are genuinely missing, things that are present but thin, and things worth noting for the future.

  ---
  Tier 1 — Real gaps users will notice
  
  1. On- policy granularity for specific failure causes

  You have On-BadSignature, On-DNSError, On-KeyNotFound, On-NoSignature, On-InternalError, On-Security, On-SignatureError. Good. But there are two distinguishable failure sub-cases that
  fall silently into On-BadSignature and which some sites would want to handle differently:

  - On-ExpiredSignature — a signature that was valid when sent but is now past its x= timestamp. This is different from a cryptographically bad signature; it often indicates a replay attack
   or a legitimate message caught in a queue. The library already tracks DKIM_SIGERROR_EXPIRED and DKIM_SIGERROR_FUTURE — the daemon just doesn't expose a separate policy knob for them.
  - On-WeakAlgorithm — an RSA-SHA1 signature that verifies but uses a deprecated algorithm. It currently passes and is annotated in the A-R header, but there's no way to configure "treat a
  passing sha1 signature as neutral/fail without breaking good signatures". Some operators would want this as RHEL 9 systems already reject sha1 outright at the SSL layer.

  2. systemd Type=notify + watchdog

  The service unit uses Type=simple, which means systemd declares the unit "active" the moment the process starts — before it has bound its milter socket and is actually ready to serve
  connections. During a restart, Postfix can try to deliver through the socket before it exists and fall back to milter_default_action. Fix: add sd_notify(READY=1) after smfi_main() returns
   from initialisation (or after the socket is bound), declare Type=notify in the unit, and add WatchdogSec= + periodic sd_notify(WATCHDOG=1) heartbeats from the filter thread. This is a
  small addition with meaningful operational impact for services managed by systemd.

  3. Systemd unit hardening gaps

  ProtectSystem=strict and ProtectHome=true are present, but the unit is missing the next tier of sandboxing that security-conscious deployments expect:
  NoNewPrivileges=true
  CapabilityBoundingSet=
  MemoryDenyWriteExecute=true
  RestrictRealtime=true
  RestrictSUIDSGID=true
  LockPersonality=true
  SystemCallFilter=@system-service
  ProtectKernelTunables=true
  ProtectKernelModules=true
  ProtectControlGroups=true
  PrivateDevices=true
  This is low-effort boilerplate — systemd-analyze security opendkim will show the current exposure score. Closing these would also give users with systemd-harden-aware distros (Debian 12,
  Fedora 40+) better out-of-box isolation without requiring AppArmor/SELinux profiles.
  
  4. opendkim-testkey batch / KeyTable-wide mode

  Currently testkey takes a single (-d domain, -s selector) pair or reads from a config with one Domain/Selector. If you run 50 domains, you have to loop manually. A -A / --all flag that
  reads the full KeyTable and reports pass/fail for every entry — with a single exit code summarising the whole batch — would be genuinely useful for deployment verification and cron-driven
   monitoring.
  
  5. PKCS#11 / HSM key storage

  High-volume senders and regulated industries (banking, government mail servers) increasingly store signing keys in HSMs or cloud KMS services rather than files. The OpenSSL 3 provider
  model supports this cleanly via pkcs11-provider (or legacy libpkcs11-helper). A KeyFile value that accepts a pkcs11: URI, or an optional -DWITH_PKCS11=ON build flag, would open that use
  case without changing any crypto code — the EVP layer handles it transparently once the provider is loaded. This is worth at least documenting as a known gap.
  
  6. opendkim-genkey fingerprint output

  When generating a key pair, print the SHA-256 fingerprint of the public key (the SPKI fingerprint, the same thing ssh-keygen -l gives) to stdout. This makes it trivial to cross-check "is
  the key in DNS the one I generated" without having to base64-decode and compare manually. One line to the .txt file or a -v mode.

  ---
  Tier 2 — Present but thin / could be meaningfully improved

  7. opendkim-testmsg verification output

  On a successful verify, testmsg exits 0 silently. For a testing tool, that's underselling it. A -v level that prints: algorithm used, domain, selector, canonicalisation pair, body hash
  match, timestamp validity, and DNSSEC status of the key record would make it actually useful for debugging "did my outbound signature survive transit through X MTA" workflows. The
  information is all available from dkim_sig_get* calls.
  
  8. Key rotation documentation / workflow

  You have all the pieces (date-based selectors in the multisigning example, genzone -u for nsupdate, testkey), but there's no document that walks through the full safe rotation sequence:
  1. Generate new selector, add to KeyTable
  2. Publish new DNS record, keep old one
  3. Wait ≥ TTL (currently 300s default — that's actually fine for rotation)
  4. Switch signing (reorder in SigningTable or change MultipleSignatures)
  5. Retire old key file, revoke DNS record
  
  This is a FAQ item for every operator. Even a short docs/key-rotation.md would reduce support burden substantially.

  9. BodyLengthDB (l= tag) danger warning

  The config documentation mentions "this creates a potential security issue" but doesn't say what it is: a receiver that enforces the l= limit will accept appended content as if it were
  signed. This is an active attack vector (the "DKIM truncation" or "Nolisting" class of attacks). The documentation should either be expanded with a clear recommendation against using l=
  in new deployments (RFC 6376 §8.2 and RFC 8616 §3.1 both discourage it), or BodyLengthDB should emit a startup warning. OpenARC has already dropped support for signing with l=.
  
  ---
  Tier 3 — Future scope (already noted or strategic)
  
  11. Prometheus / StatsD metrics — already in your SCOPE.md future notes. Worth adding: the minimum useful metric set would be dkim_signatures_total{result=pass|fail|none,algorithm=...}
  and dkim_dns_lookups_total{result=...}. StatsD is simpler to implement (one sendto()); Prometheus is more useful for modern stacks.

  13. DKIM2 (draft-ietf-dkim-next) — acknowledged. Nothing to do yet; the draft is still in flux.

  ---
  One thing that's genuinely good and worth keeping visible
  
  The UnprotectedKey option (treating a DKIM key retrieved without DNSSEC differently) is something most DKIM implementations don't expose at all. It's exactly right that it's there.
  Consider making it more prominent in documentation — it's a real differentiator for security-conscious deployments.

===============

In: fix/sha1-verify-options


  # Resume: implement On-WeakAlgorithm (rsa-sha1) policy in PhoenixDKIM

  ## Repo
  PhoenixDKIM (a fork of trusteddomainproject/OpenDKIM), at /home/edmund/devel/projects/PhoenixDKIM.
  Library code in libopendkim/, daemon in opendkim/. Configure with -DWITH_LUA=1 -DWITH_REDIS=1.
  Build dir already exists: `cd build && cmake --build . --target opendkim`.
  Commit style: "Fix:"/"Add" prefix, attribute upstream where relevant, NO Claude/Co-Authored-By trailer; commits are GPG-signed.

  ## Goal
  Add a new verifier config option `On-WeakAlgorithm` controlling how a DKIM signature that
  uses the deprecated rsa-sha1 algorithm (RFC 8301) is handled. Values (milter-handling family,
  share the dkimf_values vocabulary): accept, neutral (DEFAULT), reject, quarantine, tempfail, discard.
  - neutral  = deliver the message, report dkim=neutral (reason: deprecated algorithm rsa-sha1)
  - accept   = trust it: verify normally and report dkim=pass on success (historical behaviour)
  - reject/quarantine/tempfail/discard = the corresponding milter disposition

  ## KEY DESIGN DECISION (this is the important part)
  Decide on the DECLARED algorithm (a=rsa-sha1, known at parse time, dkim.c:2018 sets sig_signalg),
  NOT on the crypto pass/fail result. Reason: on Fedora 44 / RHEL 9 DEFAULT crypto policy, OpenSSL
  REFUSES RSA-over-SHA1 signature verification (EVP_PKEY_CTX_set_signature_md / EVP_PKEY_verify fail
  at libopendkim/dkim.c:5550-5614), so an rsa-sha1 sig never gets DKIM_SIGFLAG_PASSED — it errors
  into KEYDECODE/BADSIG and falls into On-BadSignature. So "verify then downgrade a pass" is broken
  on the target platform. (opendkim itself still STARTS fine — the AllowSHA1Only startup gate is about
  sha256 availability, not sha1. Raw sha1 body-hash digesting still works; only RSA+sha1 *signature*
  verify is blocked.)

  Required behaviour (per user):
  - SHORT-CIRCUIT rsa-sha1 verification in libopendkim (skip the OpenSSL call) UNLESS policy == accept.
    - neutral (default): short-circuit, report neutral, deliver. Done.
    - reject/quarantine/tempfail/discard: short-circuit, then apply that disposition.
    - accept: do NOT short-circuit — verify normally, accept if it passes. (On hardened platforms this
      mode needs `update-crypto-policies --set LEGACY` or a SHA1 subpolicy; DOCUMENT this in the man page.)
  - Signing: rsa-sha1 signing is already unsupported (dkim.c:3743) — no signing changes needed.

  ## WHAT IS ALREADY ON DISK (intermediate, pre-pivot "verify-then-downgrade" version — NOT yet compiled)
  These reflect the milter-handling wiring and mostly STAY, but the detection/enforcement logic must be
  REWORKED for the short-circuit model:
  - opendkim/opendkim.c:
    - `#define DKIMF_MILTER_NEUTRAL 5` (~126)
    - struct handling: `int hndl_weakalg;` (~152); defaults table: weakalg = DKIMF_MILTER_NEUTRAL
    - `#define HNDL_WEAKALG 10`; dkimf_params: `{ "weakalgorithm", HNDL_WEAKALG }`
    - dkimf_values: `{ "n"/"neutral", DKIMF_MILTER_NEUTRAL }`
    - dkimf_miltercode(): NEUTRAL case → returns SMFIS_ACCEPT
    - dkimf_parsehandler(): HNDL_WEAKALG case (NOT added to HNDL_DEFAULT — weakalg is opt-in, not swept by On-Default)
    - config load chain (~5806): `dkimf_parsehandler(data, "On-WeakAlgorithm", ...)`
    - dkimf_ar_all_sigs() (~9581): downgrades result to "neutral" when hndl_weakalg != ACCEPT AND result=="pass"
      AND alg==rsa-sha1  ← REWORK: must also catch the short-circuited (non-passed) rsa-sha1 sig
    - DKIM_STAT_OK enforcement block (~12174): checks final passed sig, applies dkimf_miltercode, with
      testkey→accept downgrade for reject/tempfail/discard  ← REWORK: won't fire for short-circuited sigs
  - opendkim/opendkim-config.h: `{ "On-WeakAlgorithm", CONFIG_TYPE_STRING, FALSE }`
  - opendkim/opendkim.conf.5: On-WeakAlgorithm entry (neutral default + all options) — UPDATE to document
  - opendkim/opendkim.conf.sample: `# On-WeakAlgorithm` line
  
  ## WHAT STILL NEEDS TO BE DONE (the pivot)
  1. New library flag to request sha1-verify short-circuit. Follow the existing DKIM_LIBFLAGS_* /
     DKIM_OPTS_FLAGS pattern (set in opendkim.c dkimf_config_setlib ~7365-7371 via dkim_getopt/dkim_setopt;
     flags defined in libopendkim/dkim.h). Add e.g. DKIM_LIBFLAGS_NOSHA1VERIFY. Daemon enables it when
     On-WeakAlgorithm != accept.
  2. In libopendkim verify path (dkim.c ~5550, before `md = EVP_sha1()` / the EVP calls): if the flag is
     set AND sig_hashtype/sig_signalg is rsa-sha1, SKIP crypto and mark the sig with a dedicated state
     (suggest a new code DKIM_SIGERROR_WEAKALG in dkim.h + string in libopendkim/dkim-tables.c, and
     expose in opendkim/opendkim-lua.c globals like the other DKIM_SIGERROR_* if appropriate). Set
     DKIM_SIGFLAG_PROCESSED, do NOT set PASSED, do not call OpenSSL.
  3. Daemon: rework so On-WeakAlgorithm is applied based on the declared-rsa-sha1 / WEAKALG marker
     regardless of crypto outcome (it will arrive via a non-OK status / the new sig error, not DKIM_STAT_OK).
     - ar_all_sigs: report "neutral" (reason deprecated algorithm) for a WEAKALG-marked sig.
     - disposition: apply hndl_weakalg (reject/quarantine/tempfail/discard) in the relevant branch; keep
       testkey→accept downgrade for the hard dispositions (mirrors On-BadSignature).
     - accept mode: flag NOT set, so the sig is verified normally → existing pass/fail path, report pass.
  4. Build (`cmake --build build --target opendkim`) and fix compile errors. The on-disk code has NOT been
     compiled yet. 
     
  ## Useful code references
  - Verify/crypto: libopendkim/dkim.c:5550-5614 (md=EVP_sha1 at 5559; rsastat→PASSED/BADSIG)
  - sig_signalg set at parse: dkim.c:2018; DKIM_SIGN_RSASHA1=0 / RSASHA256=1 (dkim.h:198-199);
    dkim_sig_getsignalg() at dkim.c:7351
  - A-R result strings: opendkim.c dkimf_ar_all_sigs ~9442-9607 (pass/fail/neutral/policy)
  - Disposition flow: mlfi_eom status switch ~12160 sets mctx_status; bottom switch ~12710 maps
    mctx_status→milter ret via dkimf_libstatus; `ret` inits to SMFIS_ACCEPT. DKIM_STAT_CANTVRFY and
    DKIM_STAT_BADSIG both route to On-BadSignature (hndl_badsig).
  - Final result computation in lib: dkim.c:4115-4152 (which sig_errors map to CANTVRFY vs BADSIG etc.)
  - DKIM_LIBFLAGS plumbing example: opendkim.c:7365-7371
  
  ## Constraints
  - DO NOT construct/test real rsa-sha1 messages on this Fedora box (user instruction).
  - Don't sweep On-WeakAlgorithm into On-Default. Keep neutral as the default.
  
  The on-disk changes are an intermediate state (the pre-pivot "verify-then-downgrade" version) and have not been compiled yet — the next session will rework the detection to short-circuit
  and then build. Nothing has been committed.
