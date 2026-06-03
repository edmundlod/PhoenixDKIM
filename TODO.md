Remove libbsd dependency for Debian >= 13 (Trixie). strlcpy/strlcat are in
glibc 2.38, which ships with Debian 13 but not Debian 12. Once Debian 12
support is dropped, libbsd-dev can be removed from Build-Depends and the
cmake libbsd detection can be conditioned or dropped accordingly.
Ref: https://sourceware.org/pipermail/libc-alpha/2023-July/150524.html

========================

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
