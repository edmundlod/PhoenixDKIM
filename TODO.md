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

  5. PKCS#11 / HSM key storage

  High-volume senders and regulated industries (banking, government mail servers) increasingly store signing keys in HSMs or cloud KMS services rather than files. The OpenSSL 3 provider
  model supports this cleanly via pkcs11-provider (or legacy libpkcs11-helper). A KeyFile value that accepts a pkcs11: URI, or an optional -DWITH_PKCS11=ON build flag, would open that use
  case without changing any crypto code — the EVP layer handles it transparently once the provider is loaded. This is worth at least documenting as a known gap.
  
  ---
  Tier 3 — Future scope (already noted or strategic)
  
  11. Prometheus / StatsD metrics — already in your SCOPE.md future notes. Worth adding: the minimum useful metric set would be dkim_signatures_total{result=pass|fail|none,algorithm=...}
  and dkim_dns_lookups_total{result=...}. StatsD is simpler to implement (one sendto()); Prometheus is more useful for modern stacks.

  13. DKIM2 (draft-ietf-dkim-next) — acknowledged. Nothing to do yet; the draft is still in flux.

  ---


===============

In: fix/sha1-verify-options
