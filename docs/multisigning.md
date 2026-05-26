# A quick example on using multiple DKIM-keys per e-mail

If you want to use several DKIM keys for a domain, for example to use an Ed25519 signing key, with an RSA key as fall-back for those providers who don't verify Ed25519, the configuration would look as follows.

In `/etc/opendkim.conf`

```sh
MultipleSignatures      yes

KeyTable                /etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
```

The configuration files look like this:

```sh
/etc/opendkim/key.table:

20260101ed._domainkey.domain.com     domain.com:20260101ed:/etc/dkimkeys/20260101ed.private
20260101rsa._domainkey.domain.com     domain.com:20260101rsa:/etc/dkimkeys/20260101rsa.private
```

```sh
cat /etc/opendkim/signing.table
*@domain.com 20260101ed._domainkey.domain.com
*@domain.com 20260101rsa._domainkey.domain.com
```

See opendkim.conf(5) for what each option means in detail.

Note that since the signing.table in this example uses regex, it needs to be configured in `/etc/opendkim.conf` with `refile:/etc/opendkim/signing.table`.

## Choosing the algorithm

There is no need to name the signing algorithm in the key table. PhoenixDKIM
derives it from the key material itself: an Ed25519 key signs with
`ed25519-sha256` and an RSA key with `rsa-sha256`. An optional fourth field
naming an algorithm is accepted for compatibility with key tables written for
other implementations, but it is advisory only — if it contradicts the actual
key, a warning is logged and signing proceeds with the key-derived algorithm.

## Operational caveats

The motivation for dual-algorithm signing is as a contingency against a future
cryptographic weakness in one algorithm; no such weakness in RSA has been
discovered at the time of this writing. While Ed25519 produces smaller DNS
records and shorter keys than RSA, the savings in the context of modern mail
headers are trivial. Signing with multiple algorithms requires each validating
server to verify all signatures, increasing load on both sides, and provides
no immediate security benefit in normal operation. Have a clear reason before
enabling this feature; it is most useful for interoperability testing.

## How verifiers report the result

A verifier produces a single `Authentication-Results` header containing one
`dkim=` entry per signature, for example:

```
Authentication-Results: example.com;
  dkim=pass header.d=domain.com header.s=20260101rsa header.a=rsa-sha256;
  dkim=fail header.d=domain.com header.s=20260101ed header.a=ed25519-sha256
```

RFC 6376 requires that each signature be evaluated independently but does not
define what a verifier or downstream tool should conclude when results are
mixed; this is left to local policy. OpenDKIM treats a message as passing if
any signature passes, but a stricter implementation may treat any `dkim=fail`
entry as a failure regardless of other results. Downstream tools that inspect
`Authentication-Results` headers (including, but not limited to, SpamAssassin)
may behave differently and in ways that are not easily predicted. Test the full
mail path before deploying multi-algorithm signing in production.
