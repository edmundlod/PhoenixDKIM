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
