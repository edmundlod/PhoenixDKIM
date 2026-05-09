# opendkim Filter — Configuration Guide

This document walks through configuring and activating the opendkim filter
after it has been compiled and installed. See the root-level `INSTALL` for
build and installation instructions.

## Overview

Setting up opendkim for signing involves:

1. Choosing a selector name
2. Generating a signing keypair
3. Publishing the public key in DNS
4. Configuring the filter
5. Connecting the filter to your MTA
6. Testing

For verification-only deployments (no signing), start at step 5.

---

## Socket Selection

The MTA and the opendkim filter communicate over a socket. Two types are
supported:

**UNIX domain socket** — secured via filesystem permissions; cannot be
reached from remote hosts. Recommended for single-server setups.

**TCP socket** — accessible from remote hosts. Required if multiple MTAs
share one opendkim instance. Ensure your packet filter permits traffic on
the chosen port. For SELinux systems:

```
semanage port -a -t milter_port_t -p tcp <port>
```

---

## Configuring opendkim

### 1. Choose a selector name

A selector is a label that identifies which key was used to sign a message.
You can use any name you like. Common conventions: the hostname of the
signing server, or the current month and year (e.g. `2026-01`).

### 2. Generate a signing keypair

Use `opendkim-genkey`. For an RSA key:

```
opendkim-genkey -b 4096 -d example.com -s SELECTOR
```

For an Ed25519 key (RFC 8463, shorter key, faster operations):

```
opendkim-genkey -t ed25519 -d example.com -s SELECTOR
```

Both commands produce:
- A private key file (`SELECTOR.private`)
- A DNS TXT record (`SELECTOR.txt`) ready to paste into your zone file

RSA keys must be at least 2048 bits. 4096 bits is recommended.

### 3. Publish the public key in DNS

The public key must be published as a TXT record at:

```
SELECTOR._domainkey.DOMAIN
```

Copy the `p=` value from the generated `.txt` file into your zone file.
Add `t=y` during testing (signals to verifiers that this key is in test
mode). Remove `t=y` once you are satisfied with the results.

Set a short TTL during initial deployment so changes propagate quickly.

Check that the record is being served correctly:

```
dig TXT SELECTOR._domainkey.DOMAIN @NAMESERVER
```

Then validate it against your private key:

```
opendkim-testkey -d DOMAIN -s SELECTOR -k SELECTOR.private
```

### 4. Store the private key

Place the private key in a secure location, for example:

```
/etc/opendkim/keys/SELECTOR.private
```

The key file should be owned by the user that runs opendkim and have mode
`0600`. The directory should be mode `0700`.

### 5. Configure the filter

A sample configuration file is installed at
`/etc/opendkim/opendkim.conf.sample`. Copy it to `/etc/opendkim/opendkim.conf`
and edit it.

For a simple single-domain setup with one key:

```
Domain          example.com
Selector        SELECTOR
KeyFile         /etc/opendkim/keys/SELECTOR.private
Socket          local:/run/opendkim/opendkim.sock
Syslog          yes
```

For more complex setups with multiple domains or keys, use `KeyTable` and
`SigningTable` — see **Complex Signing Configurations** below.

### 6. Start the filter

Using systemd (recommended):

```
systemctl enable opendkim
systemctl start opendkim
```

Or manually:

```
opendkim -x /etc/opendkim/opendkim.conf
```

### 7. Configure your MTA

**Postfix** — add to `main.cf`:

```
smtpd_milters        = local:/run/opendkim/opendkim.sock
non_smtpd_milters    = local:/run/opendkim/opendkim.sock
milter_default_action = accept
```

If you have a content filter in `master.cf` that feeds mail back into a
second smtpd process, add `-o receive_override_options=no_milters` to that
smtpd entry to avoid double-signing.

**Sendmail** — add to `sendmail.mc`:

```
INPUT_MAIL_FILTER(`opendkim', `S=local:/run/opendkim/opendkim.sock')
```

Rebuild `sendmail.cf` in the usual way.

### 8. Reload your MTA

```
# Postfix
postfix reload

# Sendmail
kill -HUP $(head -1 /var/run/sendmail.pid)
```

---

## Complex Signing Configurations

The `KeyTable` and `SigningTable` are used when you need to sign for
multiple domains, multiple selectors, or map different senders to different
keys.

**KeyTable** maps arbitrary key names to `domain:selector:keyfile` triples:

```
preskey   example.com:foo:/etc/opendkim/keys/president.private
comkey    example.com:bar:/etc/opendkim/keys/excom.private
netkey    example.net:baz:/etc/opendkim/keys/exnet.private
```

**SigningTable** maps sender addresses (or patterns) to key names from
the KeyTable. If wildcards are needed, use a `refile:` data set:

```
president@example.com   preskey
*@example.com           comkey
*@example.net           netkey
```

Reference both in `opendkim.conf`:

```
KeyTable      /etc/opendkim/keytable
SigningTable  refile:/etc/opendkim/signingtable
```

---

## Data Sets

Several configuration options accept a "dataset" — a source of key/value
pairs. The supported backends are:

**file:** — flat text file, two columns separated by whitespace. The key
column is matched exactly (or by the lookup rules described in the man
page for each option). This is the default if the value starts with `/`.

```
KeyTable    /etc/opendkim/keytable
```

**refile:** — like `file:`, but the key column is a glob pattern where
`*` matches zero or more characters. Required for wildcard entries in
`SigningTable`.

```
SigningTable  refile:/etc/opendkim/signingtable
```

**csl:** — comma-separated inline list in the configuration file itself.

```
ExemptDomains  csl:example.com,test.example.com
```

**lmdb:** — LMDB database file. Faster lookups for large tables. Use
`opendkim-genzone` or an external tool to build the LMDB database.

```
KeyTable  lmdb:/etc/opendkim/keytable.lmdb
```

**lua:** — Lua script called for each lookup. The script receives the
query string in a global variable `query` and returns the value.
Requires `-DWITH_LUA=ON`. Useful for secrets-manager integrations or
dynamically computed lookup tables.

```
KeyTable  lua:/etc/opendkim/keylookup.lua
```

For multi-field values (e.g. KeyTable entries), colon-separated fields
are used:

```
keyname   domain.com:selector:/path/to/key.private
```

---

## Mailing List Handling

Most mailing list software (Mailman, etc.) modifies messages in ways that
break existing DKIM signatures — adding footers, changing headers, etc.
If you run a mailing list, configure opendkim to sign list-generated mail:

1. If the list is on a subdomain (e.g. `lists.example.org`), generate a
   key for that domain and add it to the KeyTable.

2. In the `SigningTable`, add an entry for the bounce address
   (`mylist-bounces@lists.example.org`), not the list post address.
   Alternatively, sign the whole subdomain:

   ```
   lists.example.org   listkey
   ```

3. Set `SenderHeaders Sender,From` in `opendkim.conf` so opendkim uses
   the `Sender:` field (which mailing list software sets to the bounce
   address) rather than the `From:` field for signing table lookups.

With this configuration, mail generated by the list software will be
signed. If a subscriber from your domain posts to the list, the message
will carry two signatures — the original (likely broken by list
modifications) and the new one. This is normal; verifiers treat a broken
signature as absent.

---

## Testing

Send a test message through your signing MTA to one of the DKIM
verification services below. Each will reply showing the headers added
in transit, including the `Authentication-Results:` field.

```
check-auth@verifier.port25.com
autorespond+dkim@dk.elandsys.com
dkim-test@altn.com
```

Alternatively, send to a major provider (Gmail, etc.) that verifies DKIM
and check the raw message headers in your received copy.

The reply should contain a `DKIM-Signature:` added by your filter and an
`Authentication-Results:` from the receiving server showing `dkim=pass`.
If verification fails, check that no intermediate filter is modifying the
message between signing and delivery.

---

## Large Keys

TXT records in DNS consist of strings not exceeding 255 bytes each. Large
RSA public keys (4096 bits and above) must be split across multiple strings
in the zone file. `opendkim-genkey` produces a correctly formatted
multi-string record in the `.txt` file it generates. If you are formatting
a record manually:

```dns
SELECTOR._domainkey  IN  TXT  (
    "v=DKIM1; k=rsa; "
    "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
    "...rest-of-key..." )
```

Ed25519 keys are 32 bytes and always fit within a single 255-byte string.

---

## Manually Creating DKIM Keys

`opendkim-genkey` is the recommended tool. If you need to generate keys
manually with openssl:

**RSA (minimum 2048 bits; 4096 recommended):**

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out rsa.private
openssl rsa -in rsa.private -pubout -out rsa.public
```

**Ed25519:**

```
openssl genpkey -algorithm ed25519 -out ed25519.private
openssl pkey -in ed25519.private -pubout -out ed25519.public
```

Publish the base64-encoded public key (the content between `-----BEGIN
PUBLIC KEY-----` and `-----END PUBLIC KEY-----`, with whitespace removed)
as the `p=` value in the DNS TXT record:

```
"v=DKIM1; k=rsa; p=MIIBIjAN..."
"v=DKIM1; k=ed25519; p=MCowBQYDK2VwAyEA..."
```

---

## Debug Features

### Canonicalised content

Set `KeepTemporaryFiles yes` and optionally `TemporaryDirectory /path`
to preserve the canonicalised header and body files written during signing
or verification. Comparing these files between a signer and a failing
verifier usually reveals what changed in transit.

### Diagnostics

Set `Diagnostics yes` to include a `z=` tag in generated signatures
containing the original signed header set. If a verifier has
`DiagnosticDirectory` set, it will write a file comparing the `z=`
headers to the received headers whenever a `z=`-tagged signature fails.

---

## Support

Report bugs and submit contributions via GitHub:

https://github.com/edmundlod/opendkim-ng
