# Quick Start — sign your first message

This is the short path: from a built-and-installed PhoenixDKIM to mail that
leaves your server carrying a valid DKIM signature, in a handful of commands.
It signs with **two keys at once** — one Ed25519 and one RSA-2048 — using a
KeyTable and a SigningTable, and wires the daemon to Postfix.

The examples target **Debian 13 (trixie)** and the domain `example.com`.
Substitute your own domain throughout. Adapting the paths and the package
manager to another OS is straightforward; the shape of the configuration does
not change.

If you have not installed PhoenixDKIM yet, do that first — see
[Building](../README.md#building) or the package on
[phoenixdkim.org](https://www.phoenixdkim.org/packages.html). This guide assumes
`phoenixdkim`, `phoenixdkim-genkey`, `phoenixdkim-testkey`, and
`phoenixdkim-testmsg` are on your `PATH` and that a `phoenixdkim` system user
exists (the package and the systemd unit create one).

## 1. Generate two signing keys

Keep both keys in one directory. The selector names them in DNS, so pick
something you will recognise — here, the algorithm:

```sh
mkdir -p /etc/phoenixdkim/keys
cd /etc/phoenixdkim/keys

phoenixdkim-genkey -t ed25519 -d example.com -s ed25519
phoenixdkim-genkey -b 2048    -d example.com -s rsa
```

Each run writes two files and prints a fingerprint:

- `ed25519.private` / `rsa.private` — the signing keys (mode `0600`)
- `ed25519.txt` / `rsa.txt` — the DNS TXT record to publish
- a `SHA256:...` public-key fingerprint on stdout (also a comment in the `.txt`)

> For production, name selectors by date (e.g. `20260601ed`) so several can
> coexist and rotation is painless — see [key-rotation.md](key-rotation.md).

Let the daemon read them, and nobody else:

```sh
chown -R phoenixdkim:phoenixdkim /etc/phoenixdkim/keys
chmod 0700 /etc/phoenixdkim/keys
```

## 2. Publish the two DNS records

Each `.txt` file contains one `v=DKIM1` TXT record. Publish both in the
`example.com` zone — at `ed25519._domainkey` and `rsa._domainkey` respectively.
How you do that (your own authoritative DNS, or a hosted provider's control
panel) is up to you; the record content is exactly what is in the file.

```sh
cat ed25519.txt rsa.txt
```

Wait for the records to propagate before signing with the keys (step 5 verifies
this). Publishing first, signing second, is the rule that keeps verifiers from
failing your mail.

## 3. Write the configuration

Three small files. First, `/etc/phoenixdkim/phoenixdkim.conf`:

```
Syslog                  yes
Canonicalization        relaxed/simple
MultipleSignatures      yes
KeyTable                /etc/phoenixdkim/keytable
SigningTable            refile:/etc/phoenixdkim/signingtable
Socket                  inet:8891@localhost
```

`MultipleSignatures yes` is what makes the daemon emit both signatures; without
it only the first matching key is used.

`/etc/phoenixdkim/keytable` — one line per key, mapping a name to
`domain:selector:keyfile`:

```
ed25519._domainkey.example.com   example.com:ed25519:/etc/phoenixdkim/keys/ed25519.private
rsa._domainkey.example.com       example.com:rsa:/etc/phoenixdkim/keys/rsa.private
```

`/etc/phoenixdkim/signingtable` — map every sender at the domain to both keys.
This file uses a regex (`*`), which is why the conf prefixes it with `refile:`:

```
*@example.com   ed25519._domainkey.example.com
*@example.com   rsa._domainkey.example.com
```

Syntax-check, then start the daemon:

```sh
phoenixdkim -t                       # configuration + key sanity check
systemctl enable --now phoenixdkim
```

## 4. Wire it to Postfix

Add to (or edit) `/etc/postfix/main.cf`:

```
milter_default_action = accept
smtpd_milters         = inet:localhost:8891
non_smtpd_milters     = inet:localhost:8891
```

Then reload:

```sh
systemctl reload postfix
```

`inet:localhost:8891` matches the `Socket` line above and avoids the
chroot/permission issues a UNIX-socket setup runs into when Postfix is
chrooted. (If you prefer a UNIX socket, point the conf at
`local:/var/spool/postfix/phoenixdkim/phoenixdkim.sock` and Postfix at
`unix:phoenixdkim/phoenixdkim.sock`.)

> PhoenixDKIM **signs** mail from trusted hosts (`InternalHosts`, default
> `127.0.0.1`/`::1`) and **verifies** mail from everywhere else. Postfix submits
> locally over the loopback, so your outbound mail is signed. If your mail
> originates on another host, add it to `InternalHosts`, or it will not be
> signed.

## 5. Verify it works

**Keys resolve and match the published records.** With a KeyTable configured and
no `-d/-s/-k`, `phoenixdkim-testkey` checks every entry against live DNS:

```sh
phoenixdkim-testkey -v
```

A clean run reports a pass for both `ed25519` and `rsa`. If it fails, the record
has not propagated or was published incorrectly — fix that before relying on
signing.

**Private keys round-trip through DNS.** `phoenixdkim-testmsg` signs a message
with a private key, then verifies it by fetching the *public* key from DNS — an
end-to-end check that the key you sign with matches the record you published:

```sh
printf 'From: you@example.com\r\nSubject: test\r\n\r\nhello\r\n' \
  | phoenixdkim-testmsg -d example.com -s ed25519 -k /etc/phoenixdkim/keys/ed25519.private \
  | phoenixdkim-testmsg -v
```

`phoenixdkim-testmsg -v` prints a one-line summary ending in a pass, and exits
`0`. Repeat with `-s rsa` and the RSA key to confirm both.

**A real message is signed.** Send yourself mail through Postfix and inspect the
headers — there should be two `DKIM-Signature:` headers (`a=ed25519-sha256` and
`a=rsa-sha256`):

```sh
echo "quick start works" | mail -s "dkim test" you@somewhere-else.example
```

Receiving mailbox should show `dkim=pass` in its `Authentication-Results`.
`journalctl -u phoenixdkim` shows the daemon's view if anything looks off.

That's it — outbound mail now carries an Ed25519 and an RSA signature.

## Where to next

- `phoenixdkim.conf(5)` — every configuration option
- [key-rotation.md](key-rotation.md) — rotate keys with no verification gap

