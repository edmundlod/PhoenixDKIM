# Rotating DKIM signing keys

Signing keys should be rotated periodically — quarterly is a common cadence —
and immediately if a private key may have been exposed. The hard part is doing
it without a window in which outbound mail is signed with a key that verifiers
cannot yet (or can no longer) resolve in DNS. The sequence below rotates a key
with zero such window.

The key idea is **overlap**: publish the new public key *before* you start
signing with it, and retire the old public key only *after* you have stopped
signing with it and enough time has passed for in-flight mail to be delivered
and verified.

Throughout, selectors are named by date so that several can coexist and it is
obvious which is current. The examples use `example.com` and assume keys live
in `/etc/phoenixdkim/keys`.

## 1. Generate the new key

Pick a new selector. A date stamp plus the algorithm makes collisions
impossible and the active key self-documenting:

```sh
cd /etc/phoenixdkim/keys
phoenixdkim-genkey -s 20260601 -d example.com
```

This writes `20260601.private` (the signing key) and `20260601.txt` (the DNS
TXT record) and prints the public key fingerprint, for example:

```
phoenixdkim-genkey: public key fingerprint: SHA256:q/u2mXhFTpfCgNNoxPCCFZQ51jyk0wHRSI/DvQurmns
```

Keep that fingerprint; in step 3 you will confirm the record published in DNS
is the one you just generated. The same line is also recorded as a comment at
the top of the `.txt` file.

Add the new key to the KeyTable, leaving the existing entry in place:

```
20260101._domainkey.example.com   example.com:20260101:/etc/phoenixdkim/keys/20260101.private
20260601._domainkey.example.com   example.com:20260601:/etc/phoenixdkim/keys/20260601.private
```

Do **not** point the SigningTable at the new selector yet. At this stage the
daemon knows about the new key but is still signing with the old one.

## 2. Publish the new public key in DNS

Add the contents of `20260601.txt` to the `example.com` zone *alongside* the
existing `20260101._domainkey` record. Both records must be live at the same
time. If you drive DNS with dynamic updates, `phoenixdkim-genzone -u` emits an
`nsupdate(8)` script for the KeyTable.

Reload the zone and reload the daemon so it sees the new KeyTable entry:

```sh
phoenixdkim -t            # syntax-check the configuration first
systemctl reload phoenixdkim
```

## 3. Wait for propagation, then verify both keys resolve

Wait at least as long as the TTL of the `_domainkey` records (the value your
zone assigns them — `phoenixdkim-genkey` emits no per-record TTL, so they
inherit the zone default; `phoenixdkim-genzone -t` can set one explicitly) so
that any resolver that cached "no such record" has had a chance to expire it.

Confirm both selectors resolve and match their private keys. When a KeyTable
is configured and no `-d/-s/-k` is given, `phoenixdkim-testkey` reads the whole
KeyTable and reports every entry (it loads
`/etc/phoenixdkim/phoenixdkim.conf` by default; use `-x` for another file):

```sh
phoenixdkim-testkey -v
```

A clean run reports a pass for both `20260101` and `20260601` and a summary
line. Cross-check that the `20260601` record carries the fingerprint you noted
in step 1 — the published `p=` value, run through `ssh-keygen -l` or
`openssl pkey -pubin -outform DER | openssl dgst -sha256`, must produce the same
`SHA256:...` string.

Do not proceed until the new key verifies. If it does not, the new record has
not propagated or was published incorrectly; signing with it now would break
verification for recipients.

## 4. Switch signing to the new key

Now point the SigningTable at the new selector:

```
*@example.com   20260601._domainkey.example.com
```

(or, under `MultipleSignatures`, reorder so the new selector is the one used —
see [multisigning.md](multisigning.md)). Reload:

```sh
phoenixdkim -t
systemctl reload phoenixdkim
```

From this point outbound mail is signed with `20260601`. The old public key is
still in DNS, so any mail signed with `20260101` that is still in transit
continues to verify.

## 5. Retire the old key

Leave the old public key in DNS long enough for all mail signed with it to have
been delivered and verified. A few days is generous; a week is safe and costs
nothing. There is no rush.

When the overlap window has elapsed:

1. Remove the `20260101._domainkey` TXT record from the zone (or, to leave an
   explicit tombstone, replace its value with `v=DKIM1; p=` — an empty `p=`
   marks the key as revoked).
2. Remove the `20260101` line from the KeyTable and reload the daemon.
3. Securely delete the retired private key:

   ```sh
   shred -u /etc/phoenixdkim/keys/20260101.private
   ```

Rotation is complete. `20260601` is now the sole active key, and the next
rotation repeats the cycle from step 1 with a new selector.

## Why the overlap matters

- **Publish before signing (steps 2–4).** If you switch signing to a selector
  whose record has not propagated, verifiers fail to retrieve the key and treat
  your mail as unsigned (or worse, as a failed signature). Publishing and
  verifying first eliminates that gap.
- **Retire after signing (step 5).** A message can sit in a queue, a forwarder,
  or a mailing list for hours or days before final delivery. If you delete the
  old public key the moment you stop using it, that in-flight mail fails
  verification. Keeping the old record live through the overlap window covers
  it.

## See also

- `phoenixdkim-genkey(8)` — key and TXT-record generation, fingerprint output
- `phoenixdkim-genzone(8)` — generate zone data or `nsupdate` scripts from a KeyTable
- `phoenixdkim-testkey(8)` — verify a key (or a whole configured KeyTable) against DNS
- [multisigning.md](multisigning.md) — running several keys/algorithms at once
