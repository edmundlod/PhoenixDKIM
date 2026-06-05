# Internationalized email (EAI / RFC 8616)

PhoenixDKIM signs and verifies internationalized mail. Where pre-fork OpenDKIM
rejected any non-ASCII byte outright, and where the later OpenDKIM patch simply
waved every high byte through, PhoenixDKIM does the correct thing per
[RFC 8616](https://www.rfc-editor.org/rfc/rfc8616.txt): it accepts **well-formed
UTF-8** and resolves **U-label domains**.

## What works

- **UTF-8 in header field bodies.** A `Subject:` (or any field) carrying UTF-8
  is accepted and signed/verified as-is. The bytes are validated as well-formed
  UTF-8 (the `UTF8-2/3/4` productions of RFC 3629), so a `Héllo` or an emoji
  passes while malformed input is still rejected.
- **UTF-8 in signature tag values.** Non-ASCII is allowed in tag *values* — for
  example a UTF-8 local-part in the `i=` (AUID) tag — while tag *names* stay
  ASCII, exactly as RFC 8616 requires.
- **U-label signing domains.** A `d=` (SDID) written as a U-label (e.g.
  `d=münchen.example`) is converted to its A-label (`xn--mnchen-3ya.example`)
  with [libidn2](https://www.gnu.org/software/libidn/#libidn2) only for the DNS
  key lookup. The signed hash always uses the domain in the exact form it
  appears in the header, as the RFC mandates — the conversion never touches the
  signed data.
- **ASCII field names.** Header field names remain printable ASCII; only field
  bodies and tag values may carry UTF-8.

## What we improved over OpenDKIM

| | pre-fork OpenDKIM | OpenDKIM PR #404 | PhoenixDKIM |
|---|---|---|---|
| UTF-8 in field bodies | rejected | accepted (any byte ≥ 0x80) | accepted, **validated** as well-formed UTF-8 |
| Malformed UTF-8 (lone/overlong/surrogate/truncated) | rejected | **accepted** | **rejected** (`DKIM_STAT_SYNTAX`) |
| UTF-8 `i=` local-part | rejected | accepted | accepted |
| U-label `d=` → A-label for DNS | not done | not done | **done** via libidn2 |

## Building

U-label support is provided by **libidn2** and is on by default
(`-DWITH_IDN=ON`). libidn2 is packaged on Linux and the BSDs. To build without
it — in which case a signature whose `d=` is a U-label will fail its key
lookup — reconfigure with `-DWITH_IDN=OFF`.

## Notes

- Verification of UTF-8 header bodies and a U-label `d=` needs no configuration;
  it is always active.
- For maximum interoperability with verifiers that predate RFC 8616, you may
  still prefer to publish and sign with A-label domains. Both forms verify.
