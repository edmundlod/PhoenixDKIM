# Future initiative: replace syslog() with environment-decided logging

Status: PROPOSED (not started). Out of scope for the upstream-port audit.
Context: arose while assessing upstream commit `62bc29c9` (Add `-O` / `StdoutLog`
for Docker). That commit is marked NOT NEEDED in the audit — it's a feature, not
a fix; it's implemented as a ~1500-line invasive rewrite; and our primary
deployment (systemd `Type=notify` + `-f`) already captures syslog via journald.
This note records the *better* way to get container/modern logging if we ever
want it, so the analysis isn't lost.

## The core problem
`syslog(pri, fmt, ...)` has no destination argument — destination is
process-global libc state set by `openlog()`. So making the destination
*configurable* (syslog vs stdout vs both) forces abandoning direct `syslog()`
calls in favor of a wrapper that decides. Upstream's pain came from making that
decision **per-config** (`dkimf_log(conf, pri, ...)`), which required threading
`conf` into hundreds of sites that don't have it (signal handlers, early init,
DB callbacks). That threading IS the 1500-line diff.

## Surface in our tree (measured 2026-05-26)
- 179 `syslog()` sites total: 176 in `opendkim/opendkim.c`, 2 in `opendkim/util.c`,
  1 in `opendkim/opendkim-dns.c`.
- libopendkim does NOT syslog (uses in-memory `dkim_error` strings) — library
  stays clean; blast radius is essentially one file.
- Priorities: 110 ERR, 29 INFO, 23 WARNING, 10 NOTICE, 1 CRIT.
- `openlog`/`closelog` live only in `dkimf_init_syslog()` (~opendkim.c:3718-3745).
- Syslog-coupled config: `Syslog` (conf_dolog master switch, gates ~50 sites),
  `SyslogFacility`, `SyslogName`, `SyslogSuccess`, `LogWhy`.
- Daemonize path (~opendkim.c:7995-8005) dup2's /dev/null over fds 0/1/2 then
  setsid() — so backgrounding sends stderr to /dev/null.

## The cheap modern design
- Destination is a **startup-fixed file-scope global**, NOT per-conf. Set once
  from CLI/config in the `dkimf_init_syslog` equivalent; read by the log fn.
  This is the key difference from upstream: "always one destination, chosen at
  startup" needs no context object, so NO conf-threading.
- One ~40-line vararg shim `dkimf_log(pri, fmt, ...)`; near-mechanical rename of
  the 179 call sites (sed-assisted, then hand-check priority/format edge cases).
- Default destination: stderr, emitting the sd-daemon prefix `"<%d>"` (pri) so
  journald parses real `PRIORITY=` and `journalctl -p err` keeps working — with
  ZERO libsystemd dependency. One snprintf, not a new dep.
- Keep syslog as an **opt-in backend** selected at startup, so traditional
  FreeBSD/jail/no-systemd hosts (today: /var/log/maillog via mail facility) don't
  regress.

## Where the real budget goes (not code)
- Compat/deprecation decisions for `SyslogFacility`/`SyslogName`/`SyslogSuccess`
  (parse-and-warn? repurpose `Syslog` as master on/off?). Live opendkim.conf
  files set these; can't just delete.
- Background-mode story: stderr-only logging mandates foreground-first operation
  (supervisor owns daemonization). We already run `Type=notify -f`; decide what
  background mode does for others (refuse, or keep syslog backend).
- Verification is eyeball/deploy-only: miltertest asserts no log output.

## End state
A one-function log layer with a destination switch — i.e. upstream's
`dkimf_log()` *shape* — but destination as a startup global (cheap) rather than
per-conf (expensive). ~60% of upstream's diff, none of the plumbing, regresses
nobody. Estimate: ~1 focused day of code + review; most effort is config-
deprecation decisions and docs.
