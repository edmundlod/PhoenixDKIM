-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- DKIM2-core modifying re-sign integration test
--
-- Drives the whole modifying-resign loop through the daemon, end to end:
--
--   1. originate   -- the daemon signs a fresh message (captures MI1 + SIG1)
--   2. verify+snap -- the same message arrives inbound, the daemon verifies the
--                     chain (PASS) and snapshots it keyed by the top instance
--   3. modify+sign -- a modified copy (a mailing-list footer appended) is
--                     re-injected; the daemon diffs it against the snapshot and
--                     adds MI2 + SIG2 carrying a reverting recipe
--   4. verify      -- the re-signed two-hop message verifies PASS offline
--   5. no snapshot -- a modified message whose chain was never snapshotted is
--                     delivered UNSIGNED (the daemon must not vouch for a chain
--                     it cannot reconstruct)
--
-- Public keys are served offline from pubkeys via TestDNSData, so the run needs
-- no live DNS.  See phoenixdkim-dkim2store.c and dkimf_dkim2_sign_msg().

mt.echo("*** DKIM2-core modifying re-sign integration test")

-- ── setup ────────────────────────────────────────────────────────────────────
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-dkim2-resign.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

cwd = mt.getcwd()
snapdir = cwd .. "/t-dkim2-resign.snap"
m2file = cwd .. "/t-dkim2-resign.m2.tmp"

-- The daemon refuses to start if its snapshot directory is missing, and never
-- creates it itself; provision a clean one (clearing any stale shards first).
os.execute("rm -rf '" .. snapdir .. "' && mkdir -p '" .. snapdir .. "'")

-- Locate the standalone DKIM2 verifier used as the offline oracle in step 4.
-- Under the normal CMake build PHOENIXDKIM_BINPATH is <build>/phoenixdkim and
-- the CLI sits beside it in <build>/libphoenixdkim.
function find_verify_cli()
	local c = {
		(string.gsub(binpath, "phoenixdkim$", "libphoenixdkim"))
			.. "/phoenixdkim2-verify",
		binpath .. "/phoenixdkim2-verify",
		binpath .. "/../libphoenixdkim/phoenixdkim2-verify",
	}
	for _, p in ipairs(c) do
		local f = io.open(p, "r")
		if f ~= nil then
			f:close()
			return p
		end
	end
	return nil
end
verifycli = find_verify_cli()
if verifycli == nil then
	error("cannot locate phoenixdkim2-verify CLI")
end

-- start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x", "t-dkim2-resign.conf",
               "-p", sock)

-- ── helpers ──────────────────────────────────────────────────────────────────

-- Run one full SMTP transaction against the filter and return the open
-- connection so the caller can inspect the filter's end-of-message actions.
-- `hdrs` is an array of {name, value} pairs; `ip` selects internal (127.0.0.1,
-- signs) vs external (a non-loopback address, verify only).
function txn(ip, jobid, mailfrom, rcpt, hdrs, body)
	local conn = mt.connect(sock, 40, 0.25)
	if conn == nil then
		error("mt.connect() failed")
	end
	if mt.conninfo(conn, "mta.example.net", ip) ~= nil then
		error("mt.conninfo() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.conninfo() unexpected reply")
	end
	mt.macro(conn, SMFIC_MAIL, "i", jobid)
	if mt.mailfrom(conn, mailfrom) ~= nil then
		error("mt.mailfrom() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.mailfrom() unexpected reply")
	end
	if mt.rcptto(conn, rcpt) ~= nil then
		error("mt.rcptto() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.rcptto() unexpected reply")
	end
	for _, h in ipairs(hdrs) do
		if mt.header(conn, h[1], h[2]) ~= nil then
			error("mt.header(" .. h[1] .. ") failed")
		end
		if mt.getreply(conn) ~= SMFIR_CONTINUE then
			error("mt.header(" .. h[1] .. ") unexpected reply")
		end
	end
	if mt.eoh(conn) ~= nil then
		error("mt.eoh() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.eoh() unexpected reply")
	end
	if mt.bodystring(conn, body) ~= nil then
		error("mt.bodystring() failed")
	end
	if mt.getreply(conn) ~= SMFIR_CONTINUE then
		error("mt.bodystring() unexpected reply")
	end
	if mt.eom(conn) ~= nil then
		error("mt.eom() failed")
	end
	if mt.getreply(conn) ~= SMFIR_ACCEPT then
		error("mt.eom() unexpected reply (expected ACCEPT)")
	end
	return conn
end

function added_dkim2_sig(conn)
	return mt.eom_check(conn, MT_HDRINSERT, "DKIM2-Signature") or
	       mt.eom_check(conn, MT_HDRADD, "DKIM2-Signature")
end

function count_snapshots()
	local p = io.popen("find '" .. snapdir .. "' -type f 2>/dev/null | wc -l")
	local n = tonumber(p:read("*a")) or 0
	p:close()
	return n
end

-- Fixed, byte-identical covered headers shared by every hop of message 1 so the
-- reconstructed inbound copy hashes the same as what the daemon first signed.
FROM = { "From", "Alice <alice@example.com>" }
DATE = { "Date", "Tue, 22 Dec 2009 13:04:12 -0800" }
SUBJ = { "Subject", "modifying resign test" }
BODY = "Original body line one.\r\n"
FOOTER = "-- \r\nMailing list footer\r\n"

ALICE = "<alice@example.com>"
LIST  = "<list@example.com>"
RCPT  = "<rcpt@example.org>"

-- ── step 1: originate (daemon signs a fresh message) ─────────────────────────
mt.echo("*** step 1: originate")
conn = txn("127.0.0.1", "resign-1", ALICE, RCPT, { FROM, DATE, SUBJ }, BODY)
if not added_dkim2_sig(conn) then
	error("step 1: daemon did not add a DKIM2-Signature")
end
sig1 = mt.getheader(conn, "DKIM2-Signature", 0)
mi1 = mt.getheader(conn, "Message-Instance", 0)
if sig1 == nil or string.find(sig1, "i=1;", 1, true) == nil then
	error("step 1: originated DKIM2-Signature is not i=1")
end
if mi1 == nil or string.find(mi1, "m=1;", 1, true) == nil then
	error("step 1: originated Message-Instance is not m=1")
end
mt.disconnect(conn)

-- ── step 2: inbound verify + snapshot (external: verify only) ─────────────────
mt.echo("*** step 2: inbound verify + snapshot")
conn = txn("192.0.2.1", "resign-2", ALICE, RCPT,
           { FROM, DATE, SUBJ,
             { "Message-Instance", mi1 }, { "DKIM2-Signature", sig1 } }, BODY)
-- an external inbound message is verified, not re-signed
if added_dkim2_sig(conn) then
	error("step 2: daemon signed an external inbound message")
end
mt.disconnect(conn)
-- the verified chain must have left a snapshot behind
if count_snapshots() < 1 then
	error("step 2: no snapshot was written for the verified chain")
end

-- ── step 3: modify + re-sign (internal: diff against snapshot) ────────────────
mt.echo("*** step 3: modify + re-sign")
conn = txn("127.0.0.1", "resign-3", LIST, RCPT,
           { FROM, DATE, SUBJ,
             { "Message-Instance", mi1 }, { "DKIM2-Signature", sig1 } },
           BODY .. FOOTER)
if not added_dkim2_sig(conn) then
	error("step 3: daemon did not re-sign the modified message")
end
sig2 = mt.getheader(conn, "DKIM2-Signature", 0)
mi2 = mt.getheader(conn, "Message-Instance", 0)
if sig2 == nil or string.find(sig2, "i=2;", 1, true) == nil then
	error("step 3: re-signed DKIM2-Signature is not i=2")
end
if mi2 == nil or string.find(mi2, "m=2;", 1, true) == nil then
	error("step 3: re-signed Message-Instance is not m=2")
end
-- a modifying re-sign must record a reverting recipe on the new instance
if string.find(mi2, "r=", 1, true) == nil then
	error("step 3: re-signed Message-Instance carries no recipe (r=)")
end
mt.disconnect(conn)

-- ── step 4: the re-signed two-hop chain verifies offline ─────────────────────
mt.echo("*** step 4: verify the re-signed chain")
f = io.open(m2file, "w")
if f == nil then
	error("step 4: cannot open scratch file " .. m2file)
end
f:write("Message-Instance: " .. mi2 .. "\r\n")
f:write("DKIM2-Signature: " .. sig2 .. "\r\n")
f:write("Message-Instance: " .. mi1 .. "\r\n")
f:write("DKIM2-Signature: " .. sig1 .. "\r\n")
f:write(FROM[1] .. ": " .. FROM[2] .. "\r\n")
f:write(DATE[1] .. ": " .. DATE[2] .. "\r\n")
f:write(SUBJ[1] .. ": " .. SUBJ[2] .. "\r\n")
f:write("\r\n")
f:write(BODY .. FOOTER)
f:close()

cmd = "'" .. verifycli .. "' --mail-from '" .. LIST .. "'" ..
      " --rcpt-to '" .. RCPT .. "' --dns-fixture pubkeys < '" .. m2file .. "'"
p = io.popen(cmd)
out = p:read("*a")
p:close()
if string.find(out, "PASS", 1, true) == nil then
	error("step 4: re-signed chain did not verify PASS (got: " ..
	      (out or "") .. ")")
end

-- ── step 5: modified message with no snapshot is delivered unsigned ──────────
mt.echo("*** step 5: no snapshot => unsigned")
-- originate a *different* message (distinct subject => distinct top instance)
-- that we deliberately never snapshot.
SUBJ2 = { "Subject", "second message, never snapshotted" }
BODY2 = "Second message body.\r\n"
conn = txn("127.0.0.1", "resign-5a", ALICE, RCPT, { FROM, DATE, SUBJ2 }, BODY2)
if not added_dkim2_sig(conn) then
	error("step 5a: daemon did not originate the second message")
end
sig3 = mt.getheader(conn, "DKIM2-Signature", 0)
mi3 = mt.getheader(conn, "Message-Instance", 0)
mt.disconnect(conn)

-- re-inject it modified; with no snapshot the daemon cannot build a recipe and
-- must deliver it unsigned rather than vouch for an unreconstructable chain.
conn = txn("127.0.0.1", "resign-5b", LIST, RCPT,
           { FROM, DATE, SUBJ2,
             { "Message-Instance", mi3 }, { "DKIM2-Signature", sig3 } },
           BODY2 .. FOOTER)
if added_dkim2_sig(conn) then
	error("step 5b: daemon signed a modified message with no snapshot")
end
mt.disconnect(conn)

-- ── cleanup ──────────────────────────────────────────────────────────────────
os.remove(m2file)
os.execute("rm -rf '" .. snapdir .. "'")

mt.echo("*** DKIM2-core modifying re-sign integration test: OK")
