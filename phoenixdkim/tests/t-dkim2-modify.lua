-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- DKIM2 deliberate-modifier test
--
-- Drives the milter with DKIM2Mode=sign, a configured Subject tag and body
-- footer, and an inbound message that already carries a one-hop DKIM2 chain.
-- The filter must rewrite the Subject and body on the wire and record the
-- change as a modifying re-sign: a new Message-Instance (m=2) carrying a recipe
-- plus a new DKIM2-Signature (i=2).

mt.echo("*** DKIM2 deliberate-modifier test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-dkim2-modify.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

mt.startfilter(binpath .. "/phoenixdkim", "-x", "t-dkim2-modify.conf", "-p", sock)

conn = mt.connect(sock, 40, 0.25)
if conn == nil then
	error("mt.connect() failed")
end

if mt.conninfo(conn, "localhost", "127.0.0.1") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

mt.macro(conn, SMFIC_MAIL, "i", "t-dkim2-modify")
if mt.mailfrom(conn, "<user@example.com>") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

if mt.rcptto(conn, "<rcpt@example.org>") ~= nil then
	error("mt.rcptto() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.rcptto() unexpected reply")
end

-- ordinary content headers
if mt.header(conn, "From", "user@example.com") ~= nil then
	error("mt.header(From) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(From) unexpected reply")
end
if mt.header(conn, "Date", "Tue, 22 Dec 2009 13:04:12 -0800") ~= nil then
	error("mt.header(Date) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Date) unexpected reply")
end
if mt.header(conn, "Subject", "hello") ~= nil then
	error("mt.header(Subject) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Subject) unexpected reply")
end

-- a one-hop DKIM2 chain already on the message (so this is a re-sign, and a
-- recipe-bearing m=2 instance is added rather than a fresh m=1)
if mt.header(conn, "Message-Instance",
             "m=1; h=sha256:aGVhZGVy:Ym9keQ==;") ~= nil then
	error("mt.header(Message-Instance) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Message-Instance) unexpected reply")
end
if mt.header(conn, "DKIM2-Signature",
             "i=1; m=1; t=1700000000; mf=PHVzZXJAZXhhbXBsZS5jb20+; " ..
             "rt=PHJjcHRAZXhhbXBsZS5vcmc+; d=example.com; " ..
             "s=test:rsa-sha256:AAAA;") ~= nil then
	error("mt.header(DKIM2-Signature) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(DKIM2-Signature) unexpected reply")
end

if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eoh() unexpected reply")
end

if mt.bodystring(conn, "Original body line\r\n") ~= nil then
	error("mt.bodystring() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.bodystring() unexpected reply")
end

if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

-- the Subject must have been rewritten with the tag
if not mt.eom_check(conn, MT_HDRCHANGE, "Subject") then
	error("Subject was not changed")
end

-- the body must have been replaced (footer appended)
if not mt.eom_check(conn, MT_BODYCHANGE) then
	error("body was not changed")
end

-- a new DKIM2-Signature (i=2) must have been inserted
if not mt.eom_check(conn, MT_HDRINSERT, "DKIM2-Signature") and
   not mt.eom_check(conn, MT_HDRADD, "DKIM2-Signature") then
	error("no DKIM2-Signature added")
end

-- a new modifying Message-Instance (m=2, with a recipe) must have been inserted
if not mt.eom_check(conn, MT_HDRINSERT, "Message-Instance") and
   not mt.eom_check(conn, MT_HDRADD, "Message-Instance") then
	error("no Message-Instance added")
end

sig = mt.getheader(conn, "DKIM2-Signature", 0)
if string.find(sig, "i=2;", 1, true) == nil then
	error("new DKIM2-Signature has wrong i= value")
end

mi = mt.getheader(conn, "Message-Instance", 0)
if string.find(mi, "m=2;", 1, true) == nil then
	error("new Message-Instance has wrong m= value")
end
if string.find(mi, "r=", 1, true) == nil then
	error("new Message-Instance carries no recipe")
end

mt.disconnect(conn)
