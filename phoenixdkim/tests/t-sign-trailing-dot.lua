-- Copyright (c) 2026 PhoenixDKIM contributors
--   All rights reserved.

-- trailing-dot From: domain signing test
--
-- A From: header whose domain carries a trailing root-label dot
-- ("user@example.com.") names the same domain as "user@example.com"
-- (RFC 5322 3.2.3 disallows the dot in an addr-spec; real mailers
-- normalize it away).  The milter must strip that dot before matching
-- the signing domain, otherwise it fails to match the configured
-- Domain (no signature) or emits a malformed "d=example.com." value.
-- This guards the strip added next to the mctx_domain lowercase.

mt.echo("*** trailing-dot From: domain signing test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-sign-trailing-dot.sock"
end

binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x", "t-sign-trailing-dot.conf",
               "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn == nil then
	error("mt.connect() failed")
end

-- send connection information
-- mt.negotiate() is called implicitly
if mt.conninfo(conn, "localhost", "127.0.0.1") ~= nil then
	error("mt.conninfo() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.conninfo() unexpected reply")
end

-- send envelope macros and sender data
-- mt.helo() is called implicitly
mt.macro(conn, SMFIC_MAIL, "i", "t-sign-trailing-dot")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
-- note the trailing dot on the From: domain
if mt.header(conn, "From", "user@example.com.") ~= nil then
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
if mt.header(conn, "Subject", "Signing test") ~= nil then
	error("mt.header(Subject) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(Subject) unexpected reply")
end

-- send EOH
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.eoh() unexpected reply")
end

-- send body
if mt.bodystring(conn, "This is a test!\r\n") ~= nil then
	error("mt.bodystring() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.bodystring() unexpected reply")
end

-- end of message; let the filter react
if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

-- a signature must have been added: without the dot strip the From:
-- domain "example.com." does not match the configured Domain and
-- nothing is signed
if not mt.eom_check(conn, MT_HDRINSERT, "DKIM-Signature") and
   not mt.eom_check(conn, MT_HDRADD, "DKIM-Signature") then
	error("no signature added (trailing-dot domain not normalized?)")
end

-- confirm the signing domain dropped the trailing dot
sig = mt.getheader(conn, "DKIM-Signature", 0)
if string.find(sig, "d=example.com.", 1, true) ~= nil then
	error("d= retained the trailing root-label dot")
end
if string.find(sig, "d=example.com;", 1, true) == nil then
	error("signature has wrong d= value")
end
if string.find(sig, "s=test", 1, true) == nil then
	error("signature has wrong s= value")
end

mt.disconnect(conn)
