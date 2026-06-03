-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- StrictSignAlgorithm, matching declaration: must still sign
--
-- The KeyTable declares rsa-sha256 for an RSA key.  This agrees with the key,
-- so StrictSignAlgorithm must not interfere: the message signs normally.
-- This is the complement of t-sign-strict-algmismatch and guards against the
-- option breaking legitimate configurations.

mt.echo("*** StrictSignAlgorithm matching-declaration signing test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-sign-strict-algmatch.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x",
               "t-sign-strict-algmatch.conf", "-p", sock)

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
mt.macro(conn, SMFIC_MAIL, "i", "t-sign-strict-algmatch")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers
-- mt.rcptto() is called implicitly
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

-- end of message; the filter must accept and sign
if mt.eom(conn) ~= nil then
	error("mt.eom() failed")
end
if mt.getreply(conn) ~= SMFIR_ACCEPT then
	error("mt.eom() unexpected reply")
end

-- a signature must have been added, with the key-derived algorithm
if not mt.eom_check(conn, MT_HDRINSERT, "DKIM-Signature") and
   not mt.eom_check(conn, MT_HDRADD, "DKIM-Signature") then
	error("no signature added")
end

sig = mt.getheader(conn, "DKIM-Signature", 0)
if string.find(sig, "a=rsa-sha256", 1, true) == nil then
	error("signature has wrong a= value")
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error("signature has wrong d= value")
end
if string.find(sig, "s=test", 1, true) == nil then
	error("signature has wrong s= value")
end

mt.disconnect(conn)
