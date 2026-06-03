-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- StrictSignAlgorithm fail-closed test
--
-- The KeyTable declares ed25519-sha256 for an RSA key.  With
-- StrictSignAlgorithm enabled this contradiction must make signing fail
-- closed: the message is TEMPFAILed (deferred) rather than signed with the
-- key-derived algorithm.  Without the option the same setup would only warn
-- and sign; this test pins the strict behaviour.

mt.echo("*** StrictSignAlgorithm fail-closed test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-sign-strict-algmismatch.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x",
               "t-sign-strict-algmismatch.conf", "-p", sock)

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
mt.macro(conn, SMFIC_MAIL, "i", "t-sign-strict-algmismatch")
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

-- send EOH; the signing setup (and key load) happens here, so the strict
-- algorithm mismatch must fail closed at this point with a TEMPFAIL rather
-- than letting the message proceed to be signed
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_TEMPFAIL then
	error("StrictSignAlgorithm mismatch did not fail closed (expected TEMPFAIL)")
end

mt.disconnect(conn)
