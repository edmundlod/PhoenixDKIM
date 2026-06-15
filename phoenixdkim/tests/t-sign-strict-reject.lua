-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- strict-header signing reject test
--
-- With StrictHeaders enabled and On-SignatureError set to reject, a message
-- presented for signing that carries a duplicate From: field (an RFC 5322
-- violation and a known spoofing vector) must be rejected at end-of-headers
-- rather than delivered unsigned.  The verifying-side counterpart
-- (t-verify-double-from) confirms the opposite disposition: accept + record.

mt.echo("*** strict-header signing reject test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-sign-strict-reject.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x", "t-sign-strict-reject.conf", "-p", sock)

-- try to connect to it
conn = mt.connect(sock, 40, 0.25)
if conn == nil then
	error("mt.connect() failed")
end

mt.set_timeout(300)

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
mt.macro(conn, SMFIC_MAIL, "i", "t-sign-strict-reject")
if mt.mailfrom(conn, "user@example.com") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send headers, including a duplicate From: (the RFC 5322 violation)
-- mt.rcptto() is called implicitly
if mt.header(conn, "From", "user@example.com") ~= nil then
	error("mt.header(From) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(From) unexpected reply")
end
if mt.header(conn, "From", "user@example.net") ~= nil then
	error("mt.header(From #2) failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.header(From #2) unexpected reply")
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

-- end of headers: the strict-header check fires here, and signing must be
-- refused with an SMTP reply code rather than continuing
if mt.eoh(conn) ~= nil then
	error("mt.eoh() failed")
end
if mt.getreply(conn) ~= SMFIR_REPLYCODE then
	error("mt.eoh() unexpected reply - expected REPLYCODE (reject)")
end

mt.disconnect(conn)
