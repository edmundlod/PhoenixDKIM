-- Copyright (c) 2026, PhoenixDKIM contributors.  All rights reserved.

-- DKIM2-core signing test
--
-- Drives the milter with DKIM2Mode=sign and confirms that a Message-Instance
-- and a DKIM2-Signature are inserted with the expected envelope-bound contents.

mt.echo("*** DKIM2-core signing test")

-- setup
if TESTSOCKET ~= nil then
	sock = TESTSOCKET
else
	sock = "unix:" .. mt.getcwd() .. "/t-dkim2-sign.sock"
end
binpath = os.getenv("PHOENIXDKIM_BINPATH") or (mt.getcwd() .. "/..")
if os.getenv("srcdir") ~= nil then
	mt.chdir(os.getenv("srcdir"))
end

-- try to start the filter
mt.startfilter(binpath .. "/phoenixdkim", "-x", "t-dkim2-sign.conf", "-p", sock)

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

-- send envelope sender (raw <path> form, as a real MTA delivers it)
mt.macro(conn, SMFIC_MAIL, "i", "t-dkim2-sign")
if mt.mailfrom(conn, "<user@example.com>") ~= nil then
	error("mt.mailfrom() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.mailfrom() unexpected reply")
end

-- send a recipient (bound into rt=)
if mt.rcptto(conn, "<rcpt@example.org>") ~= nil then
	error("mt.rcptto() failed")
end
if mt.getreply(conn) ~= SMFIR_CONTINUE then
	error("mt.rcptto() unexpected reply")
end

-- send headers
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
if mt.header(conn, "Subject", "DKIM2 signing test") ~= nil then
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
if mt.bodystring(conn, "This is a DKIM2 test!\r\n") ~= nil then
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

-- a DKIM2-Signature must have been inserted
if not mt.eom_check(conn, MT_HDRINSERT, "DKIM2-Signature") and
   not mt.eom_check(conn, MT_HDRADD, "DKIM2-Signature") then
	error("no DKIM2-Signature added")
end

-- the originator must also add a Message-Instance
if not mt.eom_check(conn, MT_HDRINSERT, "Message-Instance") and
   not mt.eom_check(conn, MT_HDRADD, "Message-Instance") then
	error("no Message-Instance added")
end

-- confirm signature properties
sig = mt.getheader(conn, "DKIM2-Signature", 0)
if string.find(sig, "i=1;", 1, true) == nil then
	error("DKIM2-Signature has wrong i= value")
end
if string.find(sig, "d=example.com", 1, true) == nil then
	error("DKIM2-Signature has wrong d= value")
end
if string.find(sig, "s=test:rsa-sha256:", 1, true) == nil then
	error("DKIM2-Signature has wrong s= value")
end

-- confirm Message-Instance properties
mi = mt.getheader(conn, "Message-Instance", 0)
if string.find(mi, "m=1;", 1, true) == nil then
	error("Message-Instance has wrong m= value")
end
if string.find(mi, "h=sha256:", 1, true) == nil then
	error("Message-Instance has wrong h= value")
end

mt.disconnect(conn)
