# Copyright (c) 2010-2014, The Trusted Domain Project.  All rights reserved.
#

if DEBUG
AM_CFLAGS = -g
endif

sbin_PROGRAMS = opendkim-genzone opendkim-testkey opendkim-testmsg

dist_sbin_SCRIPTS = opendkim-genkey
dist_doc_DATA = opendkim.conf.sample opendkim.conf.simple \
	opendkim.conf.simple-verify README.SQL

if BUILD_FILTER
sbin_PROGRAMS += opendkim
opendkim_SOURCES = opendkim.c opendkim.h opendkim-ar.c opendkim-ar.h opendkim-arf.c opendkim-arf.h opendkim-config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-dns.c opendkim-dns.h opendkim-lua.c opendkim-lua.h config.c config.h flowrate.c flowrate.h test.c test.h util.c util.h
opendkim_CC = $(PTHREAD_CC)
opendkim_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(LIBMILTER_LIBDIRS) $(PTHREAD_CFLAGS) $(COV_LDFLAGS)
opendkim_LDADD = ../libopendkim/libopendkim.la $(LIBMILTER_LIBS) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(COV_LIBADD) $(LIBRESOLV)
if USE_DB_OPENDKIM
opendkim_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_LDFLAGS += $(LIBODBX_LDFLAGS)
opendkim_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_LDADD += $(LIBODBX_LIBS) $(LIBDL_LIBS)
endif
if USE_LIBMEMCACHED
opendkim_CPPFLAGS += $(LIBMEMCACHED_INCDIRS)
opendkim_LDFLAGS += $(LIBMEMCACHED_LIBDIRS)
opendkim_LDADD += $(LIBMEMCACHED_LIBS)
endif
if LUA
SUBDIRS=tests
opendkim_CPPFLAGS += $(LIBLUA_INCDIRS) -DDKIMF_LUA_CONTEXT_HOOKS
opendkim_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_LDADD += $(LIBLUA_LIBS)
endif
if USE_SASL
opendkim_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_LDADD += $(OPENLDAP_LIBS)
endif
if USE_UNBOUND
opendkim_CPPFLAGS += $(LIBUNBOUND_INCDIRS)
opendkim_LDFLAGS += $(LIBUNBOUND_LIBDIRS) $(LIBLDNS_LIBDIRS) $(LIBEVENT_LIBDIRS)
opendkim_LDADD += $(LIBUNBOUND_LIBS) $(LIBLDNS_LIBS) $(LIBEVENT_LIBS)
endif
if VBR
opendkim_CPPFLAGS += -I$(srcdir)/../libvbr
opendkim_LDADD += ../libvbr/libvbr.la
endif
if RBL
opendkim_CPPFLAGS += -I$(srcdir)/../librbl
opendkim_LDADD += ../librbl/librbl.la
endif
if REPUTE
opendkim_CPPFLAGS += -I$(srcdir)/../reputation
opendkim_LDADD += ../reputation/librepute.la
endif
if USE_MDB
opendkim_CPPFLAGS += $(LIBMDB_CPPFLAGS)
opendkim_LDADD += $(LIBMDB_LIBS)
endif
if ERLANG
opendkim_CPPFLAGS += $(LIBERL_INCDIRS)
opendkim_LDFLAGS += $(LIBERL_LIBDIRS)
opendkim_LDADD += $(LIBERL_LIBS)
endif
if REPRRD
opendkim_CPPFLAGS += -I$(srcdir)/../reprrd
opendkim_LDADD += ../reprrd/libreprrd.la
endif

opendkim_CPPFLAGS += $(LIBMILTER_INCDIRS)
endif

opendkim_testkey_CC = $(PTHREAD_CC)
opendkim_testkey_SOURCES = config.c config.h opendkim-crypto.c opendkim-crypto.h opendkim-db.c opendkim-db.h opendkim-dns.c opendkim-dns.h opendkim-lua.c opendkim-lua.h opendkim-testkey.c util.c util.h $(srcdir)/../libopendkim/dkim.h $(srcdir)/../libopendkim/dkim-test.h
opendkim_testkey_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testkey_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS) $(PTHREAD_CFLAGS)
opendkim_testkey_LDFLAGS = $(LIBCRYPTO_LIBDIRS) $(COV_LDFLAGS) $(PTHREAD_CFLAGS)
opendkim_testkey_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV) $(COV_LIBADD) $(PTHREAD_LIBS)
if LUA
opendkim_testkey_CPPFLAGS += $(LIBLUA_INCDIRS) $(LIBMILTER_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_testkey_LDADD += $(LIBLUA_LIBS)
endif
if USE_DB_OPENDKIM
opendkim_testkey_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_testkey_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_testkey_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_testkey_LDFLAGS += $(LIBODBX_LDFLAGS)
opendkim_testkey_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_testkey_LDADD += $(LIBODBX_LIBS) $(LIBDL_LIBS)
endif
if USE_LIBMEMCACHED
opendkim_testkey_CPPFLAGS += $(LIBMEMCACHED_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBMEMCACHED_LIBDIRS)
opendkim_testkey_LDADD += $(LIBMEMCACHED_LIBS)
endif
if USE_LDAP
opendkim_testkey_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_testkey_LDADD += $(OPENLDAP_LIBS)
endif
if USE_SASL
opendkim_testkey_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_UNBOUND
opendkim_testkey_CPPFLAGS += $(LIBUNBOUND_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBUNBOUND_LIBDIRS) $(LIBLDNS_LIBDIRS)
opendkim_testkey_LDADD += $(LIBUNBOUND_LIBS) $(LIBLDNS_LIBS)
endif
if RBL
opendkim_testkey_CPPFLAGS += -I$(srcdir)/../librbl
opendkim_testkey_LDADD += ../librbl/librbl.la
endif
if VBR
opendkim_testkey_CPPFLAGS += -I$(srcdir)/../libvbr
opendkim_testkey_LDADD += ../libvbr/libvbr.la
endif
if REPUTE
opendkim_testkey_CPPFLAGS += -I$(srcdir)/../reputation
opendkim_testkey_LDADD += ../reputation/librepute.la
endif
if USE_MDB
opendkim_testkey_CPPFLAGS += $(LIBMDB_CPPFLAGS)
opendkim_testkey_CFLAGS += $(LIBMDB_CFLAGS)
opendkim_testkey_LDADD += $(LIBMDB_LIBS)
endif
if ERLANG
opendkim_testkey_CPPFLAGS += $(LIBERL_INCDIRS)
opendkim_testkey_LDFLAGS += $(LIBERL_LIBDIRS)
opendkim_testkey_LDADD += $(LIBERL_LIBS)
endif

opendkim_testmsg_CC = $(PTHREAD_CC)
opendkim_testmsg_SOURCES = opendkim-testmsg.c
opendkim_testmsg_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_testmsg_CFLAGS = $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS) $(PTHREAD_CFLAGS)
opendkim_testmsg_LDFLAGS = $(COV_LDFLAGS) $(PTHREAD_CFLAGS)
opendkim_testmsg_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(LIBRESOLV) $(COV_LIBADD) $(PTHREAD_LIBS)

opendkim_genzone_CC = $(PTHREAD_CC)
opendkim_genzone_SOURCES = config.c config.h opendkim-db.c opendkim-db.h opendkim-genzone.c opendkim-lua.c util.c util.h
opendkim_genzone_CPPFLAGS = -I$(srcdir)/../libopendkim $(LIBCRYPTO_CPPFLAGS)
opendkim_genzone_CFLAGS = $(PTHREAD_CFLAGS) $(LIBCRYPTO_CFLAGS) $(COV_CFLAGS)
opendkim_genzone_LDFLAGS = $(COV_LDFLAGS) $(LIBCRYPTO_LIBDIRS) $(PTHREAD_CFLAGS)
opendkim_genzone_LDADD = ../libopendkim/libopendkim.la $(LIBCRYPTO_LIBS) $(COV_LIBADD) $(PTHREAD_LIBS)
if USE_DB_OPENDKIM
opendkim_genzone_CPPFLAGS += $(LIBDB_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBDB_LIBDIRS)
opendkim_genzone_LDADD += $(LIBDB_LIBS)
endif
if USE_ODBX
opendkim_genzone_CPPFLAGS += $(LIBODBX_CPPFLAGS)
opendkim_genzone_LDFLAGS += $(LIBODBX_LDFLAGS)
opendkim_genzone_CFLAGS += $(LIBODBX_CFLAGS)
opendkim_genzone_LDADD += $(LIBODBX_LIBS) $(LIBDL_LIBS)
endif
if USE_LIBMEMCACHED
opendkim_genzone_CPPFLAGS += $(LIBMEMCACHED_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBMEMCACHED_LIBDIRS)
opendkim_genzone_LDADD += $(LIBMEMCACHED_LIBS)
endif
if USE_SASL
opendkim_genzone_CPPFLAGS += $(SASL_CPPFLAGS)
endif
if USE_LDAP
opendkim_genzone_CPPFLAGS += $(OPENLDAP_CPPFLAGS)
opendkim_genzone_LDADD += $(OPENLDAP_LIBS)
endif
if LUA
opendkim_genzone_CPPFLAGS += $(LIBLUA_INCDIRS) $(LIBMILTER_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBLUA_LIBDIRS)
opendkim_genzone_LDADD += $(LIBLUA_LIBS)
endif
if REPUTE
opendkim_genzone_CPPFLAGS += -I$(srcdir)/../reputation
opendkim_genzone_LDADD += ../reputation/librepute.la
endif
if USE_MDB
opendkim_genzone_CPPFLAGS += $(LIBMDB_CPPFLAGS)
opendkim_genzone_CFLAGS += $(LIBMDB_CFLAGS)
opendkim_genzone_LDADD += $(LIBMDB_LIBS)
endif
if ERLANG
opendkim_genzone_CPPFLAGS += $(LIBERL_INCDIRS)
opendkim_genzone_LDFLAGS += $(LIBERL_LIBDIRS)
opendkim_genzone_LDADD += $(LIBERL_LIBS)
endif

if LUA
dist_doc_DATA += \
        setup.lua.sample \
	screen.lua.sample \
	final.lua.sample
endif

man_MANS = opendkim-genkey.8 opendkim-genzone.8 opendkim-testkey.8 \
	opendkim-testmsg.8
if BUILD_FILTER
man_MANS += opendkim.conf.5 opendkim.8
if LUA
man_MANS += opendkim-lua.3
endif
endif
