/home/builder/projects/opendkim-ng/opendkim/opendkim.c: In function ‘mlfi_eom’:
/home/builder/projects/opendkim-ng/opendkim/opendkim.c:12408:47: warning: ‘%s’ directive output may be truncated writing up to 4096 bytes into a region of size 4073 [-Wformat-truncation=]
12408 |                                          "%s: %s",
      |                                               ^~
In file included from /usr/include/stdio.h:970,
                 from /home/builder/projects/opendkim-ng/opendkim/opendkim.c:42:
In function ‘snprintf’,
    inlined from ‘mlfi_eom’ at /home/builder/projects/opendkim-ng/opendkim/opendkim.c:12407:5:
/usr/include/x86_64-linux-gnu/bits/stdio2.h:68:10: note: ‘__builtin___snprintf_chk’ output between 25 and 4121 bytes into a destination of size 4097
   68 |   return __builtin___snprintf_chk (__s, __n, __USE_FORTIFY_LEVEL - 1,
      |          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   69 |                                    __glibc_objsize (__s), __fmt,
      |                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   70 |                                    __va_arg_pack ());
      |                                    ~~~~~~~~~~~~~~~~~

========================

Audit unported autotools feature checks (like HAVE_REALPATH)
Audit opendkim-db.c for more dead code

========================

Configure COPR for RPM builds (Fedora/RHEL/CentOS/AlmaLinux).
Set up a .spec file and wire the CI to dispatch to COPR on tag push,
similar to the Debian apt dispatch step.

========================

Go through all the issues at https://github.com/trusteddomainproject/OpenDKIM/issues and see if any apply to our version.

Also look at distro's (Fedora, OpenSUSE, Debian, Gentoo, e.a.) that might have created their own patches. Something useful for us?

Debian (debian/ package config as well as patches):
https://salsa.debian.org/debian/opendkim/-/tree/master/debian?ref_type=heads

https://codeberg.org/gentoo/gentoo/src/branch/master/mail-filter/opendkim/files
For OpenRC:
https://codeberg.org/gentoo/gentoo/src/branch/master/mail-filter/opendkim/files/opendkim-2.10.3-openrc.patch

https://www.freshports.org/mail/opendkim/
https://codeberg.org/FreeBSD/freebsd-ports/src/branch/main/mail/opendkim/files
FreeBSD rc.conf:
https://codeberg.org/FreeBSD/freebsd-ports/src/branch/main/mail/opendkim/files/milter-opendkim.in

https://github.com/openbsd/ports/tree/master/mail/opendkim
OpenBSD rc.conf
https://github.com/openbsd/ports/blob/master/mail/opendkim/pkg/opendkim.rc
