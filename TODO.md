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

Claude Code added comments when libmilter legacy API forced a -Wcast-qual.
The comment reads something like:

      12781 +  /* Legacy API constraint: smfiDesc::xxfi_name is char *. */
      12782 +  (char *) DKIMF_PRODUCT,  /* filter name */
      
More correct would be:

/*
**  libmilter's xxfi_name is char *; libmilter never writes through
**  this pointer — cast away const on our string literal.
*/

Look up all these comments, and change them in the same vein. It explains better why we cast, and why it is safe.
