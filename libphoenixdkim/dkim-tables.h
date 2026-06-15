/*
**  Copyright (c) 2005-2008 Sendmail, Inc. and its suppliers.
**    All rights reserved.
**
**  Copyright (c) 2009, 2010, 2012, 2014, The Trusted Domain Project.
**    All rights reserved.
*/

#ifndef _DKIM_TABLES_H_
#define _DKIM_TABLES_H_


/* structures */
struct nametable
{
	const char *	tbl_name;	/* name */
	const int	tbl_code;	/* code */
};

/*
**  These name<->code lookup tables are shared across the library and the
**  phoenixdkim daemon, so they must have external linkage (they cannot be
**  static).  Their C identifiers are short and generic, however, and a shared
**  library must not export bare names like "results" or "hashes" into the
**  global dynamic symbol table, where they could clash with other libraries.
**
**  The __asm__ labels give each one a dkim_-prefixed *exported* symbol name
**  without touching any of the use sites: every reference still spells the
**  identifier (e.g. "results") and the compiler emits the prefixed symbol.
**  The definitions in dkim-tables.c inherit the label from this declaration.
**  If you add a table here, give it a label too, and regenerate
**  debian/libphoenixdkim0.symbols.  __asm__ (not asm) keeps -pedantic-errors
**  happy.
*/
extern struct nametable *algorithms		__asm__("dkim_algorithms");
extern struct nametable *canonicalizations	__asm__("dkim_canonicalizations");
extern struct nametable *hashes			__asm__("dkim_hashes");
extern struct nametable *keyflags		__asm__("dkim_keyflags");
extern struct nametable *keyparams		__asm__("dkim_keyparams");
extern struct nametable *keytypes		__asm__("dkim_keytypes");
extern struct nametable *querytypes		__asm__("dkim_querytypes");
extern struct nametable *results		__asm__("dkim_results");
extern struct nametable *settypes		__asm__("dkim_settypes");
extern struct nametable *sigerrors		__asm__("dkim_sigerrors");
extern struct nametable *sigparams		__asm__("dkim_sigparams");

/* prototypes */
extern const char *dkim_code_to_name(struct nametable *tbl,
                                          const int code);
extern int dkim_name_to_code(struct nametable *tbl,
                                  const char *name);

#endif /* _DKIM_TABLES_H_ */
