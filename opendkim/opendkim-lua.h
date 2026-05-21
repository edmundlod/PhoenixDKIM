/*
**  Copyright (c) 2009-2012, The Trusted Domain Project.  All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
*/

#ifndef _OPENDKIM_LUA_H_
#define _OPENDKIM_LUA_H_

/* system includes */
#include <sys/types.h>

/* types */
/*
**  lrs_error is a tagged-union pointer.  It is either:
**    - NULL,
**    - a heap string strdup'd from lua_tostring() (set by the hooks
**      in opendkim-lua.c), which the consumer must free, OR
**    - a string literal assigned by the consumer when the hook left
**      it NULL (in which case the consumer sets a local dofree=FALSE
**      flag to skip free()).
**  The const here reflects what every reader does; the rare
**  free() site is gated by dofree and casts away const.
*/

struct dkimf_lua_script_result
{
	int		lrs_rcount;
	const char *	lrs_error;
	char **		lrs_results;
};

struct dkimf_lua_gc_item
{
	int				gci_type;
	void *				gci_item;
	struct dkimf_lua_gc_item *	gci_next;
};

struct dkimf_lua_gc
{
	struct dkimf_lua_gc_item *	gc_head;
	struct dkimf_lua_gc_item *	gc_tail;
};

/* macros */
#define	DKIMF_GC		"_DKIMF_GC"
#define	DKIMF_LUA_GC_DB		1

/* prototypes */
extern int dkimf_lua_db_hook __P((const char *, size_t, const char *,
                                  struct dkimf_lua_script_result *,
                                  void **, size_t *));
extern int dkimf_lua_final_hook __P((void *, const char *, size_t,
                                     const char *,
                                     struct dkimf_lua_script_result *,
                                     void **, size_t *));
extern void dkimf_lua_gc_add __P((struct dkimf_lua_gc *g, void *, int));
extern void dkimf_lua_gc_cleanup __P((struct dkimf_lua_gc *));
extern void dkimf_lua_gc_remove __P((struct dkimf_lua_gc *, void *));
extern int dkimf_lua_screen_hook __P((void *, const char *, size_t,
                                      const char *,
                                      struct dkimf_lua_script_result *,
                                      void **, size_t *));
extern int dkimf_lua_setup_hook __P((void *, const char *, size_t,
                                     const char *,
                                     struct dkimf_lua_script_result *,
                                     void **, size_t *));

#endif /* _OPENDKIM_LUA_H_ */
