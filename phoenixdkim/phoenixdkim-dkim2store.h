/*
**  Copyright (c) 2026, The PhoenixDKIM Authors.  All rights reserved.
**
**  phoenixdkim-dkim2store.h -- on-disk snapshot store for DKIM2 modifying
**                              re-signing.
**
**  A forwarder or mailing list that rewrites a message must record a reversible
**  recipe on the new Message-Instance it adds (draft-ietf-dkim-dkim2-spec
**  Sections 4 & 8.1).  Building that recipe needs the *pre-modification* bytes,
**  which a milter only has on the inbound transaction -- the rewrite (Mailman,
**  an alias, a gateway) and the outbound re-sign happen in a later, separate
**  SMTP transaction.  So on inbound (after the chain verifies) the full message
**  is snapshotted to disk keyed by its topmost Message-Instance value; on
**  outbound the signer fetches that snapshot and diffs it against the (possibly
**  modified) current message.  This mirrors Mail::DKIM2::MessageStore in the
**  dkim2wg/interop reference implementation.
**
**  The key is the SHA-256 (hex) of the canonicalized Message-Instance value, so
**  the inbound and outbound transactions agree on it even though the upstream MI
**  field may be folded differently; snapshots are filed under a 2-character
**  prefix subdirectory to avoid crowding a single directory.
*/

#ifndef PHOENIXDKIM_DKIM2STORE_H
#define PHOENIXDKIM_DKIM2STORE_H

#include "build-config.h"

#ifdef USE_DKIM2

#include <stddef.h>

/*
**  DKIMF_DKIM2_STORE_PUT -- store a message snapshot keyed by an MI value.
**
**  Parameters:
**  	dir -- the snapshot base directory (must already exist)
**  	mi_value -- the Message-Instance field value (folding tolerated)
**  	data -- the snapshot bytes (the full received message)
**  	len -- length of data in bytes
**
**  Return value:
**  	0 on success, -1 on error (bad argument, or a filesystem failure that is
**  	logged by the caller's context).  Writes via a temp file + rename so a
**  	reader never sees a partial snapshot.
*/
extern int dkimf_dkim2_store_put(const char *dir, const char *mi_value,
                                 const char *data, size_t len);

/*
**  DKIMF_DKIM2_STORE_GET -- fetch a snapshot previously stored under an MI value.
**
**  Parameters:
**  	dir -- the snapshot base directory
**  	mi_value -- the Message-Instance field value to look up
**  	lenout -- receives the snapshot length on success
**
**  Return value:
**  	A malloc'd buffer the caller frees, or NULL when no snapshot exists or on
**  	error.
*/
extern char *dkimf_dkim2_store_get(const char *dir, const char *mi_value,
                                   size_t *lenout);

/*
**  DKIMF_DKIM2_STORE_REMOVE -- delete the snapshot stored under an MI value.
**
**  Return value:
**  	0 if a snapshot was removed, -1 if none existed or on error.  A missing
**  	snapshot is not an error worth surfacing to the caller's flow.
*/
extern int dkimf_dkim2_store_remove(const char *dir, const char *mi_value);

#endif /* USE_DKIM2 */

#endif /* PHOENIXDKIM_DKIM2STORE_H */
