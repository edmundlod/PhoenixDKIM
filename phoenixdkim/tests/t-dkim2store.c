/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-dkim2store.c -- offline unit tests for the DKIM2 modifying-resign snapshot
**  store (phoenixdkim-dkim2store.c).  The translation unit is #included directly
**  so the tests can also reach the static canon_mi()/key_hex() helpers and
**  confirm that a folded inbound MI value keys the same snapshot as its
**  unfolded outbound form.
*/

#include "phoenixdkim-dkim2store.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void
ck_true(const char *name, int cond)
{
	printf("%-44s %s\n", name, cond ? "OK" : "*** FAIL ***");
	if (!cond)
		failures++;
}

int
main(void)
{
	char tmpl[] = "/tmp/t-dkim2store.XXXXXX";
	char *dir = mkdtemp(tmpl);
	const char *mi = "m=2; h=sha256:AAAA:BBBB;";
	/* same value, folded across two lines with leading WSP -- must key alike */
	const char *mi_folded = " m=2;\r\n  h=sha256:AAAA:BBBB;";
	const char *data = "Message-Instance: m=2; h=sha256:AAAA:BBBB;\r\n"
	                   "From: a@b\r\n\r\nhello\r\n";
	char rmcmd[256];
	char *got;
	size_t gotlen = 0;
	char hex1[65], hex2[65];
	char *c;

	if (dir == NULL)
	{
		fprintf(stderr, "mkdtemp failed\n");
		return 2;
	}

	/* canon_mi collapses folding/whitespace and trims */
	c = canon_mi("  m=1;\r\n\th=sha256:x:y;  ");
	ck_true("canon collapses fold + trims",
	        c != NULL && strcmp(c, "m=1; h=sha256:x:y;") == 0);
	free(c);

	/* folded and unfolded forms derive the same key */
	ck_true("key_hex folded == unfolded",
	        key_hex(mi, hex1) == 0 && key_hex(mi_folded, hex2) == 0 &&
	        strcmp(hex1, hex2) == 0);

	/* put creates the hashed shard subdir inside an existing base, but never
	** the base itself: a put into a non-existent base fails */
	ck_true("put into missing base fails",
	        dkimf_dkim2_store_put("/nonexistent/phoenixdkim-snap", mi, data,
	                              strlen(data)) != 0);

	/* put then get round-trips the exact bytes */
	ck_true("put succeeds",
	        dkimf_dkim2_store_put(dir, mi, data, strlen(data)) == 0);
	got = dkimf_dkim2_store_get(dir, mi, &gotlen);
	ck_true("get round-trips bytes",
	        got != NULL && gotlen == strlen(data) &&
	        memcmp(got, data, gotlen) == 0);
	free(got);

	/* the folded form fetches the same snapshot */
	got = dkimf_dkim2_store_get(dir, mi_folded, &gotlen);
	ck_true("get via folded key finds it",
	        got != NULL && gotlen == strlen(data));
	free(got);

	/* a miss returns NULL */
	got = dkimf_dkim2_store_get(dir, "m=99; h=sha256:Z:Z;", &gotlen);
	ck_true("get miss returns NULL", got == NULL);
	free(got);

	/* remove deletes it; a second remove reports nothing to do */
	ck_true("remove succeeds", dkimf_dkim2_store_remove(dir, mi) == 0);
	ck_true("remove again is a no-op", dkimf_dkim2_store_remove(dir, mi) != 0);
	got = dkimf_dkim2_store_get(dir, mi, &gotlen);
	ck_true("get after remove returns NULL", got == NULL);
	free(got);

	(void) snprintf(rmcmd, sizeof rmcmd, "rm -rf '%s'", dir);
	if (system(rmcmd) != 0)
		fprintf(stderr, "warning: cleanup of %s failed\n", dir);

	printf("%s: %d failure(s)\n", failures == 0 ? "PASS" : "FAIL", failures);
	return failures == 0 ? 0 : 1;
}
