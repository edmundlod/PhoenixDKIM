/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-parsers.c -- offline unit tests for the curl-backend parsers:
**  dkimf_db_vault_extract(), dkimf_db_http_buildurl(), dkimf_db_http_safe().
**
**  These functions are static in opendkim-db.c, so we #include the
**  translation unit directly instead of linking it.
*/

#include "opendkim-db.c"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void
ck_rc(const char *name, int got, int want)
{
	int ok = (got == want);
	printf("%-34s rc=%d %s\n", name, got, ok ? "OK" : "*** FAIL ***");
	if (!ok)
		failures++;
}

static void
ck_str(const char *name, int rc, const char *got, const char *want)
{
	int ok = (rc == 0) && (strcmp(got, want) == 0);
	printf("%-34s %s\n", name, ok ? "OK" : "*** FAIL ***");
	if (!ok)
		failures++;
}

static void
ck_true(const char *name, int cond)
{
	printf("%-34s %s\n", name, cond ? "OK" : "*** FAIL ***");
	if (!cond)
		failures++;
}

int
main(void)
{
	char o[4096];
	int rc;
	CURL *curl;

	/* ── dkimf_db_vault_extract: KVv1/KVv2, escapes, edges ─────────────── */
	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"private_key\":\"PEM\"}}}",
	                            "private_key", o, sizeof o);
	ck_str("vault kvv2 simple", rc, o, "PEM");

	rc = dkimf_db_vault_extract("{\"data\":{\"private_key\":\"K1\"}}",
	                            "private_key", o, sizeof o);
	ck_str("vault kvv1 simple", rc, o, "K1");

	rc = dkimf_db_vault_extract(
	         "{\"data\":{\"data\":{\"private_key\":\"L1\\nL2\\nL3\"}}}",
	         "private_key", o, sizeof o);
	ck_str("vault PEM newlines", rc, o, "L1\nL2\nL3");

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"a\\\"b\\\\c\\/d\"}}}",
	                            "k", o, sizeof o);
	ck_str("vault escapes \" \\ /", rc, o, "a\"b\\c/d");

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"\"}}}",
	                            "k", o, sizeof o);
	ck_str("vault empty value", rc, o, "");

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"u\\u0041v\"}}}",
	                            "k", o, sizeof o);
	ck_str("vault \\uXXXX skipped", rc, o, "uv");

	rc = dkimf_db_vault_extract(
	         "{\"data\":{\"data\":{\"private_key\":\"V\"},\"metadata\":{\"x\":1}}}",
	         "private_key", o, sizeof o);
	ck_str("vault metadata isolated", rc, o, "V");

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"other\":\"x\"}}}",
	                            "private_key", o, sizeof o);
	ck_rc("vault field missing", rc, -1);

	rc = dkimf_db_vault_extract("{\"errors\":[\"nope\"]}",
	                            "private_key", o, sizeof o);
	ck_rc("vault no envelope", rc, -1);

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"unterminated",
	                            "k", o, sizeof o);
	ck_rc("vault unterminated", rc, -1);

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"trail\\",
	                            "k", o, sizeof o);
	ck_rc("vault trailing backslash", rc, -1);

	rc = dkimf_db_vault_extract("{\"data\":{\"data\":{\"k\":\"toolong\"}}}",
	                            "k", o, 4);
	ck_rc("vault output overflow", rc, -1);

	/* ── dkimf_db_http_safe: SSRF allowlist ────────────────────────────── */
	ck_true("safe allows alnum._@-",
	        dkimf_db_http_safe("Ab9.dom_a-in@x", 14));
	ck_true("safe rejects slash",  !dkimf_db_http_safe("a/b", 3));
	ck_true("safe rejects space",  !dkimf_db_http_safe("a b", 3));
	ck_true("safe rejects query",  !dkimf_db_http_safe("a?b", 3));
	ck_true("safe rejects colon",  !dkimf_db_http_safe("a:b", 3));

	/* ── dkimf_db_http_buildurl: substitution + encoding ───────────────── */
	curl = curl_easy_init();
	if (curl == NULL)
	{
		fprintf(stderr, "curl_easy_init failed\n");
		return 1;
	}

	rc = dkimf_db_http_buildurl(curl, "https://h/dkim/{d}/{s}",
	                            "example.com:sel1", o, sizeof o);
	ck_str("url {d}/{s} expansion", rc, o,
	       "https://h/dkim/example.com/sel1");

	rc = dkimf_db_http_buildurl(curl, "https://h/k/{key}",
	                            "example.com", o, sizeof o);
	ck_str("url {key} expansion", rc, o, "https://h/k/example.com");

	rc = dkimf_db_http_buildurl(curl, "https://h/lookup",
	                            "example.com", o, sizeof o);
	ck_str("url no-token appends ?key", rc, o,
	       "https://h/lookup?key=example.com");

	/* '@' is allowlisted but still percent-encoded by curl_easy_escape */
	rc = dkimf_db_http_buildurl(curl, "https://h/{key}",
	                            "a@b.com", o, sizeof o);
	ck_str("url encodes @", rc, o, "https://h/a%40b.com");

	rc = dkimf_db_http_buildurl(curl, "https://h/{d}",
	                            "ev/il:s", o, sizeof o);
	ck_rc("url rejects unsafe {d}", rc, -1);

	rc = dkimf_db_http_buildurl(curl, "https://h/{key}",
	                            "example.com", o, 8);
	ck_rc("url rejects overflow", rc, -1);

	curl_easy_cleanup(curl);

	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;
}
