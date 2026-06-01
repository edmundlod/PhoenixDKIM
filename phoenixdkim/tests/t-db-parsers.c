/*
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
**
**  t-db-parsers.c -- offline unit tests for the curl-backend parsers:
**  dkimf_db_vault_extract(), dkimf_db_http_buildurl(), dkimf_db_http_safe().
**
**  These functions are static in opendkim-db.c, so we #include the
**  translation unit directly instead of linking it.
*/

#include "phoenixdkim-db.c"

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

	/* ── dkimf_db_vault_parse_selectors: array parsing + window filter ──── */
	{
		struct dkimf_vault_selector sels[DKIMF_DB_VAULT_MAXSELECTORS];
		unsigned int n;
		char big[8192];
		size_t off;
		unsigned int i;

		/* two selectors, both valid at now=2500 */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"KA\","
		         "\"valid_start\":1000,\"valid_end\":3000},"
		         "{\"selector\":\"b\",\"key\":\"KB\",\"valid_start\":2000}"
		         "]}}}",
		         "selectors", (time_t) 2500, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel two valid -> n=2",
		        rc == 0 && n == 2 &&
		        strcmp(sels[0].vs_selector, "a") == 0 &&
		        strcmp(sels[0].vs_key, "KA") == 0 &&
		        strcmp(sels[1].vs_selector, "b") == 0 &&
		        strcmp(sels[1].vs_key, "KB") == 0);

		/* valid_end is exclusive: now == valid_end -> expired */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"K\",\"valid_end\":3000}]}}}",
		         "selectors", (time_t) 3000, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel valid_end exclusive", rc == 0 && n == 0);

		/* now == valid_start -> valid (inclusive lower bound) */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"K\",\"valid_start\":2000}]}}}",
		         "selectors", (time_t) 2000, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel valid_start inclusive", rc == 0 && n == 1);

		/* not yet valid */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"K\",\"valid_start\":2000}]}}}",
		         "selectors", (time_t) 1000, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel not yet valid", rc == 0 && n == 0);

		/* unbounded (no window fields) -> always kept */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"K\"}]}}}",
		         "selectors", (time_t) 123, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel unbounded kept", rc == 0 && n == 1);

		/* expired excluded, valid kept (three entries, two in window) */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"KA\","
		         "\"valid_start\":1000,\"valid_end\":3000},"
		         "{\"selector\":\"b\",\"key\":\"KB\",\"valid_start\":2000},"
		         "{\"selector\":\"old\",\"key\":\"KO\","
		         "\"valid_start\":100,\"valid_end\":1500}]}}}",
		         "selectors", (time_t) 2500, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel expired excluded",
		        rc == 0 && n == 2 &&
		        strcmp(sels[0].vs_selector, "a") == 0 &&
		        strcmp(sels[1].vs_selector, "b") == 0);

		/* malformed entry (missing key) skipped, valid one kept */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"x\"},"
		         "{\"selector\":\"y\",\"key\":\"KY\"}]}}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel malformed skipped",
		        rc == 0 && n == 1 && strcmp(sels[0].vs_selector, "y") == 0);

		/* per-entry domain + alg captured; unknown field ignored */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"s\",\"key\":\"K\",\"domain\":\"d.example\","
		         "\"alg\":\"ed25519\",\"note\":{\"nested\":[1,2]}}]}}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel domain+alg captured",
		        rc == 0 && n == 1 &&
		        strcmp(sels[0].vs_domain, "d.example") == 0 &&
		        strcmp(sels[0].vs_alg, "ed25519") == 0);

		/* KVv1 envelope */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"selectors\":["
		         "{\"selector\":\"s\",\"key\":\"K\"}]}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel kvv1 envelope", rc == 0 && n == 1);

		/* no selectors array -> 1 (caller uses single-key path) */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"private_key\":\"PEM\"}}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_rc("sel no array -> 1", rc, 1);

		/* no envelope at all -> 1 */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"errors\":[\"nope\"]}", "selectors", (time_t) 0,
		         sels, DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_rc("sel no envelope -> 1", rc, 1);

		/* empty array -> 0 kept */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":[]}}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel empty array", rc == 0 && n == 0);

		/* numeric overflow in valid_start -> entry dropped */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"selectors\":["
		         "{\"selector\":\"a\",\"key\":\"K\","
		         "\"valid_start\":999999999999999999999999}]}}}",
		         "selectors", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel numeric overflow dropped", rc == 0 && n == 0);

		/* more than MAXSELECTORS entries -> bounded at MAXSELECTORS */
		off = 0;
		off += (size_t) snprintf(big + off, sizeof big - off,
		                         "{\"data\":{\"data\":{\"selectors\":[");
		for (i = 0; i < DKIMF_DB_VAULT_MAXSELECTORS + 2; i++)
			off += (size_t) snprintf(big + off, sizeof big - off,
			                         "%s{\"selector\":\"s%u\",\"key\":\"K\"}",
			                         i == 0 ? "" : ",", i);
		off += (size_t) snprintf(big + off, sizeof big - off, "]}}}");
		rc = dkimf_db_vault_parse_selectors(big, "selectors", (time_t) 0,
		                                    sels,
		                                    DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel bounded at max",
		        rc == 0 && n == DKIMF_DB_VAULT_MAXSELECTORS);

		/* configurable array field name */
		rc = dkimf_db_vault_parse_selectors(
		         "{\"data\":{\"data\":{\"keys\":["
		         "{\"selector\":\"s\",\"key\":\"K\"}]}}}",
		         "keys", (time_t) 0, sels,
		         DKIMF_DB_VAULT_MAXSELECTORS, &n);
		ck_true("sel custom field name", rc == 0 && n == 1);
	}

	printf(failures ? "\n%d FAILED\n" : "\nALL PASS\n", failures);
	return failures ? 1 : 0;
}
