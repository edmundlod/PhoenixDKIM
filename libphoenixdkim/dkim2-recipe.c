/*
**  dkim2-recipe.c -- DKIM2 body and header recipes.  See dkim2-recipe.h.
*/

#include "dkim2-recipe.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* libphoenixdkim includes */
#include "dkim2-json.h"

/* ── growable pointer vector (owns its entries) ──────────────────────────── */

struct ptrvec
{
	char	**v;
	size_t	  n;
	size_t	  cap;
};

static int
pv_push(struct ptrvec *p, char *s)
{
	if (p->n == p->cap)
	{
		size_t cap = p->cap ? p->cap * 2 : 8;
		char **g = realloc(p->v, cap * sizeof *g);

		if (g == NULL)
			return -1;
		p->v = g;
		p->cap = cap;
	}
	p->v[p->n++] = s;
	return 0;
}

static void
pv_free_all(struct ptrvec *p)
{
	size_t i;

	for (i = 0; i < p->n; i++)
		free(p->v[i]);
	free(p->v);
	p->v = NULL;
	p->n = p->cap = 0;
}

/* ── line split / join (the one CRLF convention) ─────────────────────────── */

/*
**  Split a body into CRLF-delimited lines (content without the terminator).  A
**  trailing CRLF closes the last line without creating an empty one; trailing
**  bytes with no CRLF still form a final line.  Returns a malloc'd array of
**  malloc'd strings (count in *nout), or NULL on allocation failure.
*/
static char **
body_split_lines(const char *body, size_t blen, size_t *nout)
{
	struct ptrvec lines = { 0 };
	size_t start = 0;
	size_t i = 0;

	while (i < blen)
	{
		if (i + 1 < blen && body[i] == '\r' && body[i + 1] == '\n')
		{
			size_t len = i - start;
			char *line = malloc(len + 1);

			if (line == NULL)
				goto fail;
			memcpy(line, body + start, len);
			line[len] = '\0';
			if (pv_push(&lines, line) != 0)
			{
				free(line);
				goto fail;
			}
			i += 2;
			start = i;
		}
		else
			i++;
	}
	if (start < blen)
	{
		size_t len = blen - start;
		char *line = malloc(len + 1);

		if (line == NULL)
			goto fail;
		memcpy(line, body + start, len);
		line[len] = '\0';
		if (pv_push(&lines, line) != 0)
		{
			free(line);
			goto fail;
		}
	}

	*nout = lines.n;
	return lines.v;

  fail:
	pv_free_all(&lines);
	return NULL;
}

/* Join lines with a CRLF terminator after each.  Always allocates. */
static char *
body_join_lines(char *const *lines, size_t n, size_t *outlen)
{
	size_t total = 0;
	size_t i;
	char *out;
	size_t off = 0;

	for (i = 0; i < n; i++)
		total += strlen(lines[i]) + 2;

	out = malloc(total + 1);
	if (out == NULL)
		return NULL;
	for (i = 0; i < n; i++)
	{
		size_t l = strlen(lines[i]);

		memcpy(out + off, lines[i], l);
		off += l;
		out[off++] = '\r';
		out[off++] = '\n';
	}
	out[off] = '\0';
	*outlen = off;
	return out;
}

/* ── header field helpers ────────────────────────────────────────────────── */

/* Lowercased field name of "Name: value", or NULL if there is no colon. */
static char *
field_name_lower(const char *field)
{
	const char *colon = strchr(field, ':');
	size_t n;
	char *name;
	size_t i;

	if (colon == NULL)
		return NULL;
	n = (size_t) (colon - field);
	name = malloc(n + 1);
	if (name == NULL)
		return NULL;
	for (i = 0; i < n; i++)
		name[i] = (char) tolower((unsigned char) field[i]);
	name[n] = '\0';
	return name;
}

/* Does "Name: value" have the (already lowercased) name? */
static int
field_name_is(const char *field, const char *lname)
{
	const char *colon = strchr(field, ':');
	size_t n;

	if (colon == NULL)
		return 0;
	n = (size_t) (colon - field);
	if (n != strlen(lname))
		return 0;
	return strncasecmp(field, lname, n) == 0;
}

/* The value of "Name: value" with one run of leading WSP removed. */
static const char *
field_value_trimmed(const char *field)
{
	const char *colon = strchr(field, ':');

	if (colon == NULL)
		return "";
	colon++;
	while (*colon == ' ' || *colon == '\t')
		colon++;
	return colon;
}

/* ── operation model ─────────────────────────────────────────────────────── */

static dkim2_recipe_op_t *
op_new(dkim2_ropt_t t)
{
	dkim2_recipe_op_t *o = calloc(1, sizeof *o);

	if (o != NULL)
		o->ro_type = t;
	return o;
}

static void
ops_free(dkim2_recipe_op_t *o)
{
	while (o != NULL)
	{
		dkim2_recipe_op_t *next = o->ro_next;
		size_t i;

		for (i = 0; i < o->ro_ndata; i++)
			free(o->ro_data[i]);
		free(o->ro_data);
		free(o);
		o = next;
	}
}

/* Append a data string to a DATA op (takes a copy). */
static int
op_data_add(dkim2_recipe_op_t *o, const char *s)
{
	char **g = realloc(o->ro_data, (o->ro_ndata + 1) * sizeof *g);
	char *dup;

	if (g == NULL)
		return -1;
	o->ro_data = g;
	dup = strdup(s);
	if (dup == NULL)
		return -1;
	o->ro_data[o->ro_ndata++] = dup;
	return 0;
}

/* ── parse (untrusted: base64-JSON r=) ───────────────────────────────────── */

/* A cJSON number that is a non-negative integer ordinal >= 1. */
static int
json_ordinal(const cJSON *n, size_t *out)
{
	double v;

	if (!cJSON_IsNumber(n))
		return -1;
	v = n->valuedouble;
	if (v < 1.0 || v != (double) (size_t) v)
		return -1;
	*out = (size_t) v;
	return 0;
}

static dkim2_recipe_op_t *
op_parse(const cJSON *opj)
{
	const cJSON *c;
	const cJSON *d;

	if (!cJSON_IsObject(opj))
		return NULL;
	c = cJSON_GetObjectItemCaseSensitive(opj, "c");
	d = cJSON_GetObjectItemCaseSensitive(opj, "d");

	if ((c != NULL) == (d != NULL))
		return NULL;	/* exactly one of c/d */

	if (c != NULL)
	{
		dkim2_recipe_op_t *o;
		size_t s, e;

		if (!cJSON_IsArray(c) || cJSON_GetArraySize(c) != 2)
			return NULL;
		if (json_ordinal(cJSON_GetArrayItem(c, 0), &s) != 0 ||
		    json_ordinal(cJSON_GetArrayItem(c, 1), &e) != 0 ||
		    e < s)
			return NULL;
		o = op_new(DKIM2_ROP_COPY);
		if (o == NULL)
			return NULL;
		o->ro_start = s;
		o->ro_end = e;
		return o;
	}
	else
	{
		dkim2_recipe_op_t *o;
		const cJSON *it;

		if (!cJSON_IsArray(d))
			return NULL;
		o = op_new(DKIM2_ROP_DATA);
		if (o == NULL)
			return NULL;
		cJSON_ArrayForEach(it, d)
		{
			if (!cJSON_IsString(it) ||
			    op_data_add(o, it->valuestring) != 0)
			{
				ops_free(o);
				return NULL;
			}
		}
		return o;
	}
}

/* Parse a JSON array of ops into a list; *err is set on a malformed op. */
static dkim2_recipe_op_t *
ops_parse(const cJSON *arr, int *err)
{
	dkim2_recipe_op_t *head = NULL, *tail = NULL;
	const cJSON *it;

	*err = 0;
	if (!cJSON_IsArray(arr))
	{
		*err = 1;
		return NULL;
	}
	cJSON_ArrayForEach(it, arr)
	{
		dkim2_recipe_op_t *o = op_parse(it);

		if (o == NULL)
		{
			*err = 1;
			ops_free(head);
			return NULL;
		}
		if (tail == NULL)
			head = o;
		else
			tail->ro_next = o;
		tail = o;
	}
	return head;
}

dkim2_recipe_t *
dkim2_recipe_parse(const char *b64, size_t len)
{
	cJSON *json;
	const cJSON *h;
	const cJSON *b;
	dkim2_recipe_t *r;

	if (b64 == NULL)
		return NULL;
	json = dkim2_json_b64_decode(b64, len);
	if (json == NULL)
		return NULL;
	if (!cJSON_IsObject(json))
	{
		cJSON_Delete(json);
		return NULL;
	}

	r = calloc(1, sizeof *r);
	if (r == NULL)
	{
		cJSON_Delete(json);
		return NULL;
	}

	h = cJSON_GetObjectItemCaseSensitive(json, "h");
	b = cJSON_GetObjectItemCaseSensitive(json, "b");

	/* spec-03 Section 5.1: headers must always be restorable, so "h":null is
	** invalid -- reject it.  Only "b":null is legal, marking the body
	** irreversible; the header object (if any) is still parsed normally, and a
	** verifier stops the backward walk at this hop. */
	if (h != NULL && cJSON_IsNull(h))
		goto fail;
	if (b != NULL && cJSON_IsNull(b))
		r->re_body_null = 1;

	if (h != NULL)
	{
		const cJSON *member;
		dkim2_recipe_hdr_t *tail = NULL;

		if (!cJSON_IsObject(h))
			goto fail;
		cJSON_ArrayForEach(member, h)
		{
			dkim2_recipe_hdr_t *rh;
			int err;
			size_t i;

			rh = calloc(1, sizeof *rh);
			if (rh == NULL)
				goto fail;
			rh->rh_name = strdup(member->string);
			if (rh->rh_name == NULL)
			{
				free(rh);
				goto fail;
			}
			/* normalise the field name to lowercase */
			for (i = 0; rh->rh_name[i] != '\0'; i++)
				rh->rh_name[i] =
				    (char) tolower((unsigned char) rh->rh_name[i]);
			rh->rh_ops = ops_parse(member, &err);
			if (err)
			{
				free(rh->rh_name);
				free(rh);
				goto fail;
			}
			if (tail == NULL)
				r->re_hdrs = rh;
			else
				tail->rh_next = rh;
			tail = rh;
		}
	}

	if (b != NULL && !cJSON_IsNull(b))
	{
		int err;

		r->re_body = ops_parse(b, &err);
		if (err)
			goto fail;
		/* An empty "b":[] is a body that reconstructs to nothing; keep a
		** marker op so apply does not mistake it for "unchanged". */
		if (r->re_body == NULL)
		{
			r->re_body = op_new(DKIM2_ROP_DATA);
			if (r->re_body == NULL)
				goto fail;
		}
	}

	cJSON_Delete(json);
	return r;

  fail:
	cJSON_Delete(json);
	dkim2_recipe_free(r);
	return NULL;
}

/* ── format ──────────────────────────────────────────────────────────────── */

static cJSON *
ops_to_json(const dkim2_recipe_op_t *ops)
{
	cJSON *arr = cJSON_CreateArray();
	const dkim2_recipe_op_t *o;

	if (arr == NULL)
		return NULL;
	for (o = ops; o != NULL; o = o->ro_next)
	{
		cJSON *opj = cJSON_CreateObject();

		if (opj == NULL)
			goto fail;
		cJSON_AddItemToArray(arr, opj);

		if (o->ro_type == DKIM2_ROP_COPY)
		{
			cJSON *c = cJSON_CreateArray();

			if (c == NULL)
				goto fail;
			cJSON_AddItemToObject(opj, "c", c);
			cJSON_AddItemToArray(c,
			    cJSON_CreateNumber((double) o->ro_start));
			cJSON_AddItemToArray(c,
			    cJSON_CreateNumber((double) o->ro_end));
		}
		else
		{
			cJSON *d = cJSON_CreateArray();
			size_t i;

			if (d == NULL)
				goto fail;
			cJSON_AddItemToObject(opj, "d", d);
			for (i = 0; i < o->ro_ndata; i++)
				cJSON_AddItemToArray(d,
				    cJSON_CreateString(o->ro_data[i]));
		}
	}
	return arr;

  fail:
	cJSON_Delete(arr);
	return NULL;
}

char *
dkim2_recipe_format(const dkim2_recipe_t *r)
{
	cJSON *root;
	char *out;

	if (r == NULL)
		return NULL;
	root = cJSON_CreateObject();
	if (root == NULL)
		return NULL;

	/* Headers (if changed) are always emitted as a reversible object; the body
	** is either a reversible op list or, when irreversible, the "b":null marker.
	** Both may appear together: {"h":{…},"b":null}. */
	if (r->re_hdrs != NULL)
	{
		cJSON *h = cJSON_CreateObject();
		const dkim2_recipe_hdr_t *rh;

		if (h == NULL)
			goto fail;
		cJSON_AddItemToObject(root, "h", h);
		for (rh = r->re_hdrs; rh != NULL; rh = rh->rh_next)
		{
			cJSON *arr = ops_to_json(rh->rh_ops);

			if (arr == NULL)
				goto fail;
			cJSON_AddItemToObject(h, rh->rh_name, arr);
		}
	}
	if (r->re_body_null)
	{
		cJSON_AddNullToObject(root, "b");
	}
	else if (r->re_body != NULL)
	{
		cJSON *b = ops_to_json(r->re_body);

		if (b == NULL)
			goto fail;
		cJSON_AddItemToObject(root, "b", b);
	}

	out = dkim2_json_b64_encode(root);
	cJSON_Delete(root);
	return out;

  fail:
	cJSON_Delete(root);
	return NULL;
}

/* ── free ────────────────────────────────────────────────────────────────── */

void
dkim2_recipe_free(dkim2_recipe_t *r)
{
	dkim2_recipe_hdr_t *rh;

	if (r == NULL)
		return;
	rh = r->re_hdrs;
	while (rh != NULL)
	{
		dkim2_recipe_hdr_t *next = rh->rh_next;

		ops_free(rh->rh_ops);
		free(rh->rh_name);
		free(rh);
		rh = next;
	}
	ops_free(r->re_body);
	free(r);
}

/* ── apply: reconstruct the previous instance ────────────────────────────── */

/* Run the body ops against cur's lines, appending the result to *out. */
static int
apply_body_ops(const dkim2_recipe_op_t *ops, char *const *lines, size_t nlines,
               struct ptrvec *out)
{
	const dkim2_recipe_op_t *o;

	for (o = ops; o != NULL; o = o->ro_next)
	{
		if (o->ro_type == DKIM2_ROP_COPY)
		{
			size_t k;

			if (o->ro_start < 1 || o->ro_end > nlines)
				return -1;
			for (k = o->ro_start; k <= o->ro_end; k++)
			{
				char *dup = strdup(lines[k - 1]);

				if (dup == NULL || pv_push(out, dup) != 0)
				{
					free(dup);
					return -1;
				}
			}
		}
		else
		{
			size_t i;

			for (i = 0; i < o->ro_ndata; i++)
			{
				char *dup = strdup(o->ro_data[i]);

				if (dup == NULL || pv_push(out, dup) != 0)
				{
					free(dup);
					return -1;
				}
			}
		}
	}
	return 0;
}

/* Build the reconstructed field sequence for one header recipe, into *out. */
static int
apply_hdr_ops(const dkim2_recipe_hdr_t *rh,
              const char *const *cur_hdrs, size_t cur_nh,
              struct ptrvec *out)
{
	const dkim2_recipe_op_t *o;

	for (o = rh->rh_ops; o != NULL; o = o->ro_next)
	{
		if (o->ro_type == DKIM2_ROP_COPY)
		{
			size_t seen = 0;
			size_t i;

			/* COPY ordinals index this name's instances in cur. */
			for (i = 0; i < cur_nh; i++)
			{
				if (cur_hdrs[i] == NULL ||
				    !field_name_is(cur_hdrs[i], rh->rh_name))
					continue;
				seen++;
				if (seen >= o->ro_start && seen <= o->ro_end)
				{
					char *dup = strdup(cur_hdrs[i]);

					if (dup == NULL || pv_push(out, dup) != 0)
					{
						free(dup);
						return -1;
					}
				}
			}
			if (o->ro_end > seen)
				return -1;	/* out-of-range ordinal */
		}
		else
		{
			size_t i;

			for (i = 0; i < o->ro_ndata; i++)
			{
				char *field;

				if (asprintf(&field, "%s: %s", rh->rh_name,
				             o->ro_data[i]) < 0)
					return -1;
				if (pv_push(out, field) != 0)
				{
					free(field);
					return -1;
				}
			}
		}
	}
	return 0;
}

int
dkim2_recipe_apply(const dkim2_recipe_t *r,
                   const char *const *cur_hdrs, size_t cur_nh,
                   const char *cur_body, size_t cur_blen,
                   char ***prev_hdrs, size_t *prev_nh,
                   char **prev_body, size_t *prev_blen)
{
	struct ptrvec hdrs = { 0 };
	const dkim2_recipe_hdr_t *rh;
	size_t i;

	if (r == NULL)
		return -1;
	if (r->re_body_null)
		return 1;	/* body cannot be reconstructed; stop the walk */

	/* ── body ── */
	if (r->re_body == NULL)
	{
		/* unchanged: copy the current body through */
		char *dup = malloc(cur_blen + 1);

		if (dup == NULL)
			return -1;
		if (cur_blen > 0)
			memcpy(dup, cur_body, cur_blen);
		dup[cur_blen] = '\0';
		*prev_body = dup;
		*prev_blen = cur_blen;
	}
	else
	{
		char **lines;
		size_t nlines;
		struct ptrvec outlines = { 0 };
		char *joined;
		size_t jl;

		lines = body_split_lines(cur_body, cur_blen, &nlines);
		if (lines == NULL)
			return -1;
		if (apply_body_ops(r->re_body, lines, nlines, &outlines) != 0)
		{
			for (i = 0; i < nlines; i++)
				free(lines[i]);
			free(lines);
			pv_free_all(&outlines);
			return -1;
		}
		for (i = 0; i < nlines; i++)
			free(lines[i]);
		free(lines);
		joined = body_join_lines(outlines.v, outlines.n, &jl);
		pv_free_all(&outlines);
		if (joined == NULL)
			return -1;
		*prev_body = joined;
		*prev_blen = jl;
	}

	/* ── headers ── */
	if (r->re_hdrs == NULL)
	{
		/* unchanged: copy every field through */
		for (i = 0; i < cur_nh; i++)
		{
			char *dup;

			if (cur_hdrs[i] == NULL)
				continue;
			dup = strdup(cur_hdrs[i]);
			if (dup == NULL || pv_push(&hdrs, dup) != 0)
			{
				free(dup);
				goto fail_hdrs;
			}
		}
	}
	else
	{
		/* Copy through fields whose name is not in the recipe; at the first
		** occurrence of a recipe field name, inject its rebuilt sequence. */
		size_t nrh = 0;
		size_t ri;
		int *injected;

		for (rh = r->re_hdrs; rh != NULL; rh = rh->rh_next)
			nrh++;
		injected = calloc(nrh ? nrh : 1, sizeof *injected);
		if (injected == NULL)
			goto fail_hdrs;

		for (i = 0; i < cur_nh; i++)
		{
			char *name;
			int handled = 0;

			if (cur_hdrs[i] == NULL)
				continue;
			name = field_name_lower(cur_hdrs[i]);
			if (name == NULL)
			{
				/* no colon: copy verbatim */
				char *dup = strdup(cur_hdrs[i]);

				if (dup == NULL || pv_push(&hdrs, dup) != 0)
				{
					free(dup);
					free(injected);
					goto fail_hdrs;
				}
				continue;
			}

			ri = 0;
			for (rh = r->re_hdrs; rh != NULL; rh = rh->rh_next, ri++)
			{
				if (strcmp(rh->rh_name, name) != 0)
					continue;
				handled = 1;
				if (!injected[ri])
				{
					injected[ri] = 1;
					if (apply_hdr_ops(rh, cur_hdrs, cur_nh,
					                  &hdrs) != 0)
					{
						free(name);
						free(injected);
						goto fail_hdrs;
					}
				}
				break;	/* skip this current field */
			}
			free(name);
			if (!handled)
			{
				char *dup = strdup(cur_hdrs[i]);

				if (dup == NULL || pv_push(&hdrs, dup) != 0)
				{
					free(dup);
					free(injected);
					goto fail_hdrs;
				}
			}
		}

		/* Recipe field names with no current instance: append them. */
		ri = 0;
		for (rh = r->re_hdrs, ri = 0; rh != NULL; rh = rh->rh_next, ri++)
		{
			if (injected[ri])
				continue;
			if (apply_hdr_ops(rh, cur_hdrs, cur_nh, &hdrs) != 0)
			{
				free(injected);
				goto fail_hdrs;
			}
		}
		free(injected);
	}

	*prev_hdrs = hdrs.v;
	*prev_nh = hdrs.n;
	return 0;

  fail_hdrs:
	pv_free_all(&hdrs);
	free(*prev_body);
	*prev_body = NULL;
	*prev_blen = 0;
	return -1;
}

/* ── generate: diff new against old ──────────────────────────────────────── */

/* Append a copy of one new-line ordinal, coalescing contiguous runs. */
static int
gen_add_copy(dkim2_recipe_op_t **head, dkim2_recipe_op_t **tail, size_t ord)
{
	dkim2_recipe_op_t *o;

	if (*tail != NULL && (*tail)->ro_type == DKIM2_ROP_COPY &&
	    (*tail)->ro_end == ord - 1)
	{
		(*tail)->ro_end = ord;
		return 0;
	}
	o = op_new(DKIM2_ROP_COPY);
	if (o == NULL)
		return -1;
	o->ro_start = ord;
	o->ro_end = ord;
	if (*tail == NULL)
		*head = o;
	else
		(*tail)->ro_next = o;
	*tail = o;
	return 0;
}

/* Append one literal data line, coalescing into the current DATA op. */
static int
gen_add_data(dkim2_recipe_op_t **head, dkim2_recipe_op_t **tail, const char *s)
{
	dkim2_recipe_op_t *o;

	if (*tail != NULL && (*tail)->ro_type == DKIM2_ROP_DATA)
		return op_data_add(*tail, s);
	o = op_new(DKIM2_ROP_DATA);
	if (o == NULL)
		return -1;
	if (op_data_add(o, s) != 0)
	{
		ops_free(o);
		return -1;
	}
	if (*tail == NULL)
		*head = o;
	else
		(*tail)->ro_next = o;
	*tail = o;
	return 0;
}

/*
**  LCS line-diff reconstructing OLD from NEW: matched lines become copy ops over
**  new's ordinals, old-only lines become data ops, new-only lines are dropped.
*/
static dkim2_recipe_op_t *
diff_lines(char *const *o_lines, size_t on, char *const *n_lines, size_t nn,
           int *err)
{
	dkim2_recipe_op_t *head = NULL, *tail = NULL;
	size_t *dp = NULL;
	size_t i, j;
	size_t stride = nn + 1;

	*err = 0;

	/* dp[i*stride + j] = LCS length of o_lines[i..], n_lines[j..]. */
	dp = calloc((on + 1) * stride, sizeof *dp);
	if (dp == NULL)
	{
		*err = 1;
		return NULL;
	}
	for (i = on; i-- > 0; )
	{
		for (j = nn; j-- > 0; )
		{
			if (strcmp(o_lines[i], n_lines[j]) == 0)
				dp[i * stride + j] = dp[(i + 1) * stride + j + 1] + 1;
			else
			{
				size_t a = dp[(i + 1) * stride + j];
				size_t b = dp[i * stride + j + 1];

				dp[i * stride + j] = a >= b ? a : b;
			}
		}
	}

	i = 0;
	j = 0;
	while (i < on || j < nn)
	{
		if (i < on && j < nn && strcmp(o_lines[i], n_lines[j]) == 0)
		{
			if (gen_add_copy(&head, &tail, j + 1) != 0)
				goto oom;
			i++;
			j++;
		}
		else if (j >= nn ||
		         (i < on && dp[(i + 1) * stride + j] >= dp[i * stride + j + 1]))
		{
			if (gen_add_data(&head, &tail, o_lines[i]) != 0)
				goto oom;
			i++;
		}
		else
		{
			j++;	/* new-only line: dropped from the older version */
		}
	}

	free(dp);
	return head;

  oom:
	free(dp);
	ops_free(head);
	*err = 1;
	return NULL;
}

/* Are two equal-length line arrays element-wise identical? */
static int
lines_equal(char *const *a, size_t an, char *const *b, size_t bn)
{
	size_t i;

	if (an != bn)
		return 0;
	for (i = 0; i < an; i++)
		if (strcmp(a[i], b[i]) != 0)
			return 0;
	return 1;
}

/* Collect the distinct lowercased field names appearing in hdrs, in order. */
static int
collect_names(const char *const *hdrs, size_t nh, struct ptrvec *names)
{
	size_t i, j;

	for (i = 0; i < nh; i++)
	{
		char *name;
		int seen = 0;

		if (hdrs[i] == NULL)
			continue;
		name = field_name_lower(hdrs[i]);
		if (name == NULL)
			continue;
		for (j = 0; j < names->n; j++)
		{
			if (strcmp(names->v[j], name) == 0)
			{
				seen = 1;
				break;
			}
		}
		if (seen)
			free(name);
		else if (pv_push(names, name) != 0)
		{
			free(name);
			return -1;
		}
	}
	return 0;
}

/* Index of the next field with the given name at or after *idx; advances *idx
** one past it.  Returns 1 when one was found, 0 at the end of the list. */
static int
next_named_field(const char *const *hdrs, size_t nh, const char *name,
                 size_t *idx, const char **value)
{
	while (*idx < nh)
	{
		size_t at = (*idx)++;

		if (hdrs[at] != NULL && field_name_is(hdrs[at], name))
		{
			*value = field_value_trimmed(hdrs[at]);
			return 1;
		}
	}
	return 0;
}

/* Do old and new carry the same instance values for the given field name? */
static int
hdr_name_unchanged(const char *name,
                   const char *const *old_hdrs, size_t old_nh,
                   const char *const *new_hdrs, size_t new_nh)
{
	size_t oi = 0, ni = 0;

	for (;;)
	{
		const char *ov = NULL, *nv = NULL;
		int o_has = next_named_field(old_hdrs, old_nh, name, &oi, &ov);
		int n_has = next_named_field(new_hdrs, new_nh, name, &ni, &nv);

		if (!o_has && !n_has)
			return 1;
		if (o_has != n_has || strcmp(ov, nv) != 0)
			return 0;
	}
}

dkim2_recipe_t *
dkim2_recipe_generate(const char *const *old_hdrs, size_t old_nh,
                      const char *old_body, size_t old_blen,
                      const char *const *new_hdrs, size_t new_nh,
                      const char *new_body, size_t new_blen)
{
	dkim2_recipe_t *r = calloc(1, sizeof *r);
	char **ol = NULL, **nl = NULL;
	size_t on = 0, nn = 0;
	struct ptrvec names = { 0 };
	dkim2_recipe_hdr_t *htail = NULL;
	size_t i;
	int err;

	if (r == NULL)
		return NULL;

	/* ── body ── */
	ol = body_split_lines(old_body, old_blen, &on);
	nl = body_split_lines(new_body, new_blen, &nn);
	if (ol == NULL || nl == NULL)
		goto fail;
	if (!lines_equal(ol, on, nl, nn))
	{
		r->re_body = diff_lines(ol, on, nl, nn, &err);
		if (err)
			goto fail;
		/* A body that reconstructs to nothing still needs a marker so apply
		** does not read re_body == NULL as "unchanged". */
		if (r->re_body == NULL)
		{
			r->re_body = op_new(DKIM2_ROP_DATA);
			if (r->re_body == NULL)
				goto fail;
		}
	}

	/* ── headers ── */
	if (collect_names(old_hdrs, old_nh, &names) != 0 ||
	    collect_names(new_hdrs, new_nh, &names) != 0)
		goto fail;

	for (i = 0; i < names.n; i++)
	{
		const char *name = names.v[i];
		dkim2_recipe_hdr_t *rh;
		dkim2_recipe_op_t *op;
		size_t j;

		if (hdr_name_unchanged(name, old_hdrs, old_nh, new_hdrs, new_nh))
			continue;

		/* Emit one DATA op carrying old's values for this name (possibly
		** empty, which reconstructs to a removed field). */
		rh = calloc(1, sizeof *rh);
		if (rh == NULL)
			goto fail;
		rh->rh_name = strdup(name);
		if (rh->rh_name == NULL)
		{
			free(rh);
			goto fail;
		}
		op = op_new(DKIM2_ROP_DATA);
		if (op == NULL)
		{
			free(rh->rh_name);
			free(rh);
			goto fail;
		}
		rh->rh_ops = op;
		for (j = 0; j < old_nh; j++)
		{
			if (old_hdrs[j] == NULL ||
			    !field_name_is(old_hdrs[j], name))
				continue;
			if (op_data_add(op, field_value_trimmed(old_hdrs[j])) != 0)
				goto fail;
		}
		if (htail == NULL)
			r->re_hdrs = rh;
		else
			htail->rh_next = rh;
		htail = rh;
	}

	for (i = 0; i < on; i++)
		free(ol[i]);
	free(ol);
	for (i = 0; i < nn; i++)
		free(nl[i]);
	free(nl);
	pv_free_all(&names);
	return r;

  fail:
	if (ol != NULL)
	{
		for (i = 0; i < on; i++)
			free(ol[i]);
		free(ol);
	}
	if (nl != NULL)
	{
		for (i = 0; i < nn; i++)
			free(nl[i]);
		free(nl);
	}
	pv_free_all(&names);
	dkim2_recipe_free(r);
	return NULL;
}
