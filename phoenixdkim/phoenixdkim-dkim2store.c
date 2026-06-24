/*
**  Copyright (c) 2026, The PhoenixDKIM Authors.  All rights reserved.
**
**  phoenixdkim-dkim2store.c -- on-disk snapshot store for DKIM2 modifying
**                              re-signing.  See phoenixdkim-dkim2store.h.
*/

#include "build-config.h"

#ifdef USE_DKIM2

/* system includes */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* openssl includes */
#include <openssl/evp.h>

/* phoenixdkim includes */
#include "phoenixdkim-dkim2store.h"

/*
**  CANON_MI -- canonicalize a Message-Instance value for keying: collapse every
**  run of WSP/CR/LF (which also unfolds continuation lines) to a single space
**  and trim the ends.  Mirrors Mail::DKIM2::MessageStore::_key_for_mi so a
**  folded inbound field and an unfolded outbound one hash identically.
**
**  Returns a malloc'd NUL-terminated string, or NULL on OOM.
*/
static char *
canon_mi(const char *mi_value)
{
	char *out;
	size_t i = 0;
	int inws = 1;		/* start "in whitespace" so leading WSP is dropped */

	if (mi_value == NULL)
		return NULL;
	out = malloc(strlen(mi_value) + 1);
	if (out == NULL)
		return NULL;

	for (; *mi_value != '\0'; mi_value++)
	{
		unsigned char c = (unsigned char) *mi_value;

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
		{
			if (!inws)
			{
				out[i++] = ' ';
				inws = 1;
			}
		}
		else
		{
			out[i++] = (char) c;
			inws = 0;
		}
	}
	/* drop a single trailing space left by the collapse */
	if (i > 0 && out[i - 1] == ' ')
		i--;
	out[i] = '\0';
	return out;
}

/*
**  KEY_HEX -- SHA-256 (lowercase hex) of the canonicalized MI value into a
**  caller-supplied 65-byte buffer.  Returns 0 on success, -1 on error.
*/
static int
key_hex(const char *mi_value, char hex[65])
{
	char *canon = canon_mi(mi_value);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	unsigned int k;

	if (canon == NULL)
		return -1;
	if (EVP_Digest(canon, strlen(canon), md, &mdlen, EVP_sha256(),
	               NULL) != 1 || mdlen != 32)
	{
		free(canon);
		return -1;
	}
	free(canon);
	for (k = 0; k < 32; k++)
		(void) snprintf(hex + (k * 2), 3, "%02x", md[k]);
	return 0;
}

/*
**  BUILD_PATHS -- fill the prefix directory and full file path for a key.  Both
**  buffers must hold at least strlen(dir) + 3 + 64 + 2 bytes.  Returns 0 on
**  success, -1 if the key could not be derived.
*/
static int
build_paths(const char *dir, const char *mi_value,
            char *dirpath, size_t dirpathlen,
            char *filepath, size_t filepathlen)
{
	char hex[65];

	if (dir == NULL || key_hex(mi_value, hex) != 0)
		return -1;
	(void) snprintf(dirpath, dirpathlen, "%s/%c%c", dir, hex[0], hex[1]);
	(void) snprintf(filepath, filepathlen, "%s/%c%c/%s", dir, hex[0],
	                hex[1], hex);
	return 0;
}

int
dkimf_dkim2_store_put(const char *dir, const char *mi_value,
                      const char *data, size_t len)
{
	char dirpath[MAXPATHLEN];
	char filepath[MAXPATHLEN];
	char tmppath[MAXPATHLEN + 16];
	int fd;
	ssize_t w;

	if (data == NULL)
		return -1;
	if (build_paths(dir, mi_value, dirpath, sizeof dirpath,
	                filepath, sizeof filepath) != 0)
		return -1;

	/* Create only the 2-char shard subdirectory inside the configured base;
	** the base itself is the admin's to provision (validated at config load)
	** so the daemon never fabricates a config-supplied directory path. */
	if (mkdir(dirpath, 0700) != 0 && errno != EEXIST)
		return -1;

	/* write to a temp file then rename so a reader never sees a partial
	** snapshot even if two transactions race on the same key */
	(void) snprintf(tmppath, sizeof tmppath, "%s.tmp.%ld", filepath,
	                (long) getpid());
	fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	for (size_t off = 0; off < len; off += (size_t) w)
	{
		w = write(fd, data + off, len - off);
		if (w <= 0)
		{
			(void) close(fd);
			(void) unlink(tmppath);
			return -1;
		}
	}
	if (close(fd) != 0 || rename(tmppath, filepath) != 0)
	{
		(void) unlink(tmppath);
		return -1;
	}
	return 0;
}

char *
dkimf_dkim2_store_get(const char *dir, const char *mi_value, size_t *lenout)
{
	char dirpath[MAXPATHLEN];
	char filepath[MAXPATHLEN];
	struct stat st;
	char *buf;
	int fd;
	size_t off;

	if (build_paths(dir, mi_value, dirpath, sizeof dirpath,
	                filepath, sizeof filepath) != 0)
		return NULL;
	fd = open(filepath, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0 || st.st_size < 0)
	{
		(void) close(fd);
		return NULL;
	}
	buf = malloc((size_t) st.st_size > 0 ? (size_t) st.st_size : 1);
	if (buf == NULL)
	{
		(void) close(fd);
		return NULL;
	}
	for (off = 0; off < (size_t) st.st_size; )
	{
		ssize_t r = read(fd, buf + off, (size_t) st.st_size - off);

		if (r < 0)
		{
			free(buf);
			(void) close(fd);
			return NULL;
		}
		if (r == 0)
			break;
		off += (size_t) r;
	}
	(void) close(fd);
	if (lenout != NULL)
		*lenout = off;
	return buf;
}

int
dkimf_dkim2_store_remove(const char *dir, const char *mi_value)
{
	char dirpath[MAXPATHLEN];
	char filepath[MAXPATHLEN];

	if (build_paths(dir, mi_value, dirpath, sizeof dirpath,
	                filepath, sizeof filepath) != 0)
		return -1;
	return unlink(filepath) == 0 ? 0 : -1;
}

#endif /* USE_DKIM2 */
