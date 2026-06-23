/*
**  phoenixdkim2-sign.c -- standalone DKIM2-core signer for the testing phase.
**
**  Reads a message on stdin, signs it, and writes the message with the new
**  Message-Instance and DKIM2-Signature fields prepended to stdout.  It exists
**  to exercise the chain against interop fixtures without an MTA; the milter is
**  the production path.
**
**  Usage:
**    phoenixdkim2-sign --key FILE --domain D --selector S --mail-from "<a@b>" \
**        [--alg rsa-sha256|ed25519-sha256] [--rcpt-to "<c@d>"]... [--time N]
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dkim2-crypto.h"
#include "dkim2-eml.h"
#include "dkim2-sign.h"

static char *
read_all(FILE *f, size_t *len)
{
	size_t cap = 65536, n = 0;
	char *buf = malloc(cap);
	size_t r;

	if (buf == NULL)
		return NULL;
	while ((r = fread(buf + n, 1, cap - n, f)) > 0)
	{
		n += r;
		if (n == cap)
		{
			char *grown = realloc(buf, cap *= 2);

			if (grown == NULL)
			{
				free(buf);
				return NULL;
			}
			buf = grown;
		}
	}
	*len = n;
	return buf;
}

int
main(int argc, char **argv)
{
	const char *keyfile = NULL, *domain = NULL, *selector = NULL;
	const char *mailfrom = NULL, *algname = NULL;
	const char **rcpt = NULL;
	size_t nrcpt = 0;
	uint64_t t = 0;
	int i;
	char *keypem, *msg, *mi = NULL, *sig = NULL;
	size_t keylen, msglen;
	EVP_PKEY *key;
	dkim2_eml_t *eml;
	dkim2_sign_params_t p;
	dkim2_alg_t alg;
	FILE *kf;

	rcpt = calloc((size_t) argc, sizeof *rcpt);
	if (rcpt == NULL)
		return 2;

	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
			keyfile = argv[++i];
		else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc)
			domain = argv[++i];
		else if (strcmp(argv[i], "--selector") == 0 && i + 1 < argc)
			selector = argv[++i];
		else if (strcmp(argv[i], "--mail-from") == 0 && i + 1 < argc)
			mailfrom = argv[++i];
		else if (strcmp(argv[i], "--alg") == 0 && i + 1 < argc)
			algname = argv[++i];
		else if (strcmp(argv[i], "--rcpt-to") == 0 && i + 1 < argc)
			rcpt[nrcpt++] = argv[++i];
		else if (strcmp(argv[i], "--time") == 0 && i + 1 < argc)
			t = strtoull(argv[++i], NULL, 10);
		else
		{
			fprintf(stderr, "phoenixdkim2-sign: unknown option '%s'\n",
			        argv[i]);
			free(rcpt);
			return 2;
		}
	}

	if (keyfile == NULL || domain == NULL || selector == NULL ||
	    mailfrom == NULL)
	{
		fprintf(stderr, "usage: phoenixdkim2-sign --key FILE --domain D "
		        "--selector S --mail-from \"<a@b>\" [--alg NAME] "
		        "[--rcpt-to \"<c@d>\"]... [--time N]\n");
		free(rcpt);
		return 2;
	}

	kf = fopen(keyfile, "rb");
	if (kf == NULL)
	{
		fprintf(stderr, "phoenixdkim2-sign: cannot open key '%s'\n", keyfile);
		free(rcpt);
		return 2;
	}
	keypem = read_all(kf, &keylen);
	fclose(kf);
	key = keypem != NULL ? dkim2_privkey_load_pem(keypem, keylen) : NULL;
	free(keypem);
	if (key == NULL)
	{
		fprintf(stderr, "phoenixdkim2-sign: bad private key\n");
		free(rcpt);
		return 2;
	}

	alg = algname != NULL ? dkim2_alg_from_name(algname) : dkim2_pkey_alg(key);
	if (alg == DKIM2_ALG_UNKNOWN)
	{
		fprintf(stderr, "phoenixdkim2-sign: unknown/unsupported algorithm\n");
		EVP_PKEY_free(key);
		free(rcpt);
		return 2;
	}

	msg = read_all(stdin, &msglen);
	eml = msg != NULL ? dkim2_eml_parse(msg, msglen) : NULL;
	if (eml == NULL)
	{
		fprintf(stderr, "phoenixdkim2-sign: cannot parse message\n");
		EVP_PKEY_free(key);
		free(msg);
		free(rcpt);
		return 2;
	}

	memset(&p, 0, sizeof p);
	p.sp_domain = domain;
	p.sp_selector = selector;
	p.sp_key = key;
	p.sp_alg = alg;
	p.sp_mf = mailfrom;
	p.sp_rt = rcpt;
	p.sp_rt_count = nrcpt;
	p.sp_t = t;

	if (dkim2_sign(&p, (const char *const *) eml->em_headers,
	               eml->em_nheaders, eml->em_body, eml->em_bodylen,
	               &mi, &sig) != 0)
	{
		fprintf(stderr, "phoenixdkim2-sign: signing failed\n");
		dkim2_eml_free(eml);
		EVP_PKEY_free(key);
		free(msg);
		free(rcpt);
		return 1;
	}

	if (mi != NULL)
		printf("%s\r\n", mi);
	printf("%s\r\n", sig);
	fwrite(msg, 1, msglen, stdout);

	free(mi);
	free(sig);
	dkim2_eml_free(eml);
	EVP_PKEY_free(key);
	free(msg);
	free(rcpt);
	return 0;
}
