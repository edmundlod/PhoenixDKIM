/*
**  Copyright (c) 2011-2013, 2015, The Trusted Domain Project.  All rights reserved.
**
**  Copyright (c) 2026, PhoenixDKIM contributors. All rights reserved.
*/

#include "build-config.h"

/* system includes */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sysexits.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* libphoenixdkim includes */
#include <dkim.h>

/* macros */
#ifndef FALSE
# define FALSE		0
#endif /* ! FALSE */
#ifndef TRUE
# define TRUE		1
#endif /* ! TRUE */

#define	BUFRSZ		1024
#define	DEFTMPDIR	"/tmp"
#define	CMDLINEOPTS	"Cd:Kk:s:t:v"
#define STRORNULL(x)	((x) == NULL ? "(null)" : (x))
#define	TMPTEMPLATE	"dkimXXXXXX"

/* prototypes */
int usage(void);

/*
**  SIGALG_NAME -- printable name for a DKIM signing algorithm
**
**  Parameters:
**  	alg -- a DKIM_SIGN_* value
**
**  Return value:
**  	A constant string.
*/

static const char *
sigalg_name(dkim_alg_t alg)
{
	switch (alg)
	{
	  case DKIM_SIGN_RSASHA1:
		return "rsa-sha1";
	  case DKIM_SIGN_RSASHA256:
		return "rsa-sha256";
	  case DKIM_SIGN_ED25519SHA256:
		return "ed25519-sha256";
	  default:
		return "(unknown)";
	}
}

/*
**  CANON_NAME -- printable name for a canonicalization mode
**
**  Parameters:
**  	canon -- a DKIM_CANON_* value
**
**  Return value:
**  	A constant string.
*/

static const char *
canon_name(dkim_canon_t canon)
{
	switch (canon)
	{
	  case DKIM_CANON_SIMPLE:
		return "simple";
	  case DKIM_CANON_RELAXED:
		return "relaxed";
	  default:
		return "(unknown)";
	}
}

/*
**  DNSSEC_NAME -- printable name for a DNSSEC disposition
**
**  Parameters:
**  	dnssec -- a DKIM_DNSSEC_* value
**
**  Return value:
**  	A constant string.
*/

static const char *
dnssec_name(int dnssec)
{
	switch (dnssec)
	{
	  case DKIM_DNSSEC_BOGUS:
		return "bogus";
	  case DKIM_DNSSEC_INSECURE:
		return "insecure";
	  case DKIM_DNSSEC_SECURE:
		return "secure";
	  case DKIM_DNSSEC_UNKNOWN:
	  default:
		return "unknown";
	}
}

/* globals */
char *progname;

/*
**  USAGE -- print a usage message
**
**  Parameters:
**  	None.
**
**  Return value:
**  	EX_CONFIG
*/

int
usage(void)
{
	fprintf(stderr,
	        "%s: usage: %s [options]\nValid options:\n"
	        "\t-C         \tpreserve CRLFs\n"
	        "\t-d domain  \tset signing domain\n"
	        "\t-K         \tkeep temporary files\n"
	        "\t-k keyfile \tprivate key file\n"
	        "\t-s selector\tset signing selector\n"
	        "\t-t path    \tdirectory for temporary files\n"
	        "\t-v         \tincrease verbosity (report verify details)\n",
	        progname, progname);

	return EX_CONFIG;
}

/*
**  DECR -- remove CRs from a string
**
**  Parameters:
**  	str -- string to modify; must be NULL-terminated
**
**  Return value:
**  	None.
*/

static void
decr(char *str)
{
	char *p;
	char *q;

	for (p = str, q = str; *p != '\0'; p++)
	{
		if (*p == '\r')
			continue;

		if (p != q)
			*q = *p;

		q++;
	}
}

/*
**  MAIN -- program mainline
**
**  Parameters:
**  	argc, argv -- the usual
**
**  Return value:
**  	Exit status.
*/

int
main(int argc, char **argv)
{
	_Bool keepcrlf = FALSE;
	_Bool keepfiles = FALSE;
	_Bool testkey = FALSE;
	int c;
	int n = 0;
	int verbose = 0;
	int retval = EX_OK;
	int tfd;
	u_int flags;
	DKIM_STAT status;
	ssize_t rlen;
	ssize_t wlen;
	ssize_t l = (ssize_t) -1;
	dkim_alg_t sa = DKIM_SIGN_RSASHA1;
	dkim_canon_t bc = DKIM_CANON_SIMPLE;
	dkim_canon_t hc = DKIM_CANON_RELAXED;
	DKIM_LIB *lib;
	DKIM *dkim;
	char *p;
	const char *domain = NULL;
	const char *selector = NULL;
	const char *keyfile = NULL;
	char *keydata = NULL;
	const char *tmpdir = DEFTMPDIR;
	char buf[BUFRSZ];
	char fn[BUFRSZ];

	progname = (p = strrchr(argv[0], '/')) == NULL ? argv[0] : p + 1;

	while ((c = getopt(argc, argv, CMDLINEOPTS)) != -1)
	{
		switch (c)
		{
		  case 'C':
			keepcrlf = TRUE;
			break;

		  case 'd':
			domain = optarg;
			n++;
			break;

		  case 'K':
			keepfiles = TRUE;
			break;

		  case 'k':
			keyfile = optarg;
			n++;
			break;

		  case 's':
			selector = optarg;
			n++;
			break;

		  case 't':
			tmpdir = optarg;
			break;

		  case 'v':
			verbose++;
			break;

		  default:
			return usage();
		}
	}

	if (n != 0 && n != 3)
		return usage();

	memset(fn, '\0', sizeof fn);
	snprintf(fn, sizeof fn, "%s/%s", tmpdir, TMPTEMPLATE);

	if (n == 3)
	{
		int fd;
		struct stat s;

		fd = open(keyfile, O_RDONLY);
		if (fd < 0)
		{
			fprintf(stderr, "%s: %s: open(): %s\n", progname,
			        keyfile, strerror(errno));
			return EX_OSERR;
		}

		if (fstat(fd, &s) != 0)
		{
			fprintf(stderr, "%s: %s: fstat(): %s\n", progname,
			        keyfile, strerror(errno));
			close(fd);
			return EX_OSERR;
		}

		keydata = malloc(s.st_size + 1);
		if (keydata == NULL)
		{
			fprintf(stderr, "%s: malloc(): %s\n", progname,
			        strerror(errno));
			close(fd);
			return EX_OSERR;
		}

		memset(keydata, '\0', s.st_size + 1);
		rlen = read(fd, keydata, s.st_size);
		if (rlen == -1)
		{
			fprintf(stderr, "%s: %s: read(): %s\n", progname,
			        keyfile, strerror(errno));
			close(fd);
			free(keydata);
			return EX_OSERR;
		}
		else if (rlen < s.st_size)
		{
			fprintf(stderr,
			        "%s: %s: read() truncated (got %lu, expected %lu)\n",
			        progname, keyfile, (unsigned long) rlen,
			        (unsigned long) s.st_size);
			close(fd);
			free(keydata);
			return EX_DATAERR;
		}

		close(fd);
	}

	lib = dkim_init(NULL, NULL);
	if (lib == NULL)
	{
		fprintf(stderr, "%s: dkim_init() failed\n", progname);
		return EX_SOFTWARE;
	}

	if (n == 0)
	{
		dkim = dkim_verify(lib, (u_char *) progname, NULL, &status);
		if (dkim == NULL)
		{
			fprintf(stderr, "%s: dkim_verify() failed: %s\n",
			        progname, dkim_getresultstr(status));
			dkim_close(lib);
			return EX_SOFTWARE;
		}
	}
	else
	{
		dkim = dkim_sign(lib, (u_char *) progname, NULL,
		                 (u_char *) keydata, (const u_char *) selector,
		                 (const u_char *) domain, hc, bc, sa, l, &status);
		if (dkim == NULL)
		{
			fprintf(stderr, "%s: dkim_sign() failed: %s\n",
			        progname, dkim_getresultstr(status));
			if (keydata != NULL)
				free(keydata);
			dkim_close(lib);
			return EX_SOFTWARE;
		}
	}

	/* set flags */
	flags = (DKIM_LIBFLAGS_FIXCRLF|DKIM_LIBFLAGS_STRICTHDRS);
	if (keepfiles)
		flags |= (DKIM_LIBFLAGS_TMPFILES|DKIM_LIBFLAGS_KEEPFILES);
	(void) dkim_setopt(lib, DKIM_OPTS_FLAGS, &flags,
	                    sizeof flags);

	tfd = mkstemp(fn);
	if (tfd < 0)
	{
		fprintf(stderr, "%s: mkstemp(): %s\n",
		        progname, strerror(errno));
		if (keydata != NULL)
			free(keydata);
		dkim_close(lib);
		return EX_SOFTWARE;
	}

	(void) unlink(fn);

	for (;;)
	{
		rlen = fread(buf, 1, sizeof buf, stdin);

		if (ferror(stdin))
		{
			fprintf(stderr, "%s: fread(): %s\n",
			        progname, strerror(errno));
			dkim_free(dkim);
			dkim_close(lib);
			close(tfd);
			if (keydata != NULL)
				free(keydata);
			return EX_SOFTWARE;
		}

		if (rlen > 0)
		{
			wlen = write(tfd, buf, rlen);
			if (wlen == -1)
			{
				fprintf(stderr, "%s: %s: write(): %s\n",
				        progname, fn, strerror(errno));
				dkim_free(dkim);
				dkim_close(lib);
				close(tfd);
				if (keydata != NULL)
					free(keydata);
				return EX_SOFTWARE;
			}

			status = dkim_chunk(dkim, (u_char *) buf, rlen);
			if (status != DKIM_STAT_OK)
			{
				fprintf(stderr, "%s: dkim_chunk(): %s\n",
				        progname, dkim_getresultstr(status));
				dkim_free(dkim);
				dkim_close(lib);
				close(tfd);
				if (keydata != NULL)
					free(keydata);
				return EX_SOFTWARE;
			}
		}

		if (feof(stdin))
			break;
	}

	status = dkim_chunk(dkim, NULL, 0);
	if (status != DKIM_STAT_OK)
	{
		fprintf(stderr, "%s: dkim_chunk(): %s\n",
		        progname, dkim_getresultstr(status));
		dkim_free(dkim);
		dkim_close(lib);
		close(tfd);
		if (keydata != NULL)
			free(keydata);
		return EX_SOFTWARE;
	}

	status = dkim_eom(dkim, &testkey);
	/*
	**  In verify mode a failed-but-fully-evaluated signature
	**  (BADSIG/NOKEY/REVOKED/KEYFAIL) is a verification result we want to
	**  report, not a library error; let those statuses fall through to the
	**  reporting block below.  Everything else, and any error while signing,
	**  is fatal.
	*/
	if (status != DKIM_STAT_OK &&
	    !(n == 0 && (status == DKIM_STAT_BADSIG ||
	                 status == DKIM_STAT_NOKEY ||
	                 status == DKIM_STAT_REVOKED ||
	                 status == DKIM_STAT_KEYFAIL)))
	{
		fprintf(stderr, "%s: dkim_eom(): %s\n",
		        progname, dkim_getresultstr(status));
		dkim_free(dkim);
		dkim_close(lib);
		close(tfd);
		if (keydata != NULL)
			free(keydata);
		return EX_SOFTWARE;
	}

	if (n == 0)
	{
		_Bool pass;
		int bh;
		int dnssec;
		unsigned int sigflags;
		unsigned int keybits = 0;
		uint64_t sigtime = 0;
		dkim_alg_t alg = DKIM_SIGN_RSASHA256;
		dkim_canon_t hcanon = DKIM_CANON_SIMPLE;
		dkim_canon_t bcanon = DKIM_CANON_SIMPLE;
		DKIM_SIGINFO *sig;
		u_char *sigdomain;
		u_char *sigselector;

		sig = dkim_getsignature(dkim);
		if (sig == NULL)
		{
			fprintf(stderr, "%s: no signature found\n", progname);
			dkim_free(dkim);
			dkim_close(lib);
			close(tfd);
			if (keydata != NULL)
				free(keydata);
			return EX_UNAVAILABLE;
		}

		sigflags = dkim_sig_getflags(sig);
		bh = dkim_sig_getbh(sig);
		dnssec = dkim_sig_getdnssec(sig);
		sigdomain = dkim_sig_getdomain(sig);
		sigselector = dkim_sig_getselector(sig);
		(void) dkim_sig_getsignalg(sig, &alg);
		(void) dkim_sig_getcanons(sig, &hcanon, &bcanon);
		(void) dkim_sig_getkeysize(sig, &keybits);
		(void) dkim_sig_getsigntime(sig, &sigtime);

		pass = ((sigflags & DKIM_SIGFLAG_PASSED) != 0 &&
		        bh == DKIM_SIGBH_MATCH);

		if (verbose > 0)
		{
			fprintf(stdout, "%s: verification details:\n", progname);
			fprintf(stdout, "\tdomain:          %s\n",
			        STRORNULL((char *) sigdomain));
			fprintf(stdout, "\tselector:        %s\n",
			        STRORNULL((char *) sigselector));
			fprintf(stdout, "\talgorithm:       %s\n",
			        sigalg_name(alg));
			fprintf(stdout, "\tcanon. (hdr/body): %s/%s\n",
			        canon_name(hcanon), canon_name(bcanon));
			if (keybits > 0)
				fprintf(stdout, "\tkey size:        %u bits\n",
				        keybits);
			fprintf(stdout, "\tbody hash:       %s\n",
			        bh == DKIM_SIGBH_MATCH ? "match" :
			        bh == DKIM_SIGBH_MISMATCH ? "MISMATCH" :
			        "untested");
			if (sigtime > 0)
				fprintf(stdout, "\tsignature time:  %llu\n",
				        (unsigned long long) sigtime);
			fprintf(stdout, "\tDNSSEC:          %s\n",
			        dnssec_name(dnssec));
			fprintf(stdout, "\tresult:          %s\n",
			        pass ? "pass" : "fail");
		}

		if (!pass)
		{
			if (verbose == 0)
				fprintf(stderr, "%s: verification failed: %s\n",
				        progname,
				        dkim_sig_geterrorstr(dkim_sig_geterror(sig)));
			retval = EX_DATAERR;
		}
	}
	else
	{
		unsigned char *sighdr;
		size_t siglen;

		/* extract signature */
		status = dkim_getsighdr_d(dkim,
		                          strlen(DKIM_SIGNHEADER),
		                          &sighdr, &siglen);
		if (status != DKIM_STAT_OK)
		{
			fprintf(stderr, "%s: dkim_getsighdr_d(): %s\n",
			        progname, dkim_getresultstr(status));
			dkim_free(dkim);
			dkim_close(lib);
			close(tfd);
			if (keydata != NULL)
				free(keydata);
			return EX_SOFTWARE;
		}

		/* print it and the message */
		if (!keepcrlf)
			decr((char *) sighdr);
		fprintf(stdout, "%s: %s%s\n", DKIM_SIGNHEADER, sighdr,
		        keepcrlf ? "\r" : "");
		(void) lseek(tfd, 0, SEEK_SET);
		for (;;)
		{
			rlen = read(tfd, buf, sizeof buf);
			/*
			**  rlen is ssize_t; passing a negative value as
			**  fwrite()'s nmemb (size_t) would copy garbage past
			**  the buffer, and bare rlen < sizeof buf would
			**  cast the negative to a huge size_t and loop.
			**  Bail on read error or EOF first.
			*/
			if (rlen <= 0)
				break;
			(void) fwrite(buf, 1, (size_t) rlen, stdout);
			if ((size_t) rlen < sizeof buf)
				break;
		}
	}

	dkim_free(dkim);
	dkim_close(lib);
	close(tfd);
	if (keydata != NULL)
		free(keydata);

	return retval;
}
