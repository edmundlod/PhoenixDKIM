# Copyright (c) 2026, PhoenixDKIM contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


# PhoenixDKIM website build
# Usage:
#   make        — build all pages and man pages
#   make clean  — remove output
#   make deploy — rsync to server (edit DEST in `website.local.mk`)

-include website.local.mk

SHELL   = /bin/bash
TMPL    = src/template.html
OUTDIR  = out

# ── regular pages ────────────────────────────────────────────────────────────

PAGES = \
    index \
    announcements \
    download \
    documentation \
    packages \
    contributing \
    security

HTML = $(patsubst %,$(OUTDIR)/%.html,$(PAGES))

# ── man pages ─────────────────────────────────────────────────────────────────
# Find all .3 .5 .8 files in the repo, excluding build/ directories

MANPAGES    := $(shell find .. -name '*.[358]' -not -path '*/build/*')
MANHTML     := $(patsubst %,$(OUTDIR)/man/%.html,$(notdir $(MANPAGES)))

# ── announcement pages ────────────────────────────────────────────────────────

ANN_SRCS := $(wildcard src/announcements/*.content.html)
ANN_HTML := $(patsubst src/announcements/%.content.html,$(OUTDIR)/announcements/%.html,$(ANN_SRCS))

# ── targets ───────────────────────────────────────────────────────────────────

all: $(OUTDIR) $(OUTDIR)/man $(OUTDIR)/announcements $(HTML) $(MANHTML) $(ANN_HTML)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/man:
	mkdir -p $(OUTDIR)/man

$(OUTDIR)/announcements:
	mkdir -p $(OUTDIR)/announcements

$(OUTDIR)/announcements/%.html: src/announcements/%.content.html $(TMPL) | $(OUTDIR)/announcements
	@page=$*; \
	titlefile=src/announcements/$$page.title; \
	if [ -f "$$titlefile" ]; then \
	    title=$$(cat "$$titlefile"); \
	else \
	    title=$$page; \
	fi; \
	sed \
	    -e "s|%%TITLE%%|$$title|g" \
	    -e "/%%CONTENT%%/{r src/announcements/$$page.content.html" -e "d}" \
	    $(TMPL) > $@
	@echo "  built $@"

# Regular pages: substitute %%TITLE%% from .title file, %%CONTENT%% from .content.html

$(OUTDIR)/%.html: src/%.content.html $(TMPL)
	@page=$*; \
	titlefile=src/$$page.title; \
	if [ -f "$$titlefile" ]; then \
	    title=$$(cat "$$titlefile"); \
	else \
	    title=$$page; \
	fi; \
	sed \
	    -e "s|%%TITLE%%|$$title|g" \
	    -e "/%%CONTENT%%/{r src/$$page.content.html" -e "d}" \
	    $(TMPL) > $@
	@echo "  built $@"

# Man pages: strip man2html wrapper, inject fork notice, wrap in template

# man2html sed cleanup below:
#   1. strip everything before <BODY> (man2html html header)
#   2. strip everything after </BODY>
#   3. remove "Return to Main Contents" link
#   4. join <HR> with following index anchor so rule 5 can strip the <HR> too
#   5. strip index block (<A NAME="index"> through </DL>)
#   6. strip man2html's own header (H1 + Section/Updated line) before first section
#   7. remove empty named anchors (&nbsp;) used as section targets
#   8. remove mailto: links auto-generated from node@host patterns
$(OUTDIR)/man/%.html: $(TMPL)
	$(eval MANSRC := $(filter %/$(patsubst $(OUTDIR)/man/%.html,%,$@),$(MANPAGES)))
	@name=$(patsubst $(OUTDIR)/man/%.html,%,$@); \
	tmpfile=$$(mktemp); \
	cat src/fork-notice.html > $$tmpfile; \
	man2html $(MANSRC) \
	| sed \
		-e '1,/<BODY/d' \
		-e '/<\/BODY/,$$d' \
		-e '/<A HREF="\/man\/man2html/d' \
		-e '/<HR>/{N;s/<HR>\n<A NAME="index">/<A NAME="index">/}' \
		-e '/<A NAME="index">/,/<\/DL>/d' \
		-e '1,/<A NAME="lbAB"/{ /<A NAME="lbAB"/!d }' \
		-e 's/<A NAME="[^"]*">&nbsp;<\/A>//g' \
		-e 's/<A HREF="mailto:[^"]*">\([^<]*\)<\/A>/\1/g' \
	>> $$tmpfile; \
	sed \
	    -e "s|%%TITLE%%|$$name|g" \
	    -e "/%%CONTENT%%/{r $$tmpfile" -e "d}" \
	    $(TMPL) > $@; \
	rm $$tmpfile
	@echo "  built $@"

deploy: all
	rsync -avz --delete $(OUTDIR)/ $(DEST)

clean:
	rm -rf $(OUTDIR)

.PHONY: all deploy clean
