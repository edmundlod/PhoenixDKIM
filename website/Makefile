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

# ── well-known / static assets ───────────────────────────────────────────────

WELLKNOWN_DIR   = $(OUTDIR)/.well-known
WELLKNOWN_FILES = $(WELLKNOWN_DIR)/security.txt

STATIC_FILES = $(OUTDIR)/phoenixdkim-security.asc

# ── targets ───────────────────────────────────────────────────────────────────

all: $(OUTDIR) $(OUTDIR)/man $(OUTDIR)/announcements $(WELLKNOWN_DIR) \
     $(HTML) $(MANHTML) $(ANN_HTML) $(WELLKNOWN_FILES) $(STATIC_FILES)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/man:
	mkdir -p $(OUTDIR)/man

$(OUTDIR)/announcements:
	mkdir -p $(OUTDIR)/announcements

$(WELLKNOWN_DIR):
	mkdir -p $(WELLKNOWN_DIR)

$(WELLKNOWN_DIR)/security.txt: src/security.txt | $(WELLKNOWN_DIR)
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/phoenixdkim-security.asc: src/phoenixdkim-security.asc | $(OUTDIR)
	cp $< $@
	@echo "  built $@"

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

# Man pages: use groff -T html, inject fork notice, wrap in template
#   groff cleanup:
#   1. save Creator/CreationDate comments to append at bottom
#   2. strip everything before <h2>NAME (head, body tag, h1 title, TOC, hr)
#   3. strip </body> and </html>
$(OUTDIR)/man/%.html: $(TMPL)
	$(eval MANSRC := $(filter %/$(patsubst $(OUTDIR)/man/%.html,%,$@),$(MANPAGES)))
	@name=$(patsubst $(OUTDIR)/man/%.html,%,$@); \
	tmpfile=$$(mktemp); \
	groftmp=$$(mktemp); \
	groff -man -T html $(MANSRC) 2>/dev/null > $$groftmp; \
	credate=$$(sed -n 's/<!-- CreationDate: \(.*\) -->/\1/p' $$groftmp); \
	cat src/fork-notice.html > $$tmpfile; \
	sed \
		-e '1,/<h2>NAME/{ /<h2>NAME/!d }' \
		-e '/<hr>/{N;/\n<\/body>/d}' \
		-e '/<\/body>/,$$d' \
		-e '/<\/html>/d' \
		$$groftmp \
	>> $$tmpfile; \
	printf '<hr>\nThis document was created from the manual pages using groff.<br>\nTime: %s\n' "$$credate" >> $$tmpfile; \
	rm $$groftmp; \
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
