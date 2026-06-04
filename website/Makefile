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
#   make check  - check for dead links (only internal, not to github.com or so)
#   make deploy — rsync to server (edit DEST in `website.local.mk`)

-include website.local.mk

SHELL   = /bin/bash
TMPL    = src/template.html
OUTDIR  = out

# Product version, single-sourced from the library's CMake version block, so the
# generated man pages always state the PhoenixDKIM version they were built from
# without a second place to bump at release time.
VER_SRC := ../libphoenixdkim/CMakeLists.txt
PHOENIXDKIM_VERSION := $(shell sed -n 's/^set(VERSION_RELEASE *\([0-9][0-9]*\)).*/\1/p' $(VER_SRC)).$(shell sed -n 's/^set(VERSION_MAJOR_REV *\([0-9][0-9]*\)).*/\1/p' $(VER_SRC)).$(shell sed -n 's/^set(VERSION_MINOR_REV *\([0-9][0-9]*\)).*/\1/p' $(VER_SRC))

# ── regular pages ────────────────────────────────────────────────────────────

PAGES = \
    index \
    features \
    announcements \
    download \
    quickstart \
    documentation \
    coming-from \
    removed-features \
    packages \
    contributing \
    security

HTML = $(patsubst %,$(OUTDIR)/%.html,$(PAGES))

# ── guides (rendered from ../docs/*.md, the single source) ────────────────────
# The Markdown guides live in ../docs so the repository keeps one copy that is
# also readable on the code host; the website is their authoritative published
# form. Rendered with pandoc into out/guides/ and wrapped in the site template.

GUIDES    = key-rotation multisigning crypto-policy metrics
GUIDE_HTML = $(patsubst %,$(OUTDIR)/guides/%.html,$(GUIDES))

# ── man pages ─────────────────────────────────────────────────────────────────
# Find all .3 .5 .8 files in the repo, excluding build/ directories

MANPAGES    := $(shell find .. -name '*.[358]' -not -path '*/build/*')
MANHTML     := $(patsubst %,$(OUTDIR)/man/%.html,$(notdir $(MANPAGES)))

# ── announcement pages ────────────────────────────────────────────────────────

ANN_SRCS := $(wildcard src/announcements/*.content.html)
ANN_HTML := $(patsubst src/announcements/%.content.html,$(OUTDIR)/announcements/%.html,$(ANN_SRCS))

# ── release notes (plain-text static files) ──────────────────────────────────

RN_SRCS := $(wildcard src/release_notes/*)
RN_OUT  := $(patsubst src/release_notes/%,$(OUTDIR)/release_notes/%,$(RN_SRCS))

# ── favicon files ────────────────────────────────────────────────────────────

FAVICON_SRCS := $(wildcard src/favicon/*)
FAVICON_OUT  := $(patsubst src/favicon/%,$(OUTDIR)/%,$(FAVICON_SRCS))

# ── well-known / static assets ───────────────────────────────────────────────

WELLKNOWN_DIR   = $(OUTDIR)/.well-known
WELLKNOWN_FILES = $(WELLKNOWN_DIR)/security.txt

STATIC_FILES = $(OUTDIR)/phoenixdkim-security.asc $(OUTDIR)/phoenixdkim-releases.asc $(OUTDIR)/phoenixdkim-logo.png

# ── targets ───────────────────────────────────────────────────────────────────

all: $(OUTDIR) $(OUTDIR)/man $(OUTDIR)/announcements $(OUTDIR)/release_notes \
     $(OUTDIR)/guides $(WELLKNOWN_DIR) \
     $(HTML) $(GUIDE_HTML) $(MANHTML) $(ANN_HTML) $(RN_OUT) $(FAVICON_OUT) $(WELLKNOWN_FILES) $(STATIC_FILES)
	@$(MAKE) --no-print-directory check-links

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/man:
	mkdir -p $(OUTDIR)/man

$(OUTDIR)/announcements:
	mkdir -p $(OUTDIR)/announcements

$(OUTDIR)/guides:
	mkdir -p $(OUTDIR)/guides

$(OUTDIR)/release_notes:
	mkdir -p $(OUTDIR)/release_notes

$(WELLKNOWN_DIR):
	mkdir -p $(WELLKNOWN_DIR)

$(WELLKNOWN_DIR)/security.txt: src/security.txt | $(WELLKNOWN_DIR)
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/phoenixdkim-security.asc: src/phoenixdkim-security.asc | $(OUTDIR)
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/phoenixdkim-releases.asc: src/phoenixdkim-releases.asc | $(OUTDIR)
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/phoenixdkim-logo.png: src/phoenixdkim-logo.png | $(OUTDIR)
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/release_notes/%: src/release_notes/% | $(OUTDIR)/release_notes
	cp $< $@
	@echo "  built $@"

$(OUTDIR)/%: src/favicon/% | $(OUTDIR)
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

# Guides: render ../docs/<name>.md with pandoc (GFM in, HTML fragment out) and
# wrap in the site template. The page title is taken from the document's first
# level-1 heading. Code highlighting is disabled so code blocks inherit the
# site's plain <pre> styling.

$(OUTDIR)/guides/%.html: ../docs/%.md $(TMPL) | $(OUTDIR)/guides
	@title=$$(sed -n 's/^# //p' $< | head -1); \
	[ -n "$$title" ] || title="$*"; \
	tmpfile=$$(mktemp); \
	pandoc -f gfm -t html --no-highlight --wrap=preserve $< -o $$tmpfile; \
	sed -i 's#href="\([^":]*\)\.md"#href="\1.html"#g' $$tmpfile; \
	if grep -qE 'href="[^"]*\.md"' $$tmpfile; then \
	    echo "  WARNING: $< has a .md link the rewrite left alone (external?); check it resolves on the site:"; \
	    grep -oE 'href="[^"]*\.md"' $$tmpfile | sed 's/^/    /'; \
	fi; \
	sed \
	    -e "s|%%TITLE%%|$$title|g" \
	    -e "/%%CONTENT%%/{r $$tmpfile" -e "d}" \
	    $(TMPL) > $@; \
	rm $$tmpfile
	@echo "  built $@"

# Man pages: use groff -T html, inject fork notice, wrap in template
#   groff cleanup:
#   1. save Creator/CreationDate comments to append at bottom
#   2. strip everything before <h2>NAME (head, body tag, h1 title, TOC, hr)
#   3. strip </body> and </html>
# SECONDEXPANSION lets the prerequisite name the matching man-page source by
# stem, so editing a .8/.5/.3 in the project regenerates its HTML (the recipe's
# $(eval MANSRC ...) alone created no dependency).
.SECONDEXPANSION:
$(OUTDIR)/man/%.html: $$(foreach m,$(MANPAGES),$$(if $$(filter $$*,$$(notdir $$m)),$$m)) $(TMPL) src/fork-notice.html | $(OUTDIR)/man
	$(eval MANSRC := $(filter %/$*,$(MANPAGES)))
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
	printf '<hr>\nThis document was generated from the PhoenixDKIM %s manual pages using groff.<br>\nTime: %s\n' "$(PHOENIXDKIM_VERSION)" "$$credate" >> $$tmpfile; \
	rm $$groftmp; \
	sed \
	    -e "s|%%TITLE%%|$$name|g" \
	    -e "/%%CONTENT%%/{r $$tmpfile" -e "d}" \
	    $(TMPL) > $@; \
	rm $$tmpfile
	@echo "  built $@"

check: all
	linkchecker out/index.html

# Dependency-free internal-link audit over the built site. Warns (never fails)
# about any on-page href/src that points at a local file missing from $(OUTDIR)
# -- the case that bit us when a referenced .asc was not copied by the build.
# Runs automatically at the end of `all`, and can be run on its own.
# External links (scheme://, mailto:, …) are out of scope; use `check` for
# those. /releases/ is skipped: release tarballs and their signatures are placed
# on the server at deploy time and are intentionally absent from a local build.
check-links:
	@echo "  checking internal links…"; \
	n=0; \
	while IFS= read -r f; do \
	    dir=$$(dirname "$$f"); \
	    while IFS= read -r link; do \
	        case "$$link" in \
	            ""|"#"*|*"://"*|mailto:*|tel:*|data:*|javascript:*|/releases/*) continue;; \
	        esac; \
	        link=$${link%%#*}; link=$${link%%\?*}; \
	        [ -z "$$link" ] && continue; \
	        case "$$link" in \
	            /*) target="$(OUTDIR)$$link";; \
	            *)  target="$$dir/$$link";; \
	        esac; \
	        case "$$link" in */) target="$$target/index.html";; esac; \
	        target=$$(realpath -m "$$target"); \
	        [ -d "$$target" ] && target="$$target/index.html"; \
	        if [ ! -e "$$target" ]; then \
	            echo "  WARNING: dead link in $$f -> $$link"; \
	            n=$$((n+1)); \
	        fi; \
	    done < <(grep -oE '(href|src)="[^"]+"' "$$f" | sed -E 's/^(href|src)="//; s/"$$//'); \
	done < <(find $(OUTDIR) -name '*.html'); \
	if [ $$n -eq 0 ]; then echo "  internal links OK"; \
	else echo "  $$n dead internal link(s) found — eyeball the warnings above"; fi

deploy: all
	rsync -avz --delete \
	    --exclude=/releases/ \
	    $(OUTDIR)/ $(DEST)

clean:
	rm -rf $(OUTDIR)

.PHONY: all check check-links deploy clean
