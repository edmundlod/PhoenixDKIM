#!/bin/bash
# deploy-release.sh — upload PhoenixDKIM release artifacts and archive them locally.
#
# Usage:
#   deploy-release.sh <tag>   (e.g. deploy-release.sh v3.0.0-beta13)
#
# Configuration:
#   ~/releases/deploy-release.local must set two variables:
#
#     DEST_APT      rsync destination for the reprepro repo tree (dists/ + pool/)
#                   e.g. user@www.phoenixdkim.org:/srv/apt/phoenixdkim/
#
#     DEST_TARBALL  rsync destination for the source tarball and .asc signature
#                   e.g. user@www.phoenixdkim.org:/srv/www/releases/
#
# The reprepro repo at ~/releases/repo/ is rsynced as a whole (db/ excluded).
# After a successful upload the source tarball and .asc are moved into
# ~/releases/archive/<tag>/; the reprepro tree is left in place.

set -euo pipefail

# ── arguments ─────────────────────────────────────────────────────────────────

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <tag>   (e.g. $0 v3.0.0-beta13)" >&2
    exit 1
fi

TAG="$1"
RELEASES_DIR="$HOME/releases"
REPO_DIR="$RELEASES_DIR/repo"
LOCAL_CFG="$RELEASES_DIR/deploy-release.local"

# ── config ────────────────────────────────────────────────────────────────────

if [[ ! -f "$LOCAL_CFG" ]]; then
    cat >&2 <<EOF
Error: $LOCAL_CFG not found.

Create it with the two destination variables, e.g.:

  DEST_APT="user@www.phoenixdkim.org:/srv/apt/phoenixdkim/"
  DEST_TARBALL="user@www.phoenixdkim.org:/srv/www/releases/"

EOF
    exit 1
fi

# shellcheck source=/dev/null
source "$LOCAL_CFG"

if [[ -z "${DEST_APT:-}" || -z "${DEST_TARBALL:-}" ]]; then
    echo "Error: $LOCAL_CFG must set both DEST_APT and DEST_TARBALL." >&2
    exit 1
fi

# ── derive version from tag (strip leading 'v') ───────────────────────────────

UPSTREAM="${TAG#v}"          # 3.0.0-beta13

# ── locate artifacts ──────────────────────────────────────────────────────────

TARBALL="$RELEASES_DIR/phoenixdkim-${UPSTREAM}.tar.gz"
TARBALL_ASC="${TARBALL}.asc"

echo "==> Tag:      $TAG"
echo "==> Upstream: $UPSTREAM"
echo ""

# Validate everything is present before touching the network
missing=0

for f in "$TARBALL" "$TARBALL_ASC"; do
    if [[ ! -f "$f" ]]; then
        echo "Missing: $f" >&2
        missing=1
    fi
done

if [[ ! -d "$REPO_DIR/dists" || ! -d "$REPO_DIR/pool" ]]; then
    echo "Missing: reprepro repo not found at $REPO_DIR" >&2
    missing=1
fi

if [[ $missing -ne 0 ]]; then
    echo "" >&2
    echo "Run contrib/build-release.sh $TAG first." >&2
    exit 1
fi

# ── upload ────────────────────────────────────────────────────────────────────

echo "==> Uploading source tarball and signature to: $DEST_TARBALL"
rsync -av --progress \
    "$TARBALL" \
    "$TARBALL_ASC" \
    "$DEST_TARBALL"

echo ""
echo "==> Uploading apt repo to: $DEST_APT"
# Exclude db/ — reprepro's local database, not needed by apt clients
rsync -av --progress --delete \
    --exclude="db/" \
    "$REPO_DIR/" \
    "$DEST_APT"

# ── archive tarball locally ───────────────────────────────────────────────────

ARCHIVE_DIR="$RELEASES_DIR/archive/$TAG"
mkdir -p "$ARCHIVE_DIR"

echo ""
echo "==> Archiving tarball to: $ARCHIVE_DIR"
mv "$TARBALL" "$TARBALL_ASC" "$ARCHIVE_DIR/"

echo ""
echo "==> Done."
echo "    Apt repo:  $DEST_APT  (reprepro tree at $REPO_DIR remains in place)"
echo "    Tarball:   archived to $ARCHIVE_DIR"
ls -lh "$ARCHIVE_DIR"
