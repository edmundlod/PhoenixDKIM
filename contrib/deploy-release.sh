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
#
# The loose Debian build by-products that dpkg-buildpackage/sbuild scatter in
# ~/releases/ (.deb, .changes, .buildinfo, .build, .dsc, .debian.tar.*,
# .orig.tar.*) are then deleted: the packages already live in the reprepro
# pool, and everything else is regenerable by re-running build-release.sh.
# Deletion is scoped to this version and only fires once the version's .debs
# are confirmed present in the reprepro pool.

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

UPSTREAM="${TAG#v}"                 # 3.0.0-beta13
# Debian upstream version uses a tilde where the public tarball uses a dash.
DEB_UPSTREAM="${UPSTREAM/-/\~}"     # 3.0.0~beta13

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

# ── clean build by-products ───────────────────────────────────────────────────
# Only delete once this version's .debs are confirmed in the reprepro pool, so
# a skipped/failed reprepro include can never leave us with no copy at all.

echo ""
if find "$REPO_DIR/pool" -name "*_${DEB_UPSTREAM}-*.deb" 2>/dev/null | grep -q .; then
    mapfile -t LITTER < <(
        find "$RELEASES_DIR" -maxdepth 1 \( \
            -name "*_${DEB_UPSTREAM}-*_*.deb" \
            -o -name "*_${DEB_UPSTREAM}-*_*.build" \
            -o -name "*_${DEB_UPSTREAM}-*_*.buildinfo" \
            -o -name "*_${DEB_UPSTREAM}-*_*.changes" \
            -o -name "phoenixdkim_${DEB_UPSTREAM}-*.dsc" \
            -o -name "phoenixdkim_${DEB_UPSTREAM}-*.debian.tar.*" \
            -o -name "phoenixdkim_${DEB_UPSTREAM}.orig.tar.*" \
        \)
    )
    if [[ ${#LITTER[@]} -gt 0 ]]; then
        echo "==> Removing build by-products for $DEB_UPSTREAM (in reprepro pool / regenerable):"
        printf "    %s\n" "${LITTER[@]}"
        rm -f "${LITTER[@]}"
    else
        echo "==> No loose build by-products to remove."
    fi
else
    echo "==> WARNING: no $DEB_UPSTREAM .debs found in $REPO_DIR/pool;" >&2
    echo "    leaving build by-products in place (reprepro include may have been skipped)." >&2
fi

echo ""
echo "==> Done."
echo "    Apt repo:  $DEST_APT  (reprepro tree at $REPO_DIR remains in place)"
echo "    Tarball:   archived to $ARCHIVE_DIR"
ls -lh "$ARCHIVE_DIR"
