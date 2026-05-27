#!/bin/bash
# deploy-release.sh — upload PhoenixDKIM release artifacts and archive them locally.
#
# Usage:
#   deploy-release.sh <tag>   (e.g. deploy-release.sh v3.0.0-beta13)
#
# Configuration:
#   ~/releases/deploy-release.local must export two variables:
#
#     DEST_APT      rsync destination for .deb/.changes/.buildinfo
#                   e.g. user@www.phoenixdkim.org:/srv/apt/phoenixdkim/trixie/
#
#     DEST_TARBALL  rsync destination for source tarball and .asc
#                   e.g. user@www.phoenixdkim.org:/srv/www/releases/
#
# After a successful upload, all matched artifacts are moved into
# ~/releases/archive/<tag>/ to keep the working directory clean.

set -euo pipefail

# ── arguments ─────────────────────────────────────────────────────────────────

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <tag>   (e.g. $0 v3.0.0-beta13)" >&2
    exit 1
fi

TAG="$1"
RELEASES_DIR="$HOME/releases"
LOCAL_CFG="$RELEASES_DIR/deploy-release.local"

# ── config ────────────────────────────────────────────────────────────────────

if [[ ! -f "$LOCAL_CFG" ]]; then
    cat >&2 <<EOF
Error: $LOCAL_CFG not found.

Create it with the two destination variables, e.g.:

  DEST_APT="user@www.phoenixdkim.org:/srv/apt/phoenixdkim/trixie/"
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

UPSTREAM="${TAG#v}"                           # 3.0.0-beta13
# Debian epoch/revision: upstream with ~ substituted for the first -
DEB_UPSTREAM="${UPSTREAM/-/\~}"               # 3.0.0~beta13
# Debian full version as produced by build-release.sh: 3.0.0~beta13-ng1
DEB_VERSION="${DEB_UPSTREAM}-ng1"

# ── locate artifacts ──────────────────────────────────────────────────────────

TARBALL="$RELEASES_DIR/phoenixdkim-${UPSTREAM}.tar.gz"
TARBALL_ASC="${TARBALL}.asc"

# Collect .deb / .changes / .buildinfo by Debian version string
mapfile -t DEB_FILES < <(
    find "$RELEASES_DIR" -maxdepth 1 \( \
        -name "phoenixdkim_${DEB_VERSION}*.deb" \
        -o -name "phoenixdkim-miltertest_${DEB_VERSION}*.deb" \
        -o -name "libphoenixdkim_${DEB_VERSION}*.deb" \
        -o -name "libphoenixdkim-dev_${DEB_VERSION}*.deb" \
        -o -name "phoenixdkim_${DEB_VERSION}*.changes" \
        -o -name "phoenixdkim_${DEB_VERSION}*.buildinfo" \
    \) | sort
)

echo "==> Tag:      $TAG"
echo "==> Upstream: $UPSTREAM"
echo "==> Debian:   $DEB_VERSION"
echo ""

# Validate everything is present before touching the network
missing=0

for f in "$TARBALL" "$TARBALL_ASC"; do
    if [[ ! -f "$f" ]]; then
        echo "Missing: $f" >&2
        missing=1
    fi
done

if [[ ${#DEB_FILES[@]} -eq 0 ]]; then
    echo "Missing: no .deb/.changes/.buildinfo found for $DEB_VERSION in $RELEASES_DIR" >&2
    missing=1
fi

if [[ $missing -ne 0 ]]; then
    echo "" >&2
    echo "Run contrib/build-release.sh $TAG first." >&2
    exit 1
fi

echo "==> Artifacts to deploy:"
printf "    %s\n" "$TARBALL" "$TARBALL_ASC" "${DEB_FILES[@]}"
echo ""

# ── upload ────────────────────────────────────────────────────────────────────

echo "==> Uploading source tarball and signature to: $DEST_TARBALL"
rsync -av --progress \
    "$TARBALL" \
    "$TARBALL_ASC" \
    "$DEST_TARBALL"

echo ""
echo "==> Uploading packages to: $DEST_APT"
rsync -av --progress \
    "${DEB_FILES[@]}" \
    "$DEST_APT"

# ── archive locally ───────────────────────────────────────────────────────────

ARCHIVE_DIR="$RELEASES_DIR/archive/$TAG"
mkdir -p "$ARCHIVE_DIR"

echo ""
echo "==> Archiving artifacts to: $ARCHIVE_DIR"
mv "$TARBALL" "$TARBALL_ASC" "${DEB_FILES[@]}" "$ARCHIVE_DIR/"

echo ""
echo "==> Done. $RELEASES_DIR is clean."
echo "    Archived to: $ARCHIVE_DIR"
ls -lh "$ARCHIVE_DIR"
