#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <tag>   (e.g. $0 v3.0.0-beta12)" >&2
    exit 1
fi

TAG="$1"
RELEASES_DIR="$HOME/releases"
SRC_DIR="$RELEASES_DIR/PhoenixDKIM"
KEYID="9FF41A44270A1D88226E50F3E75C78A28F60F730"

cd "$SRC_DIR"
git fetch --tags
git checkout "$TAG"

VERSION=$(dpkg-parsechangelog -S Version)
SOURCE_PKG=$(dpkg-parsechangelog -S Source)
# Derive upstream version from the tag (strip leading 'v'), not from
# dpkg-parsechangelog, which would give a Debian-style tilde (3.0.0~beta13).
# Public tarballs use a dash: phoenixdkim-3.0.0-beta13.tar.gz.
UPSTREAM="${TAG#v}"                                                                                                                                 

# 3.0 (quilt) requires an orig tarball to exist before sbuild can package the source
ORIG_TARBALL="$RELEASES_DIR/${SOURCE_PKG}_${UPSTREAM}.orig.tar.gz"
echo "==> Creating orig tarball: $(basename "$ORIG_TARBALL")"
git archive --prefix="${SOURCE_PKG}-${UPSTREAM}/" HEAD | gzip -9 > "$ORIG_TARBALL"

echo "==> Updating chroot"
#mmdebstrap --variant=buildd trixie "$HOME/releases/chroots/trixie.tar.xz"

echo "==> Building PhoenixDKIM $VERSION"

if command -v sbuild &>/dev/null; then
    echo "==> Using sbuild (clean chroot)"
    sbuild \
        --dist=trixie \
        --chroot-mode=unshare \
        --chroot="$RELEASES_DIR/chroots/trixie.tar.xz" \
        --no-clean-source \
        --keyid="$KEYID"
else
    echo "==> sbuild not available, building directly"
    dpkg-buildpackage -b -k"$KEYID"
fi

# Add packages to reprepro apt repo
REPO_DIR="$RELEASES_DIR/repo"
if [[ -d "$REPO_DIR/conf" ]]; then
    echo "==> Updating apt repo"
    reprepro -b "$REPO_DIR" include trixie "$RELEASES_DIR/${SOURCE_PKG}_${VERSION}_amd64.changes"
fi

# Source tarball
TARBALL="$RELEASES_DIR/phoenixdkim-${UPSTREAM}.tar.gz"
git archive --prefix="phoenixdkim-${UPSTREAM}/" HEAD \
    | gzip -9 > "$TARBALL"
gpg --armor --detach-sign --local-user "$KEYID" "$TARBALL"

echo ""
echo "==> Artifacts in $RELEASES_DIR:"
ls -lh "$RELEASES_DIR"/*.deb "$RELEASES_DIR"/*.changes \
        "$RELEASES_DIR"/*.buildinfo \
        "$TARBALL" "${TARBALL}.asc" 2>/dev/null
