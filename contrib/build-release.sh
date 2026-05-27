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
# Two spellings of the upstream version are needed:
#   UPSTREAM      dash form  (3.0.0-beta13) — public tarball, human-facing
#   DEB_UPSTREAM  tilde form (3.0.0~beta13) — Debian orig tarball; must match
#                 the upstream part of the changelog version or dpkg-source
#                 and sbuild will not find the orig.
UPSTREAM="${TAG#v}"
DEB_UPSTREAM="${UPSTREAM/-/\~}"

# 3.0 (quilt) requires an orig tarball to exist before sbuild can package the source
ORIG_TARBALL="$RELEASES_DIR/${SOURCE_PKG}_${DEB_UPSTREAM}.orig.tar.gz"
echo "==> Creating orig tarball: $(basename "$ORIG_TARBALL")"
git archive --prefix="${SOURCE_PKG}-${DEB_UPSTREAM}/" HEAD | gzip -9 > "$ORIG_TARBALL"

echo "==> Updating chroot"
#mmdebstrap --variant=buildd trixie "$HOME/releases/chroots/trixie.tar.xz"

echo "==> Building PhoenixDKIM $VERSION"

if command -v sbuild &>/dev/null; then
    echo "==> Using sbuild (clean chroot)"
    # --source includes the source package (.dsc, .orig.tar.*, .debian.tar.*)
    # in the resulting .changes so reprepro can serve it via 'apt-get source'.
    sbuild \
        --dist=trixie \
        --chroot-mode=unshare \
        --chroot="$RELEASES_DIR/chroots/trixie.tar.xz" \
        --no-clean-source \
        --source \
        --keyid="$KEYID"
else
    echo "==> sbuild not available, building directly"
    # -F (full build: source + binary) is the dpkg-buildpackage default, but
    # we state it explicitly — previously this was -b (binary only), which
    # produced a source-less .changes.
    dpkg-buildpackage -F -k"$KEYID"
fi

# Add packages to reprepro apt repo
REPO_DIR="$RELEASES_DIR/repo"
if [[ -d "$REPO_DIR/conf" ]]; then
    # A published version is immutable: reprepro will refuse to register a
    # rebuilt .deb of an already-present version (different checksums), and
    # the whole include — source included — aborts. Detect that up front and
    # skip cleanly rather than emitting a confusing checksum error.
    if reprepro -b "$REPO_DIR" ls "$SOURCE_PKG" 2>/dev/null \
        | awk -F' \\| ' -v v="$VERSION" -v d="trixie" '$2==v && $3==d {found=1} END{exit !found}'; then
        echo "==> $SOURCE_PKG $VERSION already in apt repo (trixie); skipping include."
        echo "    A released version is immutable — bump the revision or cut a new"
        echo "    tag to publish changed packages."
    else
        echo "==> Updating apt repo"
        reprepro -b "$REPO_DIR" include trixie "$RELEASES_DIR/${SOURCE_PKG}_${VERSION}_amd64.changes"
    fi
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
        "$RELEASES_DIR"/*.dsc "$RELEASES_DIR"/*.debian.tar.* \
        "$RELEASES_DIR"/*.orig.tar.* \
        "$TARBALL" "${TARBALL}.asc" 2>/dev/null
