#!/bin/sh
# Builds the release tarball and, with nfpm installed, the .deb and .rpm
# packages, into dist/. Run on the distribution release the packages are
# for: the release bundles the Erlang runtime built on this host.
#
#   scripts/package.sh
set -eu
cd "$(dirname "$0")/.."

VERSION=$(grep -m1 'version:' mix.exs | sed 's/.*"\(.*\)".*/\1/')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) DEB_ARCH=amd64 ;;
  aarch64) DEB_ARCH=arm64 ;;
  *) DEB_ARCH=$ARCH ;;
esac

export MIX_ENV=prod
mix deps.get --only prod
mix release --overwrite

mkdir -p dist
cp "_build/prod/sovite-$VERSION.tar.gz" "dist/sovite-$VERSION-linux-$ARCH.tar.gz"

if command -v nfpm >/dev/null 2>&1; then
  export VERSION RELEASE_DIR="_build/prod/rel/sovite"
  ARCH=$DEB_ARCH nfpm package --config packaging/nfpm.yaml --packager deb --target dist/
  ARCH=$ARCH nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
else
  echo "nfpm not found: built the tarball only" >&2
fi

ls -l dist
