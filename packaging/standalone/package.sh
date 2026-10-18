#!/bin/sh
# Packs the single binary Burrito built for TARGET (x86_64 or aarch64)
# into OUT: the binary, its .deb and .rpm packages, and their SHA-256
# sums. Run inside packaging/Containerfile.release, after
# `BURRITO_TARGET=linux_TARGET mix release`.
#
#   packaging/standalone/package.sh x86_64 /out
set -eu

TARGET=$1
OUT=$2
VERSION=$(grep -m1 'version:' mix.exs | sed 's/.*"\(.*\)".*/\1/')

case "$TARGET" in
  x86_64) DEB_ARCH=amd64 ;;
  aarch64) DEB_ARCH=arm64 ;;
  *) echo "unknown target: $TARGET" >&2; exit 64 ;;
esac

mkdir -p "$OUT"
BINARY="$OUT/sovite-$VERSION-linux-$TARGET"
cp "burrito_out/sovite_linux_$TARGET" "$BINARY"
chmod 0755 "$BINARY"

# The musl C library Burrito embedded in the binary, which it puts in /tmp
# at a path named by its SHA-256. Burrito keeps the copy it downloaded in
# its cache.
MUSL_HASH=$(sed -n "s/.*@linux_musl_runtime_$TARGET \"\([0-9a-f]*\)\".*/\1/p" \
  deps/burrito/lib/steps/fetch/fetch_musl.ex)
[ -n "$MUSL_HASH" ] || { echo "cannot find Burrito's musl runtime name" >&2; exit 1; }
MUSL_SHA256=$MUSL_HASH
MUSL_RUNTIME=
for file in "${XDG_CACHE_HOME:-$HOME/.cache}"/burrito_file_cache/*; do
  if [ -f "$file" ] && [ "$(sha256sum "$file" | cut -d ' ' -f 1)" = "$MUSL_HASH" ]; then
    MUSL_RUNTIME=$file
  fi
done
[ -n "$MUSL_RUNTIME" ] || { echo "Burrito's musl runtime is not in its cache" >&2; exit 1; }

STAGE=$(mktemp -d)
for file in env.sh sovite-runtime.conf; do
  sed -e "s/@MUSL_NAME@/libc-musl-$MUSL_HASH.so/g" -e "s/@MUSL_SHA256@/$MUSL_SHA256/g" \
    "packaging/standalone/$file" > "$STAGE/$file"
done

# nfpm expands variables in version and arch, not in file paths.
sed -e "s|\${BINARY}|$BINARY|" -e "s|\${MUSL_RUNTIME}|$MUSL_RUNTIME|" -e "s|\${STAGE}|$STAGE|" \
  packaging/nfpm-standalone.yaml > "$STAGE/nfpm.yaml"

export VERSION
ARCH=$DEB_ARCH nfpm package --config "$STAGE/nfpm.yaml" --packager deb --target "$OUT/"
ARCH=$TARGET nfpm package --config "$STAGE/nfpm.yaml" --packager rpm --target "$OUT/"

cd "$OUT"
sha256sum "sovite-$VERSION-linux-$TARGET" \
  "sovite_${VERSION}_$DEB_ARCH.deb" \
  "sovite-$VERSION-1.$TARGET.rpm" > "sovite-$VERSION-linux-$TARGET.sha256"
ls -l
