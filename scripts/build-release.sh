#!/bin/sh
# Build the macOS release archives, each with bks and bks-mac (hardened
# runtime), LICENSE, README, GUIDE and SECURITY, plus SHA256SUMS for both:
#   bks_X.Y.Z_darwin_arm64.tar.gz      Apple silicon
#   bks_X.Y.Z_darwin_universal.tar.gz  Apple silicon and Intel
#   scripts/build-release.sh v0.1.0-alpha.1      → dist/
# Signed ad-hoc, or with BKS_SIGN_IDENTITY (the release workflow passes its
# Developer ID Application identity, then notarizes).
set -eu

version="${1:-}"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "usage: $0 vMAJOR.MINOR.PATCH[-pre]" >&2; exit 2 ;;
esac

base="bks_${version#v}_darwin"
out=dist
b="$out/build"
rm -rf "$out"
mkdir -p "$b"
export CGO_ENABLED=0 GOOS=darwin

for arch in arm64 amd64; do
  GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$b/bks-$arch" ./cmd/bks
done
for arch in arm64 x86_64; do
  swiftc -swift-version 5 -O -target "$arch-apple-macos13" -o "$b/bks-mac-$arch" macos/bks-mac.swift
done

identity="${BKS_SIGN_IDENTITY:--}"
if [ "$identity" = - ]; then ts=--timestamp=none; else ts=--timestamp; fi
# sign FILE IDENTIFIER. The hardened runtime makes macOS ignore DYLD_* code
# injection and refuse debuggers, also for ad-hoc signatures.
sign() {
  codesign --force --options runtime "$ts" --identifier "$2" --sign "$identity" "$1"
}

# pack NAME: sign the bks and bks-mac already in dist/NAME, add the docs, archive.
pack() {
  sign "$out/$1/bks" io.github.zurlys.bks
  sign "$out/$1/bks-mac" io.github.zurlys.bks-mac
  cp LICENSE README.md GUIDE.md SECURITY.md "$out/$1/"
  COPYFILE_DISABLE=1 tar -C "$out" -czf "$out/$1.tar.gz" "$1"
  echo "built $out/$1.tar.gz"
}

mkdir "$out/${base}_arm64"
cp "$b/bks-arm64" "$out/${base}_arm64/bks"
cp "$b/bks-mac-arm64" "$out/${base}_arm64/bks-mac"
pack "${base}_arm64"

mkdir "$out/${base}_universal"
lipo -create -output "$out/${base}_universal/bks" "$b/bks-arm64" "$b/bks-amd64"
lipo -create -output "$out/${base}_universal/bks-mac" "$b/bks-mac-arm64" "$b/bks-mac-x86_64"
pack "${base}_universal"

(cd "$out" && shasum -a 256 "${base}_arm64.tar.gz" "${base}_universal.tar.gz" > SHA256SUMS)
rm -rf "$b"
cat "$out/SHA256SUMS"
