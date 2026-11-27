#!/bin/sh
# Build the macOS release archive: universal (arm64 + x86_64) bks and bks-mac,
# ad-hoc signed, with LICENSE and README, plus SHA256SUMS.
#   scripts/build-release.sh v0.1.0-alpha.1      → dist/
set -eu

version="${1:-}"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "usage: $0 vMAJOR.MINOR.PATCH[-pre]" >&2; exit 2 ;;
esac

name="bks_${version#v}_darwin_universal"
out=dist
rm -rf "$out"
mkdir -p "$out/build" "$out/$name"
export CGO_ENABLED=0 GOOS=darwin

for arch in arm64 amd64; do
  GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out/build/bks-$arch" ./cmd/bks
done
lipo -create -output "$out/$name/bks" "$out/build/bks-arm64" "$out/build/bks-amd64"

for target in arm64-apple-macos13 x86_64-apple-macos13; do
  swiftc -swift-version 5 -O -target "$target" -o "$out/build/bks-mac-$target" macos/bks-mac.swift
done
lipo -create -output "$out/$name/bks-mac" "$out/build/bks-mac-arm64-apple-macos13" "$out/build/bks-mac-x86_64-apple-macos13"

# Ad-hoc signatures (no Developer ID yet): required to run on Apple silicon.
codesign --force --sign - "$out/$name/bks" "$out/$name/bks-mac"

cp LICENSE README.md GUIDE.md SECURITY.md "$out/$name/"
COPYFILE_DISABLE=1 tar -C "$out" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && shasum -a 256 "$name.tar.gz" > SHA256SUMS)
rm -rf "$out/build"

echo "built $out/$name.tar.gz"
cat "$out/SHA256SUMS"
