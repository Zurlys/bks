#!/bin/sh
# For the release workflow: a temporary keychain holding the Developer ID
# Application identity, so codesign can sign without any prompt.
#
#   DEVELOPER_ID_P12=<base64 of the .p12> DEVELOPER_ID_P12_PASSWORD=… \
#     scripts/signing-keychain.sh create KEYCHAIN    → prints the identity's SHA-1
#   scripts/signing-keychain.sh delete KEYCHAIN
set -eu

usage() { echo "usage: $0 create|delete KEYCHAIN" >&2; exit 2; }
[ $# -eq 2 ] || usage
kc="$2"

case "$1" in
  delete) security delete-keychain "$kc" 2>/dev/null || true; exit 0 ;;
  create) ;;
  *) usage ;;
esac

: "${DEVELOPER_ID_P12:?base64 of the Developer ID Application .p12}"
: "${DEVELOPER_ID_P12_PASSWORD:?the .p12 password}"

# Apple's public Developer ID intermediate (G2), so codesign can build the
# chain even when the runner's system keychain lacks it.
ca="$(dirname "$0")/../packaging/apple/DeveloperIDG2CA.cer"
[ "$(shasum -a 256 "$ca" | cut -d ' ' -f 1)" = f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a ] || {
  echo "packaging/apple/DeveloperIDG2CA.cer is not Apple's Developer ID G2 certificate" >&2
  exit 1
}

p12=$(mktemp)
trap 'rm -f "$p12"' EXIT
printf '%s' "$DEVELOPER_ID_P12" | base64 --decode > "$p12"

pw=$(openssl rand -hex 24)
security create-keychain -p "$pw" "$kc"
security set-keychain-settings -lut 3600 "$kc"
security unlock-keychain -p "$pw" "$kc"
security import "$ca" -k "$kc" >/dev/null
security import "$p12" -k "$kc" -f pkcs12 -P "$DEVELOPER_ID_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$pw" "$kc" >/dev/null
# codesign looks for the identity and its chain in the search list.
# shellcheck disable=SC2046
security list-keychains -d user -s "$kc" $(security list-keychains -d user | tr -d '"')

ids=$(security find-identity -v -p codesigning "$kc" | awk '/"Developer ID Application: / { print $2 }')
if [ "$(printf '%s\n' "$ids" | grep -c .)" -ne 1 ]; then
  echo "expected exactly one valid Developer ID Application identity; the keychain has:" >&2
  security find-identity -p codesigning "$kc" >&2
  exit 1
fi
printf '%s\n' "$ids"
