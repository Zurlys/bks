#!/bin/sh
# Notarize the signed release binaries in dist/ with Apple: one submission for
# all of them, and a failure unless Apple accepts it.
#
#   NOTARY_KEY=AuthKey_XXXXXXXXXX.p8 NOTARY_KEY_ID=XXXXXXXXXX NOTARY_ISSUER_ID=<uuid> \
#     scripts/notarize.sh
#
# NOTARY_ISSUER_ID is for team API keys; leave it unset for an individual key.
set -eu

: "${NOTARY_KEY:?path to the App Store Connect API key (.p8)}"
: "${NOTARY_KEY_ID:?the API key ID}"
set -- --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID"
[ -z "${NOTARY_ISSUER_ID:-}" ] || set -- "$@" --issuer "$NOTARY_ISSUER_ID"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bks"
for d in dist/bks_*_darwin_*/; do
  [ -f "$d/bks" ] || continue
  mkdir "$work/bks/$(basename "$d")"
  cp "$d/bks" "$d/bks-mac" "$work/bks/$(basename "$d")/"
done
[ -n "$(ls "$work/bks")" ] || { echo "no release binaries in dist/ (run scripts/build-release.sh)" >&2; exit 1; }
ditto -c -k --keepParent "$work/bks" "$work/bks.zip"

# notarytool's exit code is not a verdict: read the status.
xcrun notarytool submit "$work/bks.zip" "$@" --wait --timeout 30m --output-format json > "$work/result.json" || true
cat "$work/result.json"
echo
status=$(plutil -extract status raw -o - "$work/result.json" 2>/dev/null || echo "no answer")
id=$(plutil -extract id raw -o - "$work/result.json" 2>/dev/null || true)
if [ "$status" != Accepted ]; then
  echo "notarization: $status" >&2
  [ -z "$id" ] || xcrun notarytool log "$id" "$@" >&2 || true
  exit 1
fi
echo "notarized (submission $id)"
