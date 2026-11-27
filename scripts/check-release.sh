#!/bin/sh
# Check the release built in dist/: architectures, version and the hardened
# runtime; given a team ID, also the Developer ID signature, its secure
# timestamp and Apple's notarization (asked online).
#
#   scripts/check-release.sh v0.1.0              local, ad-hoc build
#   scripts/check-release.sh v0.1.0 TEAMID       release workflow
set -eu

version="${1:?usage: $0 vX.Y.Z [TEAMID]}"
team="${2-}"
case "$team" in
  "") ;;
  *[!ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]*) echo "bad team ID: $team" >&2; exit 2 ;;
  ??????????) ;;
  *) echo "bad team ID: $team" >&2; exit 2 ;;
esac
p="dist/bks_${version#v}_darwin"
# A Developer ID Application certificate of this team, issued by Apple.
devid="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$team\""

fail() { echo "check failed: $*" >&2; exit 1; }

for b in bks bks-mac; do
  [ "$(lipo -archs "${p}_arm64/$b")" = arm64 ] || fail "${p}_arm64/$b is not arm64 only"
  archs=" $(lipo -archs "${p}_universal/$b") "
  for a in arm64 x86_64; do
    case "$archs" in *" $a "*) ;; *) fail "${p}_universal/$b has no $a" ;; esac
  done
done

for d in "${p}_arm64" "${p}_universal"; do
  [ "$("$d/bks" version)" = "bks $version" ] || fail "$d/bks does not report $version"
  "$d/bks-mac" version >/dev/null || fail "$d/bks-mac does not run"
  for f in "$d/bks" "$d/bks-mac"; do
    codesign --verify --strict "$f" || fail "$f: bad signature"
    codesign -dv "$f" 2>&1 | grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' || fail "$f: no hardened runtime"
    [ -n "$team" ] || continue
    codesign --verify --strict -R="$devid" "$f" || fail "$f: not signed with team $team's Developer ID"
    codesign -dv "$f" 2>&1 | grep -q '^Timestamp=' || fail "$f: no secure timestamp"
    # Apple's ticket can take a little while to show up after notarization.
    n=0
    until codesign --verify --strict --check-notarization -R=notarized "$f" 2>/dev/null; do
      n=$((n + 1))
      [ "$n" -lt 6 ] || fail "$f: Apple does not know it as notarized"
      sleep 20
    done
  done
done
echo "release checks passed${team:+: Developer ID of $team, notarized}"
