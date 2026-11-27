#!/bin/sh
# Print the release notes for a version: its CHANGELOG.md section, the link to
# all changes since the previous release, and install and verification steps.
#   scripts/release-notes.sh 0.1.0-alpha.1
set -eu

v="${1:?usage: $0 VERSION (without the v)}"
section=$(awk -v v="$v" '
  $0 ~ "^## \\[" { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
  found { print }
' CHANGELOG.md)
if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no section for $v" >&2
  exit 1
fi
# The version's link at the bottom of CHANGELOG.md: a compare link from the
# previous release (none for the first release).
compare=$(awk -v v="$v" 'index($0, "[" v "]: ") == 1 { print substr($0, length(v) + 5) }' CHANGELOG.md)

printf '%s\n' "$section"
case "$compare" in
  */compare/*) printf '\n**Full changelog:** %s\n' "$compare" ;;
esac
cat <<NOTES

## Install

Two downloads of the same program:

- \`bks_${v}_darwin_arm64.tar.gz\`: Apple silicon (M1 and later)
- \`bks_${v}_darwin_universal.tar.gz\`: Apple silicon and Intel

\`\`\`sh
arch=arm64   # on an Intel Mac: arch=universal
name=bks_${v}_darwin_\$arch
curl -LO https://github.com/Zurlys/bks/releases/download/v$v/\$name.tar.gz
curl -LO https://github.com/Zurlys/bks/releases/download/v$v/SHA256SUMS
shasum -a 256 -c --ignore-missing SHA256SUMS
gh attestation verify \$name.tar.gz --repo Zurlys/bks   # proves it was built here, from this tag
tar -xzf \$name.tar.gz
ln -s "\$PWD/\$name/bks" ~/.local/bin/bks   # keep bks next to bks-mac
\`\`\`

The binaries are ad-hoc signed, not notarized. Files downloaded with a browser get a quarantine flag that makes macOS refuse to run them; \`curl\` does not set it. If you used a browser: \`xattr -dr com.apple.quarantine bks_${v}_darwin_*\`.

Requires macOS 13 or later and GnuPG (tested with GPG Suite). See the [guide](https://zurlys.github.io/bks/guide.html).
NOTES
