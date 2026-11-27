#!/bin/sh
# Print the release notes for a version: its CHANGELOG.md section plus
# install and verification steps.   scripts/release-notes.sh 0.1.0-alpha.1
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

name="bks_${v}_darwin_universal"
printf '%s\n' "$section"
cat <<NOTES

## Install

\`\`\`sh
curl -LO https://github.com/Zurlys/bks/releases/download/v$v/$name.tar.gz
curl -LO https://github.com/Zurlys/bks/releases/download/v$v/SHA256SUMS
shasum -a 256 -c SHA256SUMS
gh attestation verify $name.tar.gz --repo Zurlys/bks   # proves it was built here, from this tag
tar -xzf $name.tar.gz
ln -s "\$PWD/$name/bks" ~/.local/bin/bks   # keep bks next to bks-mac
\`\`\`

The binaries are ad-hoc signed, not notarized. Files downloaded with a browser get a quarantine flag that makes macOS refuse to run them; \`curl\` does not set it. If you used a browser: \`xattr -dr com.apple.quarantine $name\`.

Requires macOS 13 or later and GnuPG (tested with GPG Suite). See the [guide](https://zurlys.github.io/bks/guide.html).
NOTES
