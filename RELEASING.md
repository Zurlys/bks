# Releasing bks

Releases are made by pushing a version tag. The [release workflow](.github/workflows/release.yml) then tests, builds and publishes; nothing else can publish.

## Versions

[Semantic Versioning](https://semver.org/), with a `v` in the tag:

| Stage | Tag | GitHub marks it |
|---|---|---|
| early testing | `v0.1.0-alpha.1`, `v0.1.0-alpha.2`, … | latest release |
| feature-complete testing | `v0.1.0-beta.1`, … then `v0.1.0-rc.1` | latest release |
| 0.x release | `v0.1.0`, `v0.2.0`, `v0.2.1` | latest release |
| stable | `v1.0.0`, then `v1.1.0` (features), `v1.0.1` (fixes), `v2.0.0` (breaking) | latest release |
| testing after 1.0.0 | `v1.1.0-beta.1`, `v1.1.0-rc.1` | pre-release |

Alpha, beta and rc tags need the hyphen (`v0.1.0-alpha.1`, not `v0.1.0a`): Go and Homebrew only understand SemVer.

GitHub never shows a pre-release as the repository's Latest release (the Releases box on the repository page). So before 1.0.0 every release is published as a normal one and the newest is Latest; its version number already says it is an alpha. From 1.0.0 on, a tag with a hyphen is published as a pre-release, so that `v1.1.0-rc.1` cannot replace `v1.0.0` as Latest.

Promise at every version: a release can read every vault written by an earlier one.

## Cutting a release

1. Make sure `main` is green in CI.
2. In [CHANGELOG.md](CHANGELOG.md), move the `Unreleased` entries into a new section `## [X.Y.Z] - YYYY-MM-DD` and add its compare/tag links at the bottom. The release refuses to run without that section: it becomes the release notes.
3. Commit, push, and wait for CI.
4. Tag and push the tag:

   ```sh
   git tag -s v0.1.0-alpha.1 -m "bks v0.1.0-alpha.1"   # -s signs the tag with your GPG key; -a for an unsigned tag
   git push origin v0.1.0-alpha.1
   ```

   `git tag -s` signs with `user.signingkey`, or with gpg's default key when that is unset — set the key you want once per clone: `git config user.signingkey <fingerprint>`.

5. Watch it: `gh run watch` (or the Actions tab). When it finishes, the release is on the [releases page](https://github.com/Zurlys/bks/releases).

## What the release workflow does

1. Checks the tag looks like `vX.Y.Z[-pre]` and that CHANGELOG.md has a section for it.
2. Runs the full test suite.
3. Builds `bks` and `bks-mac` for arm64 and x86_64, stamps the version (`bks version` prints the tag), ad-hoc signs them and packs two archives with LICENSE, README, GUIDE and SECURITY: `bks_X.Y.Z_darwin_arm64.tar.gz` (Apple silicon) and `bks_X.Y.Z_darwin_universal.tar.gz` (Apple silicon and Intel, joined with `lipo`), plus `SHA256SUMS` for both.
4. Checks each archive's binaries contain the right architectures and report the right version.
5. Creates a signed build-provenance attestation for each archive: anyone can run `gh attestation verify <archive> --repo Zurlys/bks` to prove it was built by this workflow from this tag.
6. Publishes the GitHub release with the archives, the checksums and the notes: the changelog section, a link to all changes since the previous release, and install steps. From 1.0.0 on, a `-` in the tag makes it a pre-release.

`scripts/build-release.sh vX.Y.Z` and `scripts/release-notes.sh X.Y.Z` run the same steps locally (output in `dist/`, which git ignores).

## If something goes wrong

- **The workflow failed before publishing:** fix it on `main`, then move the tag: `git tag -d vX && git push origin :refs/tags/vX`, re-tag, push again.
- **A bad release was published:** don't reuse its version. Delete or edit the release text if needed, fix, and release the next version.

## Signing and notarization (later)

Binaries are ad-hoc signed and not notarized, so a browser-downloaded archive is quarantined by macOS; the release notes explain `curl` and `xattr`. With an Apple Developer ID, the workflow can sign with `codesign --options runtime --sign "Developer ID Application: …"` and notarize with `xcrun notarytool submit … --wait`, using the certificate and an App Store Connect API key stored as repository secrets. The Touch ID enrolment does not depend on the signature, so switching to Developer ID signing needs no re-enrolment.

## Homebrew (later)

The formula is ready as a template in [packaging/homebrew/bks.rb](packaging/homebrew/bks.rb). It builds from the tag's source archive, installs `bks` and `bks-mac` together in `libexec` (bks only trusts the helper next to it) and links `bks` into the PATH. GnuPG is deliberately not a dependency: a second `gpg` would shadow GPG Suite.

To publish it:

1. Create the tap repository `Zurlys/homebrew-tap` with a `Formula/` folder.
2. For a release tag, get the source archive's checksum:

   ```sh
   curl -sL https://github.com/Zurlys/bks/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
   ```

3. Copy `packaging/homebrew/bks.rb` to `Formula/bks.rb` in the tap, set `url` and `sha256`, and check it:

   ```sh
   brew install --build-from-source ./Formula/bks.rb
   brew test bks && brew audit --strict bks
   ```

4. Push the tap. Users then install with `brew install zurlys/tap/bks`.

For each later release, update `url` and `sha256` in the tap (by hand, or later from the release workflow with a token that can push to the tap).
