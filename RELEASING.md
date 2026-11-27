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

5. Approve it: once the tests pass, the `release` job waits for you. Open the run (Actions tab, or the link in GitHub's e-mail), choose **Review deployments**, tick `release`, **Approve and deploy**. When it finishes, the release is on the [releases page](https://github.com/Zurlys/bks/releases).

## What the release workflow does

The **test** job has no access to any signing secret:

1. Checks the tag looks like `vX.Y.Z[-pre]` and that CHANGELOG.md has a section for it.
2. Runs the full test suite.

The **release** job runs after the tests pass and you approve the `release` environment:

1. Imports the Developer ID certificate into a temporary keychain, builds `bks` and `bks-mac` for arm64 and x86_64, stamps the version (`bks version` prints the tag), signs them with the Developer ID, the hardened runtime and a secure timestamp, deletes the keychain, and packs two archives with LICENSE, README, GUIDE and SECURITY: `bks_X.Y.Z_darwin_arm64.tar.gz` (Apple silicon) and `bks_X.Y.Z_darwin_universal.tar.gz` (Apple silicon and Intel, joined with `lipo`), plus `SHA256SUMS` for both.
2. Notarizes all four binaries in one submission, and fails unless Apple answers `Accepted` (the notarization log is printed otherwise).
3. Checks the architectures, the version, the hardened runtime, the team's Developer ID signature with its timestamp, and that Apple knows the binaries as notarized.
4. Creates a signed build-provenance attestation for the archives: anyone can run `gh attestation verify <archive> --repo Zurlys/bks` to prove it was built by this workflow from this tag.
5. Publishes the GitHub release with the archives, the checksums and the notes: the changelog section, a link to all changes since the previous release, and install steps. From 1.0.0 on, a `-` in the tag makes it a pre-release.

Locally, `scripts/build-release.sh vX.Y.Z` builds the same archives signed ad-hoc (output in `dist/`, which git ignores), `scripts/check-release.sh vX.Y.Z` checks them, and `scripts/release-notes.sh X.Y.Z` prints the notes.

## If something goes wrong

- **The workflow failed before publishing:** fix it on `main`, then move the tag: `git tag -d vX && git push origin :refs/tags/vX`, re-tag, push again.
- **A bad release was published:** don't reuse its version. Delete or edit the release text if needed, fix, and release the next version.

## Signing and notarization

Releases are signed with a Developer ID Application certificate (hardened runtime, secure timestamp) and notarized by Apple, so macOS runs a downloaded copy without complaint. Nothing is stapled (a ticket cannot be attached to a bare executable): the first time a downloaded copy runs, macOS asks Apple online. Local builds (`make`, `scripts/build-release.sh`) are signed ad-hoc with the same hardened runtime. The Touch ID enrolment does not depend on the signature.

Everything signing needs lives in the `release` environment (Settings → Environments), which only serves `v*` tags and needs your approval for every run; each secret reaches only the step that uses it.

| Name | Kind | What |
|---|---|---|
| `DEVELOPER_ID_P12` | secret | the Developer ID Application certificate and its private key, as a base64 `.p12` |
| `DEVELOPER_ID_P12_PASSWORD` | secret | the `.p12` password |
| `NOTARY_KEY_P8` | secret | an App Store Connect API key (`.p8`) used for nothing but notarizing bks |
| `NOTARY_KEY_ID` | secret | its key ID |
| `NOTARY_ISSUER_ID` | secret | its issuer ID (team keys; leave it unset for an individual key) |
| `APPLE_TEAM_ID` | variable | the team ID the signature must carry |

Setting it up (once, and again when the certificate expires):

1. **Certificate.** Xcode → Settings → Accounts → your team → Manage Certificates → **+** → **Developer ID Application** (only the Account Holder can). In Keychain Access, under My Certificates, export "Developer ID Application: …" (certificate with its private key) as a `.p12` with a strong password.
2. **API key.** App Store Connect → Users and Access → Integrations → Team Keys → **+**, access **Developer**. Download the `.p8` (possible only once) and note the key ID and the issuer ID.
3. **Check the key** before the first release; a wrong role or issuer shows up here as 401/403:

   ```sh
   xcrun notarytool history --key AuthKey_XXXXXXXXXX.p8 --key-id XXXXXXXXXX --issuer <issuer-id>
   ```

4. **Store them** from a terminal (the prompts keep values out of the shell history):

   ```sh
   base64 -i DeveloperID.p12 | gh secret set DEVELOPER_ID_P12 --env release --repo Zurlys/bks
   gh secret set DEVELOPER_ID_P12_PASSWORD --env release --repo Zurlys/bks   # prompts
   gh secret set NOTARY_KEY_P8 --env release --repo Zurlys/bks < AuthKey_XXXXXXXXXX.p8
   gh secret set NOTARY_KEY_ID --env release --repo Zurlys/bks                # prompts
   gh secret set NOTARY_ISSUER_ID --env release --repo Zurlys/bks             # prompts
   gh variable set APPLE_TEAM_ID --env release --repo Zurlys/bks --body XXXXXXXXXX
   ```

5. Delete the `.p12` and `.p8` files (new ones can always be made) or keep them offline.

If any of them leaks: revoke the certificate (developer.apple.com → Certificates) and the API key (App Store Connect → Integrations), make new ones, update the secrets, and publish a new release.

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
