# Changelog

All notable changes to bks. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/): before 1.0.0 anything may change, but every release can still read vaults written by earlier ones.

## [Unreleased]

## [0.1.0-alpha.3] - 2026-11-27

### Changed

- Releases are signed with a Developer ID and notarized by Apple: a copy downloaded with a browser runs without the `xattr` step.
- `bks` and `bks-mac` run with the hardened runtime, in releases and `make` builds: macOS ignores `DYLD_*` code injection into them and refuses debuggers.
- Before 1.0.0, alpha and beta releases are published as normal releases, so the newest one shows as Latest on the repository page.

## [0.1.0-alpha.2] - 2026-11-27

### Added

- An Apple silicon download, `bks_…_darwin_arm64.tar.gz`, next to the universal one (Apple silicon and Intel).
- Release notes end with a link to every change since the previous release.
- [TODO.md](https://github.com/Zurlys/bks/blob/main/TODO.md): what comes after macOS (Linux, BSD, more architectures).

## [0.1.0-alpha.1] - 2026-11-27

First public pre-release. Feedback and bug reports are very welcome; security issues go to [private reporting](https://github.com/Zurlys/bks/blob/main/SECURITY.md).

### Added

- A single GPG-encrypted vault file that opens with your GPG key (pinentry) or with Touch ID (a secret sealed by the Mac's Secure Enclave), and stays readable with plain `gpg -d`.
- Terminal UI: fuzzy search (any order, accents ignored, `#tags`), copy password / username / one-time code, reveal for 10 seconds, live TOTP codes, editing with password history, delete with confirmation.
- Locking on screen lock, screensaver, sleep, user switch, idle (5 min) and after 8 hours; locking restarts the process.
- A clipboard that stays on this Mac (no Universal Clipboard), is hidden from clipboard-history apps and is cleared after 30 seconds.
- Several Macs: edits are merged, older copies arriving through sync cannot roll anything back, conflict copies from iCloud, Syncthing and Dropbox are merged.
- `bks init` with a key picker or a wizard for a new GPG key and a checklist of what to back up.
- Command line: `get`, `otp`, `ls`, `add`, `gen` (characters or EFF diceware), `recipients add/remove`, `rotate`, `touchid`, `version`.
- 1Password import from `.1pux` exports, with a dry run that shows no secrets.

[Unreleased]: https://github.com/Zurlys/bks/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/Zurlys/bks/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/Zurlys/bks/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Zurlys/bks/releases/tag/v0.1.0-alpha.1
