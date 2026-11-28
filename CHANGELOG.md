# Changelog

All notable changes to bks. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/): before 1.0.0 anything may change, but every release can still read vaults written by earlier ones.

## [Unreleased]

### Added

- Several vaults (personal, work, …), each with its own GPG keys, Touch ID enrolment, pin and lock. `bks` asks which to open (the last used is preselected); `-v <name>` picks one; commands without `-v` use the default vault. The vault's name is shown in the header and on the lock screen. `ctrl-v` switches to another vault: the open one is wiped (the process restarts, as for a lock) and the picker preselects the other.
- `bks init` asks for the vault's name and place: iCloud Drive (recommended, when on), this Mac only (with a note on whether Time Machine backs it up), or a folder you choose. A vault already synced from another Mac is added instead of replaced.
- `bks vault list | move | add | rename | default | remove`. `move` copies, checks the copy byte for byte, switches, and renames the old file aside.
- On start, bks offers to move a vault that is not in iCloud Drive there, with "don't remind me again".
- The UI shows bks's version at the bottom right; `make` stamps local builds with `git describe` (e.g. `v0.1.0-alpha.2-10-g1234abc`).
- The list of vaults lives in `~/.config/bks/vaults.json`; an existing vault becomes `personal` and keeps its place and state.

### Changed

- Search also matches the short, one-line values of non-secret fields: the username or email of imported 1Password server, database and email items is now found. Secret fields, passwords and notes are still never searched.
- `BKS_VAULT` takes a vault name or a path; `BKS_STATE_DIR` applies only together with a path.

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

[Unreleased]: https://github.com/Zurlys/bks/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/Zurlys/bks/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/Zurlys/bks/releases/tag/v0.1.0-alpha.1
