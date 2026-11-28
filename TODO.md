# TODO

macOS comes first: the Linux and BSD work starts once the macOS releases are settled.

## macOS

- [ ] Check how a vault evicted by iCloud ("Optimize Mac Storage", `brctl evict`) behaves when bks opens it, online and offline; wait for the download instead of falling back to the last good copy when online.
- [ ] Finish release signing ([RELEASING.md](RELEASING.md), "Signing and notarization"): an App Store Connect API key with the Developer role, the `release` environment's secrets and `APPLE_TEAM_ID`. Until then a version tag fails at signing. Then release v0.1.0-alpha.3.
- [ ] Before trusting `bks-mac`, check that it is signed by the same Developer ID team as `bks` (on top of "only the binary next to bks").

## Linux and BSD

The Go code already cross-compiles for Linux, FreeBSD, OpenBSD and NetBSD; what is missing is everything the macOS helper does.

- [ ] A per-OS layer for what `internal/macos` does today (clipboard, lock watcher, warnings), so `cmd/bks` and `store` don't call macOS code directly; messages that don't say "this Mac" everywhere.
- [ ] Linux clipboard: `wl-copy`/`wl-paste` (Wayland), `xclip`/`xsel` (X11), cleared with the existing "clear if unchanged" hash check; the password-manager hint so KDE's clipboard history skips it.
- [ ] Linux locking: lock and sleep signals from systemd-logind and the desktop screensaver over D-Bus; without them, the idle, sleep and 8-hour locks.
- [ ] Linux hardening: `prctl(PR_SET_DUMPABLE, 0)` in place of `PT_DENY_ATTACH`.
- [ ] Unlock on Linux and BSD with the GPG key only. No fingerprint unlock (fprintd releases no key); a GPG smartcard key works through gpg-agent unchanged.
- [ ] No display (SSH, headless): say plainly that copying is unavailable; maybe an opt-in terminal copy (OSC 52).
- [ ] CI on Linux amd64 and arm64 runners with the distribution's GnuPG.
- [ ] FreeBSD and OpenBSD as best effort: GPG unlock, idle/sleep/8-hour locks, `procctl`/`pledge` hardening; a VM test job (weekly or on release).
- [ ] SECURITY.md per OS: the X11 clipboard is readable by any app on the display, clipboard sync (e.g. KDE Connect), lock signals depend on the desktop.
- [ ] README, GUIDE and website: install and limits per OS.

## Multiarch

- [ ] Release archives for `linux_amd64`, `linux_arm64`, `freebsd_amd64`, `freebsd_arm64`, `openbsd_amd64`, `openbsd_arm64` next to the macOS ones, all in `SHA256SUMS` and the provenance attestation.
- [ ] Homebrew formula: install `bks-mac` only on macOS so it also works on Linux.

## Not planned

- Windows: no `flock`, no re-exec for locking, different clipboard and lock APIs; a separate, much larger project.
