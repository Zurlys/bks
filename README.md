# bks — Best Kept Secret

A terminal password manager for macOS. Your passwords live in **one GPG-encrypted file**; you unlock it with **Touch ID** or your GPG passphrase, find entries with **fuzzy search**, copy with **Enter**, and it **locks when your screen locks**.

```
┌ bks ─────────────────────────────────────────────── 🔓 unlocked · idle lock 4:12 ┐
│ > jane corp█                                                              3/1834 │
├───────────────────────────────────┬──────────────────────────────────────────────┤
│▌GitLab (work)                     │ GitLab (work)                      #work #git│
│▌jane.doe@corp.example             │                                              │
│ Grafana prod                      │  username  jane.doe@corp.example             │
│ admin                             │  password  ••••••••••••                      │
│                                   │  one-time  482 913  ▰▰▰▰▰▰▱▱▱▱ 19s           │
├───────────────────────────────────┴──────────────────────────────────────────────┤
│ ✓ password copied (this Mac only) · clipboard clears in 27s                      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

## Why

- **No server, no account, no subscription.** The vault is a file, in iCloud Drive by default; keep it anywhere else if you like. Several vaults (personal, work) are fine.
- **Readable without bks, forever.** `gpg -d vault.gpg` gives you plain JSON. If this project disappears, your passwords don't.
- **Built for people who live in a terminal**, and small enough to read: a Go CLI/TUI plus a ~250-line Swift helper for the macOS bits.

## Features

- **Two ways in, one file.** The vault is an OpenPGP message that opens with your GPG key *or* with a random 256-bit secret that the Mac's **Secure Enclave** releases only after **Touch ID**.
- **Locks itself** on screen lock, screensaver, sleep, user switch, idle (5 min) and after 8 h — by restarting the process, so nothing decrypted stays in memory.
- **Fuzzy search** over titles, usernames, URL hosts, tags and field names: `jane doe corp` finds `jane.doe@corp.example`; accents don't matter; `#work` searches tags. Secrets are never searched.
- **One-time codes (TOTP)** shown live with a countdown; copy the current code with `ctrl-o`.
- **A careful clipboard.** Copies stay on this Mac (no Universal Clipboard), are marked so clipboard-history tools skip them, and are cleared after 30 s — only if nothing else was copied since.
- **Editing in the UI** with password history, a generator (random characters or EFF diceware words), and delete with confirmation.
- **Several Macs.** Edits from different Macs are merged; an older file arriving through sync cannot roll anything back; conflict copies from iCloud, Syncthing and Dropbox are merged and removed.
- **1Password import** from a `.1pux` export, with a dry run that never shows secrets.

## Requirements

- macOS with Touch ID (Apple Silicon or a Touch ID keyboard) — without it, bks works with the GPG passphrase only.
- [GnuPG](https://gnupg.org): tested with [GPG Suite](https://gpgtools.org) (GnuPG 2.2.41). Homebrew's `gnupg` (2.4) is exercised by CI; use the same GnuPG on every Mac that shares a vault.
- To build: Go 1.27+ and the Xcode command-line tools (`xcode-select --install`, for `swiftc`).

## Install

### A release

Download an archive from [Releases](https://github.com/Zurlys/bks/releases): `darwin_arm64` for Apple silicon, `darwin_universal` for Apple silicon and Intel; each release's notes give the exact commands to download, verify (checksum and GitHub build provenance) and install it.

### From source

```sh
git clone https://github.com/Zurlys/bks.git
cd bks
make                                   # builds bin/bks and the helper bin/bks-mac
ln -s "$PWD/bin/bks" ~/.local/bin/bks  # any directory on your PATH
```

Keep `bks` and `bks-mac` together: bks only trusts the helper built next to it.

## Quick start

```sh
bks init            # pick one of your GPG keys (or create one), see what to back up, enable Touch ID
bks                 # open the UI: type to search, enter copies the password
```

From scripts or the shell:

```sh
bks add --title "GitHub" --user me --url https://github.com --tag dev --generate 24
bks add --title "Bank" --user me --otp          # asks for the OTP secret, hidden
bks get github                                   # prints the password
bks get -f user github
bks otp github                                   # current one-time code
bks ls '#dev'
bks gen --words 6                                # e.g. chest-siesta-announcer-sneeze-speech-barn
bks import 1password ~/export.1pux --dry-run     # then without --dry-run
```

Secrets are never taken as command-line arguments (they would end up in shell history and `ps`): passwords are generated, prompted without echo, or read from stdin (`--password-stdin`, `--otp-stdin`).

The [guide](GUIDE.md) ([on the website](https://zurlys.github.io/bks/guide.html)) covers everything day to day: finding and copying entries, adding and editing them, tags, one-time codes and every keyboard shortcut.

## Keys

| Where | Keys |
|---|---|
| List | type to search · `↑↓` move · `enter` copy password · `ctrl-o` copy one-time code · `ctrl-u` copy username · `tab` fields · `ctrl-n` new · `ctrl-e` edit · `ctrl-d` delete · `ctrl-v` other vault · `ctrl-l` lock · `esc` clear / quit |
| Fields | `↑↓` choose · `enter` copy · `r` reveal for 10 s · `e` edit · `tab`/`esc` back |
| Edit form | `ctrl-s` save · `tab`/`shift-tab` move · `ctrl-g` generate password · `ctrl-r` show secrets · `esc` cancel |
| Lock screen | `enter` Touch ID · `g` GPG passphrase · `q` quit |

## Files

| Path | What | Sync it? |
|---|---|---|
| `iCloud Drive/bks/<name>/vault.gpg` (chosen at `bks init`; `bks vault list` shows where each vault is) | a vault | yes: in iCloud Drive it reaches your other Macs |
| `~/.config/bks/vaults.json` | which vaults this Mac knows, the default | no |
| `~/.local/state/bks/` (one folder per vault) | this Mac only: Touch ID key blob, the vault's pinned fingerprint, last good copy, a public-key-only GnuPG home | **never** |

## Backups and recovery

Keep these **offline** (not on the Mac, not in iCloud):

1. An export of your GPG secret key — `gpg --armor --export-secret-keys <fingerprint>`.
2. Its passphrase, written down and stored apart from that export.
3. The key's revocation certificate.
4. Copies of `vault.gpg` (it is encrypted; normal backups are fine).

Touch ID is tied to one Mac's Secure Enclave, so it is **not** a backup. With 1 and 2 you can always recover, even without bks:

```sh
gpg -d vault.gpg | jq .
```

With GnuPG 2.5, `gpg -d` first asks for "the passphrase for decryption": that is the vault's Touch ID secret, which you don't know. Type anything there; gpg then asks for your key's passphrase. (bks itself never shows that prompt.)

To add a second way in (a backup key, a YubiKey): `bks recipients add <fingerprint>`.

## Limitations

- macOS only for Touch ID, screen-lock detection and the private clipboard; the rest is portable Go but untested elsewhere.
- No file attachments, no browser autofill, no phone app. For the few logins you need on a phone, Apple Passwords (iCloud Keychain) is a good companion.
- Not independently audited. Read [SECURITY.md](SECURITY.md) for the threat model and design.

## Development

```sh
make test      # builds both binaries and runs all tests
make site      # rebuilds docs/guide.html from GUIDE.md
```

How releases are made: [RELEASING.md](RELEASING.md). Changes: [CHANGELOG.md](CHANGELOG.md). Planned: [TODO.md](TODO.md).

Tests use throwaway GnuPG homes (never your keyring), a fake pinentry, and a private pasteboard (never your clipboard).

## License

[MIT](LICENSE). The passphrase word list is the [EFF Large Wordlist](https://www.eff.org/dice) (CC BY 3.0 US).
