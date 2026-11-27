# bks — design

How bks works inside. For the threat model and security properties see [SECURITY.md](SECURITY.md); for usage see [README.md](README.md).

Principles: keep it simple; never invent crypto (the real `gpg` does all OpenPGP work); the vault must stay readable with plain `gpg -d`; secrets never touch argv, the environment or temp files.

## Components

```
bks       Go, no cgo          CLI + TUI, vault model, search, TOTP, sync/merge, 1Password import
bks-mac   Swift, ~250 lines    Secure Enclave seal/unseal (Touch ID), screen-lock events, private clipboard
gpg       GnuPG 2.2+           all OpenPGP encryption and decryption
```

`bks` runs `bks-mac` as a child process and trusts only the copy built next to itself (or `$BKS_HELPER`). Without the helper, bks still works through GPG; it then says plainly that screen locks go undetected and copies reach other devices.

| Package | Role |
|---|---|
| `internal/gpg` | runs `gpg`: encrypt to subkeys + passphrase, decrypt, list packets, key listing/selection, key generation/export, agent cache clearing |
| `internal/vault` | the decrypted vault: entries, recipients, settings, unlock secret; validation; update with history; delete with tombstones; merge |
| `internal/store` | the vault file and per-Mac state: unlock (GPG or unlock secret), pin check, verified save, sync merge, rotation, Touch ID enrolment |
| `internal/search` | fuzzy ranking of entries |
| `internal/otp` | RFC 6238 TOTP from `otpauth://` URIs |
| `internal/tui` | Bubble Tea UI: list, detail, edit form, locking |
| `internal/clipboard` | copies via the helper (or `pbcopy`) and the detached clearer |
| `internal/importer` | 1Password `.1pux` import |
| `internal/macos` | helper wrapper, Keychain and iCloud checks |
| `internal/gen` | password and diceware generator |
| `macos/bks-mac.swift` | the helper |

## Files

| Path | What | Synced? |
|---|---|---|
| `$BKS_VAULT` (default `~/.local/share/bks/vault.gpg`) | the vault | optional — point `BKS_VAULT` into iCloud Drive / Syncthing (a real path, not a symlink: saves rename over it) |
| `vault.gpg.bak` | the previous vault, kept on every save | with the vault |
| `$BKS_STATE_DIR/device.json` (default `~/.local/state/bks`) | this Mac's pin of the unlock secret, Touch ID key blob and sealed secret | **never** |
| `$BKS_STATE_DIR/last-good.gpg` | this Mac's last opened or saved vault | **never** |
| `$BKS_STATE_DIR/gnupg/` | bks's own GnuPG home: recipients' public keys only | **never** (rebuilt from the vault) |

There is no configuration file: settings and recipients live inside the encrypted vault, so they sync with it.

## The vault file

```
vault.gpg = OpenPGP message (AES-256) containing JSON
  ├─ public-key packet per recipient subkey  → opens with your GPG key (pinentry);  gpg -d vault.gpg | jq
  └─ symmetric packet for the unlock secret U → U is sealed per Mac by the Secure Enclave (Touch ID)
```

- **U** is 32 random bytes, stored inside the JSON too (so after a GPG unlock bks can rewrite both ways in and enrol another Mac). It is handed to gpg as 64 hex characters on file descriptor 3.
- **Two GnuPG homes, never mixed.** Encryption and every unlock with U run in bks's own home, which holds public keys only — gpg there cannot offer U to a secret key or a smartcard. Your own home (`~/.gnupg`) is used only to decrypt with your key, through normal pinentry.
- **Recipients are pinned to exact subkeys** (`--recipient <subkey-fingerprint>!`), with their armored public keys stored in the vault and imported into bks's home on each Mac. Adding a subkey to a key later never silently changes who can open the vault.
- **Encryption flags:** `--encrypt --symmetric --cipher-algo AES256 --s2k-cipher-algo AES256 --s2k-digest-algo SHA512 --no-symkey-cache --trust-model always --pinentry-mode loopback --passphrase-fd 3`. All three algorithm flags are required: on GnuPG 2.2, `--cipher-algo AES256` alone produces a file whose symmetric packet fails ("Bad session key").
- **Verify before replace:** each save writes a temp file in the vault's directory, fsyncs it, decrypts it with U and compares, checks one public-key packet per pinned subkey, copies the old vault to `.bak`, then renames.
- **Expiry:** a pinned subkey that expires within 30 days produces a warning; an expired one stops saves with an explanation.

### JSON

```json
{
  "format": 1,
  "unlock_secret": "<base64, 32 bytes>",
  "prev_unlock_secret": "<base64, only after a rotation>",
  "recipients": [
    { "label": "Jane Doe <jane@example.com>", "subkey": "<40-hex subkey fingerprint>", "pubkey": "-----BEGIN PGP PUBLIC KEY BLOCK-----…" }
  ],
  "settings": { "idle_lock": "5m", "max_unlocked": "8h", "clipboard_clear": "30s" },
  "settings_updated": "2026-11-27T10:00:00Z",
  "entries": [{
    "id": "01JDX3…",
    "title": "GitLab (work)",
    "username": "jane.doe@corp.example",
    "password": "…",
    "otp": "otpauth://totp/GitLab:jane?secret=…&issuer=GitLab",
    "urls": ["https://gitlab.corp.example"],
    "tags": ["work", "git"],
    "notes": "…",
    "fields": [{ "name": "recovery codes", "value": "…", "secret": true }],
    "history": [{ "password": "…", "until": "2026-10-01T09:00:00Z" }],
    "created": "…", "updated": "…",
    "source": "1password:<item uuid>"
  }],
  "tombstones": [{ "id": "01JC…", "deleted": "…" }]
}
```

IDs are ULIDs. `history` keeps the five most recent previous passwords. `source` is set by imports so re-imports skip existing items.

## Unlocking and locking

| Event | What happens |
|---|---|
| `bks` starts | Touch ID (`bks-mac unseal` → U → decrypt in bks's home). Cancel cancels; "Use GPG passphrase" or an unavailable Touch ID falls back to GPG through pinentry, after which gpg-agent's cached passphrase for that key is cleared. `BKS_UNLOCK=gpg` skips Touch ID. |
| Screen lock, screensaver, sleep, display sleep, user switch | `bks-mac watch` reports it and the UI locks |
| The watcher dies | the UI locks |
| Wall clock jumps > 30 s between ticks | the UI locks (the Mac slept) |
| Idle 5 min · unlocked 8 h · `ctrl-l` | the UI locks |

**Locking quits the UI and re-executes bks** (`execve`) into a fresh process that starts at the lock screen. A garbage-collected Go process cannot reliably erase strings; a new process image does.

Unlocking happens before the full-screen UI starts; warnings from it (for example a passphrase saved in the macOS Keychain) are shown and must be acknowledged first.

## Trust, sync and merging

- **Pin:** each Mac stores `sha256(U)` on first unlock (after showing entry count and recipients and asking) and refuses any vault whose U differs. Someone who can write to your sync folder can build a vault your GPG key opens, but cannot know U.
- **Last good copy:** every unlock merges this Mac's `last-good.gpg` into what it read, so an older vault file — replayed by a sync tool or planted — cannot delete entries or roll passwords back. If the merge changed anything, it is saved.
- **Conflict copies** next to the vault (iCloud `vault 2.gpg`, Syncthing `vault.sync-conflict-….gpg`, Dropbox `vault (… conflicted copy …).gpg`) are merged on unlock and removed after the save. Files that do not open with U are left alone with a warning.
- **Saving after another Mac saved** merges the newer file in first, then saves.
- **Unreadable vault** (offline, evicted by iCloud): this Mac's last good copy opens read-only.
- **Merge rules:** per entry the newer `updated` wins; a tombstone removes an entry unless it was edited after the deletion; newer `settings_updated` wins; recipients are united — but only from copies with the current U.
- **Rotation** (`bks rotate`, `bks recipients remove`): a new U is generated and the old one kept as `prev_unlock_secret`. Another Mac accepts the new U only if the old one matches its pin, and only after asking; it then turns off its Touch ID enrolment for the old secret. The rotating Mac re-enrols Touch ID itself. Copies from before a rotation can never bring back a removed recipient.

## Touch ID

`bks-mac enroll` creates a Secure Enclave P-256 key-agreement key with access control `.privateKeyUsage | .biometryCurrentSet` and accessibility `WhenUnlockedThisDeviceOnly`, and seals U to it: ephemeral P-256 ECDH, HKDF-SHA256 (`bks-touchid-v1`), AES-GCM. Sealing needs no prompt. `unseal` asks for Touch ID with a fixed prompt text and a "Use GPG passphrase" fallback, then uses the authenticated context to open the box. The key blob is useless on any other Mac; adding or removing a fingerprint disables it (re-enrol with `bks touchid enroll`).

## Clipboard

`bks-mac copy` writes with `prepareForNewContents(with: .currentHostOnly)` (no Universal Clipboard) plus the `org.nspasteboard.ConcealedType` and `TransientType` markers, verifies the markers are present (else withdraws the copy), and prints the pasteboard change count. A detached `bks _clipclear <seconds>` process receives that change count on stdin and clears the pasteboard afterwards only if it is unchanged; it never reads the clipboard's contents. Without the helper, `pbcopy` is used and the clearer compares a SHA-256 instead.

## Search

Per entry, the searched text is the title, username, URL hosts, tags and custom field names — never passwords, OTP secrets, notes or field values. Text is lowercased and stripped of diacritics. Every whitespace-separated query token must match one field as a subsequence (fzf v1 scoring: word-start and consecutive-character bonuses, gap penalties); `#tag` tokens match tags only. Examples: `jane.doe@example` finds `jane.doe@corp.example`; `petraitė` and `petraite` give the same results.

## YubiKeys and backup keys

Any number of recipients can be added with `bks recipients add <fingerprint>`. A YubiKey has one OpenPGP encryption slot, so each card is either a copy of an existing encryption subkey or an independent key generated on the card (then a lost card is just `bks recipients remove`).

**FIPS YubiKeys (firmware 5.7.x FIPS series) block RSA decryption, X25519 and secp256k1 in OpenPGP** ([Yubico](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-140-3.html)), even with approved mode off: their encryption slot must be NIST P-256/P-384. `keytocard` of an RSA subkey then fails with "Bad secret key". Generate a P-384 key on the card instead:

```sh
gpg --card-edit
  admin
  passwd      # change PIN (default 123456) and Admin PIN (default 12345678) first
  key-attr    # ECC → NIST P-384 for all slots (Curve 25519 only on non-FIPS keys)
  generate    # "Make off-card backup of encryption key?" → n
quit
bks recipients add <new key's fingerprint>
```

A key on a card cannot be exported back out: it is a second way in, not a backup of your existing key. Keep the card's PIN and Admin PIN offline.

## Testing

`make test` builds both binaries and runs every test. Tests never touch your keyring, clipboard or vault: GnuPG homes are throwaway directories (with a fake pinentry where a passphrase is needed), `GNUPGHOME` points at an empty temp home, the helper's pasteboard tests use a private named pasteboard (`BKS_PASTEBOARD`), and Touch ID is replaced by a fake sealer. Tests that need a Secure Enclave skip on machines without one.
