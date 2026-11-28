# Security

bks guards passwords, so security reports get priority.

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's private reporting instead: **Security → Report a vulnerability** on [github.com/Zurlys/bks](https://github.com/Zurlys/bks/security). Include what you found, how to reproduce it, and what an attacker gains.

Only the latest `main` is supported; there are no maintained release branches yet.

## Threat model

**bks protects against**

- a stolen or lost Mac (powered off, or locked);
- someone using the Mac after the screen locks or it sleeps;
- the vault file leaking through sync, backups or git;
- a forged or rolled-back vault file arriving through sync;
- passwords leaking through the clipboard to other devices or to clipboard history;
- shoulder surfing (secrets are masked until revealed, for 10 s).

**bks does not protect against**

- malware running as your user while the vault is unlocked — it can read process memory, log keystrokes or read the clipboard. No password manager can stop that;
- a removed recipient reading **old** copies of the vault (backups, git history) — rotate the passwords that matter after removing one;
- someone who has both your GPG secret key and its passphrase.

## Design

### The vault

- One OpenPGP message containing JSON, produced by the real `gpg` (no OpenPGP code in bks). AES-256 (`--cipher-algo`, `--s2k-cipher-algo` and `--s2k-digest-algo SHA512` are all set: GnuPG 2.2 with only `--cipher-algo AES256` produces a file whose passphrase packet fails to decrypt).
- **Two ways in:** a public-key packet per recipient GPG subkey (pinned exactly, `fpr!`), and a symmetric packet for a random 256-bit unlock secret **U**. U is passed to gpg as 64 hex characters on a file descriptor — never raw bytes (gpg reads one line; raw bytes could be truncated), never in argv or the environment.
- **Verify before replace:** every save writes a temp file, decrypts it through U and compares, checks one public-key packet per pinned subkey, and only then renames it over the vault (keeping one `.bak`).
- `gpg -d vault.gpg` always works for recovery.

### Unlocking

- **GPG:** through normal pinentry, which says which key or card it wants — bks never forwards a passphrase over loopback, so a smartcard PIN can't be consumed by a wrong secret. Afterwards bks clears gpg-agent's cached passphrase for that key, so the next run asks again, and warns if GPG Suite saved the passphrase in the macOS Keychain.
- **Touch ID:** U is sealed to a Secure Enclave P-256 key created with `.privateKeyUsage` + `.biometryCurrentSet` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (ECIES: ephemeral ECDH, HKDF-SHA256, AES-GCM). The key blob only works on that Mac; adding or removing a fingerprint disables it. The Touch ID prompt text is fixed inside the helper.
- U is only ever used in a separate GnuPG home that holds public keys only, so gpg cannot offer it to a secret key or a smartcard.

### Forgery, rollback and sync

- Anyone who can write to your sync folder can build a vault your GPG key opens (only the public key is needed). Each Mac therefore **pins** `sha256(U)` on first use (after asking) and refuses any vault with a different U.
- Each Mac keeps its **last good copy** and merges it into every unlock: an older file arriving through sync cannot delete entries or roll passwords back (newer `updated` wins; deletions are tombstones).
- **Rotation** (`bks rotate`, `bks recipients remove`) creates a new U and keeps the old one as `prev_unlock_secret`; another Mac accepts it only if the old U matches its pin, and only after asking. Copies from before a rotation never bring back a removed recipient.

### Memory, clipboard and process

- **Locking re-executes the process** (`execve`) into a fresh, locked instance: Go cannot reliably wipe strings, a new process image can.
- Core dumps are disabled, `PT_DENY_ATTACH` is set, the umask is `077`, files are `0600` and directories `0700`. `bks` and `bks-mac` run with the hardened runtime (releases and `make` builds alike): macOS ignores `DYLD_*` library injection into them and refuses debuggers. No secret is ever written to a temp file; editing happens in the UI only.
- **Clipboard:** copies go through the helper with `.currentHostOnly` (no Universal Clipboard) and the `org.nspasteboard.ConcealedType` / `TransientType` markers; the helper verifies the markers and withdraws the copy otherwise. A detached clearer receives only the pasteboard change count (or, without the helper, a SHA-256 on stdin) and clears after 30 s only if nothing else was copied — it never reads the clipboard's contents.
- `~/.config/bks/vaults.json` says where each vault is and which state directory holds its pin. Pointing an entry at another vault file alone is caught: that state directory's pin reports the file as forged. Someone who can edit the config can also point it at a fresh state directory, which turns the next unlock into a first-use trust question (entries, recipients) instead; so the config needs the same protection as the state directories, as it has: both are private files of your user account.
- The helper is trusted only as the binary built next to `bks` (or an explicit `BKS_HELPER`), never from `PATH`: it handles U and every copied password.
- Screen lock, screensaver, sleep and user switch lock the UI; so does the screen-lock watcher dying, so a killed watcher cannot leave the vault open.

### Releases

- Built from the tag by the [release workflow](.github/workflows/release.yml) on GitHub-hosted runners; the tests run in a separate job with no access to any signing secret.
- Signed with a Developer ID Application certificate (hardened runtime, secure timestamp) and notarized by Apple once that is set up in the release workflow; until then releases are ad-hoc signed (from 0.1.0-alpha.3 with the hardened runtime), and their notes say so. Each archive is listed in `SHA256SUMS` and covered by a build-provenance attestation: `gh attestation verify <archive> --repo Zurlys/bks` proves it was built by that workflow from that tag, and `codesign -dv --verbose=2 bks` shows the Developer ID and team.
- The certificate and the notarization key live in a GitHub environment that serves only `v*` tags and needs the maintainer's approval for every run; each secret reaches only the step that uses it, and the signing keychain is deleted right after signing. The maintainer's GitHub account is therefore part of what you trust, as it is for the source.

## Known findings and accepted risks

- **Snyk Code, LOW, "Device Authentication Bypass"** on `LAContext.evaluatePolicy` in `macos/bks-mac.swift`. Accepted: that call only chooses which message to show (cancelled, use GPG, unavailable). The secret is released by the Secure Enclave key, whose biometric access control the Secure Enclave enforces itself; a hooked or faked `evaluatePolicy` result yields an unauthenticated context and the key operation fails or asks again.
- **Trust on first use:** the first unlock on a Mac pins whatever vault it sees (after showing its entry count and recipients). Unlock a new Mac from a vault file you trust.
- **Rotation race:** a removed recipient knows the old U; if they can also write to your sync folder they could race a forged rotation. Each Mac asks before accepting a rotation — say no if you did not rotate.
- **Clock skew:** merges compare `updated` times across Macs; a Mac with a wrong clock can win or lose a conflicting edit.
- **Exports are plain text:** a 1Password `.1pux` export holds every secret unencrypted. bks warns when it is in an iCloud-synced folder and offers to delete it after importing.
