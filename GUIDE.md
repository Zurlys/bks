# Using bks

Everything you do day to day: opening the vault, finding and copying entries, adding and editing them, tags, one-time codes and every keyboard shortcut. For installation see the [README](README.md).

- [Open and unlock](#open-and-unlock)
- [Vaults: where they live, and several of them](#vaults-where-they-live-and-several-of-them)
- [Find an entry](#find-an-entry)
- [Copy a password, username or code](#copy-a-password-username-or-code)
- [Add an entry](#add-an-entry)
- [Edit or delete an entry](#edit-or-delete-an-entry)
- [Tags](#tags)
- [One-time codes](#one-time-codes)
- [Generate a password](#generate-a-password)
- [Locking](#locking)
- [Keyboard shortcuts](#keyboard-shortcuts)
- [Command line](#command-line)

## Open and unlock

```sh
bks
```

bks asks for **Touch ID** if you enrolled it (`bks touchid enroll`). The Touch ID dialog has a **Use GPG passphrase** button; otherwise, or without Touch ID, your GPG key's passphrase dialog opens. Cancel stops.

The first time a Mac opens a vault, bks shows how many entries it holds and which keys can open it, and asks whether to trust it. Say yes only for a vault file you know is yours.

## Vaults: where they live, and several of them

`bks init` asks for a name (the first one is `personal`) and where the vault should live:

1. **iCloud Drive** (`iCloud Drive/bks/<name>/vault.gpg`), when iCloud Drive is on. Recommended: the vault reaches your other Macs and iCloud keeps it if this Mac is lost. iCloud only ever stores the encrypted file.
2. **This Mac only** (`~/.local/share/bks/<name>/vault.gpg`). bks then says whether it sees a Time Machine backup; if not, keep a copy of the file somewhere safe yourself.
3. **Another folder** you type. bks merges the conflict copies of iCloud Drive, Dropbox and Syncthing; with other services, edits made on two Macs at the same time can be lost.

bks remembers its vaults in `~/.config/bks/vaults.json`. When a vault is not in iCloud Drive, `bks` offers on start to move it there: `m` moves it, `enter` asks again next time, `n` stops asking for that vault.

**On another Mac**, wait until iCloud Drive shows `bks/<name>/vault.gpg`, then run `bks init`, pick the same name and place, and answer yes to *Add it to this Mac?* bks unlocks it once with your GPG key and pins it to that Mac.

**Several vaults** (personal, work, …): run `bks init <name>` for each, e.g. `bks init work`. Each has its own GPG keys, its own Touch ID enrolment and its own lock. With more than one, `bks` asks which to open (enter takes the last one used); the vault's name stays in the header and on the lock screen. **`ctrl-v`** switches: bks wipes the open vault from memory (it restarts, as when it locks), shows the list with the other vault preselected, and you unlock that one. Pick one directly with `-v`:

```sh
bks -v work                 # open the work vault
bks -v work get github      # or: bks get -v work github
```

Commands without `-v` use the default vault (marked `*` in `bks vault list`); with several vaults and no default they stop and ask for `-v`.

```sh
bks vault list                      # names, where they are, the default
bks vault move personal             # into iCloud Drive (or: bks vault move personal <path>)
bks vault default work              # the vault for commands without -v
bks vault rename work business
bks vault add shared <path>         # list a vault file that is already there
bks vault remove shared             # bks forgets it; nothing is deleted
```

`bks vault move` copies the vault, checks the copy byte for byte, switches to it, and renames the old file to `vault.gpg.moved-<date>` so nothing opens the stale copy. Delete that once the new place works. Close other bks windows of that vault before moving it.

## Find an entry

Just type: the search box always has the focus.

- Type fragments of what you remember, in any order: `jane corp` finds `jane.doe@corp.example`, `git work` finds "GitLab (work)".
- Letters must appear in that order within one field, but may have gaps: `gtlb` finds "GitLab".
- Accents don't matter: `petraite` finds "Petraitė".
- `#work` finds entries tagged `work`; `#work git` finds entries tagged `work` that also match `git`.
- Searched: title, username, the host part of URLs, tags and the names of custom fields. Never searched: passwords, notes, one-time-code secrets and field values.

Best matches come first. `↑` `↓` move, `esc` clears the search (a second `esc` quits).

## Copy a password, username or code

| Key | Copies |
|---|---|
| `enter` | the password of the selected entry |
| `ctrl-u` | the username |
| `ctrl-o` | the current one-time code |

For anything else, press `tab` to move into the entry's fields, choose one with `↑` `↓` and press `enter` to copy it. `r` shows a hidden value (password, secret field) for 10 seconds; long values wrap.

Copies stay on this Mac — they don't go to your iPhone through Universal Clipboard and clipboard-history apps skip them — and the clipboard is cleared after 30 seconds, unless you copied something else in the meantime. The status line says what was copied and counts down.

## Add an entry

### In the UI

Press `ctrl-n`. A form opens:

| Field | What to enter |
|---|---|
| title | required; what you'll search for, e.g. `GitLab (work)` |
| username | login name or email |
| password | type it, or press `ctrl-g` to generate a 24-character one; `ctrl-r` shows what you typed |
| urls | one or more, separated by spaces |
| tags | separated by spaces, with or without `#`: `#work #git` |
| otp | the one-time-code secret: the `otpauth://…` link from the QR code, or the text code shown under "can't scan the QR code?" |
| notes | free text, several lines (`enter` starts a new line here) |

Move between fields with `tab` / `shift-tab` (or `↓` / `↑`, and `enter` outside the notes). **Save with `ctrl-s`.** `esc` cancels; if you changed something, press `esc` twice to throw the changes away.

### From the command line

```sh
bks add --title "GitHub" --user jane --url https://github.com --tag dev --tag personal --generate 24
```

| Option | Meaning |
|---|---|
| `--title` | required |
| `--user` | username |
| `--url` | a URL; repeat for more |
| `--tag` | a tag; repeat for more |
| `--notes` | notes |
| `--generate 24` | generate a password of 24 characters (`--no-symbols` for letters and digits only) |
| `--words 6` | generate a passphrase of 6 words instead |
| `--password-stdin` | read the password from stdin: `pbpaste \| bks add --title X --password-stdin` |
| `--otp` | ask for the one-time-code secret, hidden |
| `--otp-stdin` | read the one-time-code secret from stdin |

Without `--generate`, `--words` or `--password-stdin`, bks asks for the password without echoing it (press `enter` on an empty prompt to generate one). Secrets are never taken as command-line arguments, because those end up in your shell history.

### From 1Password

```sh
bks import 1password ~/export.1pux --dry-run    # see what would be imported; shows no secrets
bks import 1password ~/export.1pux              # import, then offers to delete the export
```

Export from 1Password with File → Export → your account → `.1pux`, into a folder that is **not** synced to iCloud (not the Desktop or Documents). Attachments are not imported: save them elsewhere before you leave 1Password; the import lists which entries had them. Importing the same export again adds nothing twice.

## Edit or delete an entry

- **Edit:** select the entry and press `ctrl-e` (or `e` while in its fields). The same form opens, filled in. Save with `ctrl-s`.
  - Changing the password keeps the old one: bks stores the five previous passwords of each entry in the vault.
  - The otp field starts empty when a code is set: leave it empty to keep the code, type a new secret to replace it, or type `-` to remove it.
  - Custom fields (for example those imported from 1Password) are kept as they are; the form does not edit them yet.
- **Delete:** select the entry, press `ctrl-d`, then `y`. Any other key keeps it.

If another Mac saved the vault while you were editing, bks merges both sets of changes when you save. If saving fails, the form stays open with everything you typed.

## Tags

Tags group entries so you can find them by category: `#work`, `#bank`, `#family`, `#server`.

- **Add tags** in the form's tags field (`#work #git`) or with `--tag work --tag git` on the command line. The `#` is optional; bks stores tags without it.
- **Search by tag** with `#`: `#work` lists everything tagged `work`; `#work git` narrows it down; a plain word like `work` also matches tags, along with titles and usernames.
- **List** entries with a tag from the shell: `bks ls '#work'` (quote it: `#` starts a comment in the shell).
- **Imported tags:** a 1Password import keeps your 1Password tags, adds the kind of item for non-logins (`credit-card`, `ssh-key`, `secure-note`, …), and the 1Password vault's name when you exported more than one vault.

## One-time codes

Add a code by filling the **otp** field of an entry (in the form, or `bks add … --otp`). bks accepts the full `otpauth://` link from the QR code or the text code (base32) that sites show under "can't scan the QR code?".

- In the UI the code is shown live with a countdown bar; in the last five seconds the next code is shown too.
- `ctrl-o` copies the current code; in the fields view, `enter` on the one-time row does the same.
- From the shell: `bks otp github` prints the code (and how long it stays valid, on stderr).

## Generate a password

```sh
bks gen                       # 24 characters: letters, digits, symbols (~151 bits)
bks gen -l 32 --no-symbols    # letters and digits only, for sites that reject symbols
bks gen --words 6             # six words, e.g. chest-siesta-announcer-sneeze-speech-barn (~78 bits)
bks gen --words 5 --sep ' '   # words separated by spaces
```

In the form, `ctrl-g` fills the password field with a 24-character password. Look-alike characters (`0 O 1 l I`) are never used.

## Locking

bks locks itself when the screen locks, the screensaver starts, the Mac sleeps or the display goes to sleep, when you switch user, after 5 idle minutes, and after 8 hours. `ctrl-l` locks immediately.

Locking closes the UI and restarts bks at the lock screen, so nothing decrypted stays in memory. Unsaved changes in an open form are discarded.

| On the lock screen | |
|---|---|
| `enter` | unlock (Touch ID if enrolled, otherwise your GPG passphrase) |
| `g` | unlock with your GPG passphrase |
| `q` / `esc` | quit |

## Keyboard shortcuts

### Everywhere in the UI

| Key | Action |
|---|---|
| `ctrl-l` | lock now |
| `ctrl-v` | switch to another vault (with several vaults; in the search box it is no longer paste, ⌘V still is) |
| `ctrl-c` | quit |

### Entry list (the search box has the focus)

| Key | Action |
|---|---|
| typing | search |
| `↑` / `↓` | previous / next entry (also `ctrl-k`, `ctrl-p` / `ctrl-j`) |
| `page up` / `page down` | jump a page |
| `enter` | copy password |
| `ctrl-u` | copy username |
| `ctrl-o` | copy one-time code |
| `tab` | go to the entry's fields |
| `ctrl-n` | new entry |
| `ctrl-e` | edit entry |
| `ctrl-d` | delete entry (asks first) |
| `esc` | clear the search; quit when it is empty |

### Entry fields (after `tab`)

| Key | Action |
|---|---|
| `↑` / `↓` | previous / next field (also `k` / `j`) |
| `enter` | copy the field (the one-time row copies the current code) |
| `r` | reveal a hidden value for 10 seconds; press again to hide |
| `e` | edit the entry |
| `tab` / `esc` / `←` | back to the list |
| `ctrl-u`, `ctrl-o`, `ctrl-n`, `ctrl-e`, `ctrl-d` | as in the list |

### Edit form

| Key | Action |
|---|---|
| `ctrl-s` | save |
| `tab` / `shift-tab` | next / previous field (also `↓` / `↑`, and `enter` outside the notes) |
| `ctrl-g` | generate a password into the password field |
| `ctrl-r` | show / hide the password and one-time secret |
| `esc` | cancel (twice if you changed something) |

All other keys type into the field: `ctrl-u` and `ctrl-o` edit text here instead of copying.

### Delete confirmation

| Key | Action |
|---|---|
| `y` | delete |
| any other key | keep the entry |

## Command line

| Command | What it does |
|---|---|
| `bks` | open the UI |
| `bks get <search>` | print the password of the one matching entry |
| `bks get -f user <search>` | print another field: `user`, `url`, `notes`, `title`, `otp` or a custom field's name |
| `bks otp <search>` | print the current one-time code |
| `bks ls [<search>]` | list entries (no secrets) |
| `bks add …` | add an entry ([options](#from-the-command-line)) |
| `bks gen …` | generate a password ([options](#generate-a-password)) |
| `bks import 1password <file.1pux>` | import from 1Password (`--dry-run` first; `--archived` includes archived items) |
| `bks init` | create a vault: pick or create a GPG key, see what to back up, enable Touch ID |
| `bks touchid status\|enroll\|remove` | Touch ID on this Mac |
| `bks recipients` | who can open the vault |
| `bks recipients add <key>` | let another GPG key open it, e.g. a backup key |
| `bks recipients remove <key or name>` | stop a key from opening it (also replaces the vault's Touch ID secret; other Macs confirm once) |
| `bks rotate` | replace the vault's Touch ID secret |
| `bks version` | the version you are running |

`get` and `otp` refuse to guess: if your search matches several entries and none has exactly that title, they list the matches and exit with status 2. Use more words, or the exact title.

Useful in scripts:

```sh
export GITHUB_TOKEN="$(bks get -f token github)"
mycli login --code "$(bks otp myservice)"   # hand a code straight to a command
```

Environment variables: `BKS_VAULT` (a vault name or path, like `-v`), `BKS_CONFIG` (the list of vaults, default `~/.config/bks/vaults.json`), `BKS_STATE_DIR` (this Mac's state; only together with `BKS_VAULT=<path>`) and `BKS_UNLOCK=gpg` (skip Touch ID).
