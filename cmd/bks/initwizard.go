package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Zurlys/bks/internal/gpg"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/store"
)

// ui talks to the person on the terminal. Tests feed it strings.
type ui struct {
	in  *bufio.Reader
	out io.Writer
}

// ttyUI opens /dev/tty, so prompts never mix with stdout/stdin pipes.
func ttyUI() (*ui, func(), error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, errors.New("no terminal: run interactively, or pass --recipient <key>")
	}
	return &ui{in: bufio.NewReader(tty), out: tty}, func() { tty.Close() }, nil
}

func (u *ui) say(format string, a ...any) { fmt.Fprintf(u.out, format, a...) }

// ask prints prompt and returns the trimmed answer, or def when empty.
func (u *ui) ask(prompt, def string) (string, error) {
	u.say("%s", prompt)
	line, err := u.in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no answer: %w", err)
	}
	if line = strings.TrimSpace(line); line == "" {
		return def, nil
	}
	return line, nil
}

func (u *ui) yes(prompt string, def bool) (bool, error) {
	hint := " [y/N] "
	if def {
		hint = " [Y/n] "
	}
	for {
		a, err := u.ask(prompt+hint, map[bool]string{true: "y", false: "n"}[def])
		if err != nil {
			return false, err
		}
		switch strings.ToLower(a) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
	}
}

// initInteractive lets the person pick one of their GPG keys, or create a
// new one, explains what must be kept offline, and creates the vault.
func initInteractive(ctx context.Context, s *store.Store, u *ui) error {
	if _, err := os.Stat(s.VaultPath); err == nil {
		return fmt.Errorf("%w at %s", store.ErrExists, s.VaultPath)
	}
	u.say("bks keeps your passwords in one file, encrypted with a GPG key of yours.\n\n")

	keys, err := s.User.SecretKeys(ctx)
	if err != nil {
		return err
	}
	cands := gpg.EncryptionCandidates(keys, time.Now())
	var chosen gpg.Candidate
	if len(cands) == 0 {
		u.say("No GPG key on this Mac can encrypt (none with an encryption subkey whose secret part is here).\n")
		ok, err := u.yes("Create a new GPG key for bks now?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("init cancelled: bks needs a GPG key (or run: bks init --recipient <key>)")
		}
		if chosen, err = newKeyWizard(ctx, s, u); err != nil {
			return err
		}
	} else {
		if chosen, err = chooseKey(ctx, s, u, cands); err != nil {
			return err
		}
	}

	if err := backupChecklist(ctx, s, u, chosen.Primary); err != nil {
		return err
	}
	ok, err := u.yes(fmt.Sprintf("Create the vault at %s now?", s.VaultPath), true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("init cancelled")
	}
	sess, err := s.Init(ctx, []string{chosen.Encrypt.Fingerprint})
	if err != nil {
		return err
	}
	u.say("\nCreated %s, encrypted to:\n", s.VaultPath)
	for _, r := range sess.Vault.Recipients {
		u.say("  %s (subkey %s)\n", r.Label, r.Subkey)
	}
	return offerTouchID(ctx, s, u, sess)
}

// offerTouchID enrols Touch ID right after init when the helper exists.
func offerTouchID(ctx context.Context, s *store.Store, u *ui, sess *store.Session) error {
	h, err := macos.FindHelper()
	if err != nil {
		u.say("\nTouch ID: %v. After building it: bks touchid enroll\n", err)
		return nil
	}
	ok, err := u.yes("\nUnlock with Touch ID on this Mac? (the GPG passphrase keeps working)", true)
	if err != nil || !ok {
		return err
	}
	if err := s.EnrollTouchID(ctx, sess, h); err != nil {
		u.say("Touch ID enrolment failed: %v (retry later: bks touchid enroll)\n", err)
		return nil
	}
	u.say("Touch ID enrolled. A fingerprint change disables it; re-run bks touchid enroll then.\n")
	return nil
}

func chooseKey(ctx context.Context, s *store.Store, u *ui, cands []gpg.Candidate) (gpg.Candidate, error) {
	u.say("GPG keys on this Mac that can encrypt:\n\n")
	for i, c := range cands {
		u.say("  %d) %s\n", i+1, c.Primary.UID)
		u.say("     key %s\n", c.Primary.Fingerprint)
		where := ""
		if c.Encrypt.OnCard() {
			where = ", on smartcard " + c.Encrypt.Token
		}
		u.say("     encrypts with %s subkey %s%s, expires %s\n", c.Encrypt.AlgoName(), c.Encrypt.KeyID, where, expiry(c.Encrypt))
		if macos.GnuPGPassphraseSaved(c.Encrypt.Keygrip) {
			u.say("     ! its passphrase is saved in the macOS Keychain: unlocking with GPG would never ask\n")
		}
		u.say("\n")
	}
	u.say("  n) create a new GPG key just for bks\n\n")
	for {
		a, err := u.ask(fmt.Sprintf("Key to encrypt the vault with [1-%d/n]: ", len(cands)), "")
		if err != nil {
			return gpg.Candidate{}, err
		}
		if strings.EqualFold(a, "n") {
			return newKeyWizard(ctx, s, u)
		}
		i, err := strconv.Atoi(a)
		if err != nil || i < 1 || i > len(cands) {
			u.say("Please answer 1-%d or n.\n", len(cands))
			continue
		}
		c := cands[i-1]
		if macos.GnuPGPassphraseSaved(c.Encrypt.Keygrip) {
			ok, err := u.yes("That key's passphrase is in the Keychain, so the vault would open without asking. Use it anyway?", false)
			if err != nil || !ok {
				if err != nil {
					return gpg.Candidate{}, err
				}
				continue
			}
		}
		return c, nil
	}
}

func newKeyWizard(ctx context.Context, s *store.Store, u *ui) (gpg.Candidate, error) {
	u.say("\nNew GPG key for bks\n")
	u.say("  type: ed25519 for signing + cv25519 for encryption (modern, fast)\n\n")
	var name string
	for name == "" {
		var err error
		if name, err = u.ask("Your name: ", ""); err != nil {
			return gpg.Candidate{}, err
		}
	}
	email, err := u.ask("Email (optional): ", "")
	if err != nil {
		return gpg.Candidate{}, err
	}
	var expire string
	for {
		if expire, err = u.ask("Expires (never, or e.g. 2y, 18m) [never]: ", "never"); err != nil {
			return gpg.Candidate{}, err
		}
		if gpg.ValidExpiry(expire) {
			break
		}
		u.say("Please answer never, or a number with d/w/m/y, e.g. 2y.\n")
	}
	uid := name
	if email != "" {
		uid = fmt.Sprintf("%s <%s>", name, email)
	}
	u.say("\ngpg now asks for the new key's passphrase in a separate window (twice).\n")
	u.say("That passphrase is the master password of your vault: make it long, and do not\n")
	u.say("let it be saved in the macOS Keychain.\n\n")
	k, err := s.User.GenerateKey(ctx, uid, expire)
	if err != nil {
		return gpg.Candidate{}, err
	}
	keys, err := s.User.SecretKeys(ctx)
	if err != nil {
		return gpg.Candidate{}, err
	}
	for _, c := range gpg.EncryptionCandidates(keys, time.Now()) {
		if c.Primary.Fingerprint == k.Fingerprint {
			u.say("Created key %s\n  %s\n", c.Primary.UID, c.Primary.Fingerprint)
			return c, nil
		}
	}
	return gpg.Candidate{}, fmt.Errorf("new key %s has no usable encryption subkey", k.Fingerprint)
}

// backupChecklist says exactly what must be kept offline so the vault can
// always be opened, and offers to write the secret-key export now.
func backupChecklist(ctx context.Context, s *store.Store, u *ui, primary gpg.Key) error {
	fpr := primary.Fingerprint
	short := fpr[len(fpr)-8:]
	rev := "(unknown GnuPG home)"
	revNote := ""
	if home, err := s.User.Homedir(ctx); err == nil {
		rev = filepath.Join(home, "openpgp-revocs.d", fpr+".rev")
		if _, err := os.Stat(rev); err != nil {
			revNote = fmt.Sprintf("     missing: create it with  gpg --output %s.rev --gen-revoke %s\n", short, fpr)
		}
	}
	u.say("\n== Keep these OFFLINE, away from this Mac (USB stick in a drawer, a safe) ==\n")
	u.say("   Not in iCloud Drive, and not on the Desktop or in Documents if those sync to iCloud.\n\n")
	u.say("  1. An export of the secret key:\n")
	u.say("       gpg --armor --export-secret-keys %s > /Volumes/<usb>/bks-key-%s.asc\n", fpr, short)
	u.say("  2. The key's passphrase, on paper, stored apart from that export.\n")
	u.say("  3. The revocation certificate, to disable the key if it ever leaks:\n")
	u.say("       %s\n%s", rev, revNote)
	u.say("  4. Copies of the vault file itself (it is encrypted; Time Machine, iCloud or git are fine):\n")
	u.say("       %s\n\n", s.VaultPath)
	u.say("Without 1 and 2, nobody can open the vault if this Mac dies or ~/.gnupg is lost,\n")
	u.say("not even you. Touch ID will only ever work on this Mac, so it is not a backup.\n\n")

	for {
		path, err := u.ask("Write the secret-key export now? Path on a USB stick, or Enter to skip: ", "")
		if err != nil {
			return err
		}
		if path == "" {
			u.say("Skipped: do step 1 before you rely on the vault.\n\n")
			return nil
		}
		path = expandHome(path)
		if macos.ICloudSynced(path) {
			u.say("That folder is synced to iCloud, so the export would be uploaded. Choose a USB stick or another folder.\n")
			continue
		}
		if err := s.User.ExportSecretKey(ctx, fpr, path); err != nil {
			u.say("Export failed: %v\n", err)
			continue
		}
		u.say("Wrote %s (gpg asked for the passphrase; the export stays protected by it).\n", path)
		if home, _ := os.UserHomeDir(); home != "" && strings.HasPrefix(path, home+string(os.PathSeparator)) {
			u.say("That is on this Mac: move it to offline storage and delete it here.\n")
		}
		u.say("\n")
		return nil
	}
}

func expiry(k gpg.Key) string {
	if k.Expires.IsZero() {
		return "never"
	}
	return k.Expires.Format("2006-01-02")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
