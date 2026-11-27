// Package store keeps the encrypted vault file and this Mac's state: the pin
// of the vault's unlock secret and bks's own public-key-only GnuPG home.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Zurlys/bks/internal/gpg"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/vault"
)

var (
	ErrNoVault    = errors.New("no vault yet: run 'bks init --recipient <fingerprint>'")
	ErrExists     = errors.New("a vault already exists")
	ErrNotTrusted = errors.New("vault not trusted on this Mac")
	ErrForged     = errors.New("the vault's unlock secret does not match the one pinned on this Mac: " +
		"the file was replaced or forged, refusing to use it")
	ErrChanged = errors.New("the vault changed on disk since it was unlocked; unlock again and retry")
)

// expiryWarning is how early a recipient's coming expiry is reported.
const expiryWarning = 30 * 24 * time.Hour

// maxSocketPath keeps gpg-agent sockets under the 104-byte macOS limit.
const maxSocketPath = 100

// Store is the vault file plus this Mac's state.
type Store struct {
	VaultPath string
	StateDir  string
	User      gpg.GPG // the user's keyring: door 1 and exporting recipients
	BKS       gpg.GPG // bks's own keyring (public keys only): encrypt, door 2, checks
	// Confirm asks a yes/no question (trust on first use). nil means no.
	Confirm func(question string) bool
	// Warn reports a non-fatal problem. nil discards it.
	Warn func(msg string)
	Now  func() time.Time

	afterWrite func(tmp string) // test hook between writing and verifying
}

// New returns a Store whose own keyring lives in stateDir/gnupg.
func New(vaultPath, stateDir string, user gpg.GPG) *Store {
	return &Store{
		VaultPath: vaultPath,
		StateDir:  stateDir,
		User:      user,
		BKS:       gpg.GPG{Home: filepath.Join(stateDir, "gnupg")},
		Now:       time.Now,
	}
}

// Default uses $BKS_VAULT and $BKS_STATE_DIR, else
// ~/.local/share/bks/vault.gpg and ~/.local/state/bks, and the user's
// default GnuPG home.
func Default() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	vp := os.Getenv("BKS_VAULT")
	if vp == "" {
		vp = filepath.Join(home, ".local", "share", "bks", "vault.gpg")
	}
	sd := os.Getenv("BKS_STATE_DIR")
	if sd == "" {
		sd = filepath.Join(home, ".local", "state", "bks")
	}
	s := New(vp, sd, gpg.GPG{})
	if n := len(filepath.Join(s.BKS.Home, "S.gpg-agent.browser")); n > maxSocketPath {
		return nil, fmt.Errorf("state dir path too long for gpg-agent sockets (%d bytes): set BKS_STATE_DIR shorter", n)
	}
	return s, nil
}

// Session is an unlocked vault.
type Session struct {
	Vault *vault.Vault
	// ReadOnly: the vault file could not be read, so this is this Mac's last
	// good copy. It cannot be saved.
	ReadOnly bool
	// Merged: the last unlock or save merged in changes from another copy.
	Merged bool

	hash      [32]byte // sha256 of vault.gpg as unlocked or last saved
	isNew     bool     // not yet written
	conflicts []string // merged sync-conflict copies, removed after the next save
}

func (s *Store) warn(format string, a ...any) {
	if s.Warn != nil {
		s.Warn(fmt.Sprintf(format, a...))
	}
}

// Init creates a new vault encrypted to the given keys (fingerprints or key
// IDs in the user's keyring) and pins it to this Mac.
func (s *Store) Init(ctx context.Context, keys []string) (*Session, error) {
	if _, err := os.Stat(s.VaultPath); err == nil {
		return nil, fmt.Errorf("%w at %s", ErrExists, s.VaultPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one recipient key is required")
	}
	var recipients []vault.Recipient
	for _, k := range keys {
		r, err := s.resolveRecipient(ctx, k)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}
	v, err := vault.New(recipients, s.Now())
	if err != nil {
		return nil, err
	}
	if err := s.prepareKeyring(ctx, v); err != nil {
		return nil, err
	}
	sess := &Session{Vault: v, isNew: true}
	if err := s.Save(ctx, sess); err != nil {
		return nil, err
	}
	return sess, s.saveDevice(device{Pin: v.Pin()})
}

// resolveRecipient pins the exact encryption subkey of key in the user's
// keyring and takes a minimal export of its public key.
func (s *Store) resolveRecipient(ctx context.Context, key string) (vault.Recipient, error) {
	k, err := s.User.EncryptionKey(ctx, key, s.Now())
	if err != nil {
		return vault.Recipient{}, err
	}
	pub, err := s.User.ExportPublic(ctx, k.Primary)
	if err != nil {
		return vault.Recipient{}, err
	}
	return vault.Recipient{Label: k.UID, Subkey: k.Fingerprint, PubKey: string(pub)}, nil
}

// UnlockGPG opens the vault through door 1: a recipient's secret key in the
// user's keyring, asked for by pinentry. Afterwards gpg-agent forgets that
// passphrase, so the next run asks again.
func (s *Store) UnlockGPG(ctx context.Context) (*Session, error) {
	ct, readOnly, err := s.readVault()
	if err != nil {
		return nil, err
	}
	pt, derr := s.User.Decrypt(ctx, ct)
	s.forgetPassphrases(ctx, ct)
	if derr != nil {
		return nil, derr
	}
	return s.open(ctx, ct, pt, "", readOnly)
}

// UnlockWithSecret opens the vault through door 2 with the unlock secret U
// (from the Secure Enclave once Touch ID exists). gpg runs in bks's own
// keyring, which has no secret keys, so U can never reach a key or a
// smartcard PIN prompt.
func (s *Store) UnlockWithSecret(ctx context.Context, u []byte) (*Session, error) {
	ct, readOnly, err := s.readVault()
	if err != nil {
		return nil, err
	}
	if err := s.ensureKeyringDir(); err != nil {
		return nil, err
	}
	pass := vault.PassphraseFor(u)
	pt, err := s.BKS.DecryptWithPassphrase(ctx, ct, pass)
	if err != nil {
		return nil, err
	}
	return s.open(ctx, ct, pt, pass, readOnly)
}

// readVault reads the vault file. If it cannot (offline, evicted by iCloud,
// deleted) but this Mac has a last good copy, that copy is returned with
// readOnly set.
func (s *Store) readVault() (ct []byte, readOnly bool, err error) {
	ct, err = os.ReadFile(s.VaultPath)
	if err == nil {
		return ct, false, nil
	}
	if lg, lerr := os.ReadFile(s.lastGoodPath()); lerr == nil {
		s.warn("cannot read %s (%v): showing this Mac's last good copy, read-only", s.VaultPath, err)
		return lg, true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("%w (looked at %s)", ErrNoVault, s.VaultPath)
	}
	return nil, false, err
}

// open checks a decrypted vault before anything from it is trusted: the
// unlock secret inside must match this Mac's pin. Only then are the
// recipients' public keys imported.
func (s *Store) open(ctx context.Context, ct, pt []byte, passUsed string, readOnly bool) (*Session, error) {
	v, err := vault.Parse(pt)
	if err != nil {
		return nil, err
	}
	if passUsed != "" && subtle.ConstantTimeCompare([]byte(passUsed), []byte(v.Passphrase())) != 1 {
		return nil, ErrForged
	}
	if err := s.checkPin(v); err != nil {
		return nil, err
	}
	if err := s.prepareKeyring(ctx, v); err != nil {
		return nil, err
	}
	sess := &Session{Vault: v, hash: sha256.Sum256(ct), ReadOnly: readOnly}
	if readOnly {
		return sess, nil
	}
	if s.mergeCopies(ctx, sess, ct) {
		if err := s.Save(ctx, sess); err != nil {
			s.warn("merged changes from other copies but could not save them yet: %v", err)
		}
	} else {
		s.writeLastGood(ct)
	}
	return sess, nil
}

func (s *Store) checkPin(v *vault.Vault) error {
	d, err := s.loadDevice()
	if err != nil {
		return err
	}
	if d.Pin == "" {
		labels := make([]string, len(v.Recipients))
		for i, r := range v.Recipients {
			labels[i] = r.Label
		}
		q := fmt.Sprintf("First unlock of %s on this Mac:\n  entries:    %d\n  recipients: %s\nTrust this vault and pin it to this Mac?",
			s.VaultPath, len(v.Entries), strings.Join(labels, "; "))
		if s.Confirm == nil || !s.Confirm(q) {
			return ErrNotTrusted
		}
		return s.saveDevice(device{Pin: v.Pin()})
	}
	if subtle.ConstantTimeCompare([]byte(d.Pin), []byte(v.Pin())) == 1 {
		return nil
	}
	// The secret was rotated on another Mac: accept it only if the vault
	// proves it knew our pinned secret, and only after asking.
	if len(v.PrevUnlockSecret) > 0 && subtle.ConstantTimeCompare([]byte(d.Pin), []byte(vault.PinFor(v.PrevUnlockSecret))) == 1 {
		labels := make([]string, len(v.Recipients))
		for i, r := range v.Recipients {
			labels[i] = r.Label
		}
		q := fmt.Sprintf("The vault's unlock secret was rotated on another Mac (recipients now: %s).\nAccept the rotation on this Mac?", strings.Join(labels, "; "))
		if s.Confirm == nil || !s.Confirm(q) {
			return ErrNotTrusted
		}
		if d.TouchID != nil {
			s.warn("Touch ID was set up for the old unlock secret and is now off on this Mac: run bks touchid enroll")
		}
		d.Pin, d.TouchID = v.Pin(), nil
		return s.saveDevice(d)
	}
	return ErrForged
}

// forgetPassphrases clears gpg-agent's cached passphrase for every message
// recipient this keyring holds, and warns if pinentry saved one in the
// macOS Keychain (then door 1 would not ask at all).
func (s *Store) forgetPassphrases(ctx context.Context, ct []byte) {
	if s.ensureKeyringDir() != nil {
		return
	}
	ids, _, err := s.BKS.Packets(ctx, ct)
	if err != nil {
		s.warn("could not list vault recipients to clear gpg-agent's cache: %v", err)
		return
	}
	for _, id := range ids {
		k, err := s.User.Key(ctx, id)
		if err != nil || k.Keygrip == "" {
			continue // not in this keyring
		}
		if err := s.User.ClearPassphrase(ctx, k.Keygrip); err != nil {
			s.warn("gpg-agent still caches the passphrase of %s: %v", k.KeyID, err)
		}
		if macos.GnuPGPassphraseSaved(k.Keygrip) {
			s.warn("the passphrase of %s is saved in the macOS Keychain (GPG Suite 'Save in Keychain'), "+
				"so the GPG unlock never asks. Delete the Keychain item 'GnuPG' with account %s.", k.KeyID, k.Keygrip)
		}
	}
}

func (s *Store) ensureKeyringDir() error {
	if err := os.MkdirAll(s.BKS.Home, 0o700); err != nil {
		return err
	}
	return os.Chmod(s.BKS.Home, 0o700)
}

// prepareKeyring imports the recipients' public keys into bks's keyring.
func (s *Store) prepareKeyring(ctx context.Context, v *vault.Vault) error {
	if err := s.ensureKeyringDir(); err != nil {
		return err
	}
	for _, r := range v.Recipients {
		if _, err := s.BKS.Key(ctx, r.Subkey); err == nil {
			continue
		}
		if err := s.BKS.Import(ctx, []byte(r.PubKey)); err != nil {
			return fmt.Errorf("recipient %q: %w", r.Label, err)
		}
		if _, err := s.BKS.Key(ctx, r.Subkey); err != nil {
			return fmt.Errorf("recipient %q: its public key has no subkey %s", r.Label, r.Subkey)
		}
	}
	return nil
}

// Save encrypts the vault to all recipients and to U, verifies the new file
// through both checks, keeps the previous file as .bak and atomically
// replaces the vault. If another Mac saved since unlock, its changes are
// merged in first (sess.Vault is updated in place).
func (s *Store) Save(ctx context.Context, sess *Session) error {
	if sess.ReadOnly {
		return errors.New("read-only: the vault file could not be read, this is this Mac's last good copy")
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()

	v := sess.Vault
	cur, err := os.ReadFile(s.VaultPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !sess.isNew {
			return ErrChanged
		}
		cur = nil
	case err != nil:
		return err
	case sess.isNew:
		return fmt.Errorf("%w at %s", ErrExists, s.VaultPath)
	case sha256.Sum256(cur) != sess.hash:
		other, union, err := s.openCopy(ctx, cur, v)
		if err != nil {
			return fmt.Errorf("%w; it no longer opens with this vault's unlock secret (rotated on another Mac?)", ErrChanged)
		}
		merged, _ := vault.Merge(v, other, union)
		*v = *merged
		sess.Merged = true
	}
	pt, err := v.Marshal()
	if err != nil {
		return err
	}

	subkeys, err := s.checkRecipients(ctx, v)
	if err != nil {
		return err
	}
	ct, err := s.BKS.Encrypt(ctx, pt, subkeys, v.Passphrase())
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.VaultPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := writeTemp(dir, filepath.Base(s.VaultPath), ct)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmp)
		}
	}()
	if s.afterWrite != nil {
		s.afterWrite(tmp)
	}
	written, err := s.verify(ctx, tmp, pt, v.Passphrase(), subkeys)
	if err != nil {
		return fmt.Errorf("new vault file failed verification, vault left unchanged: %w", err)
	}
	if cur != nil {
		if err := writeFileAtomic(s.VaultPath+".bak", cur); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, s.VaultPath); err != nil {
		return err
	}
	committed = true
	syncDir(dir)
	sess.hash, sess.isNew = sha256.Sum256(written), false
	s.writeLastGood(written)
	for _, p := range sess.conflicts {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.warn("could not remove merged conflict copy %s: %v", p, err)
		}
	}
	sess.conflicts = nil
	return nil
}

// verify re-reads the written file and proves both doors: door 2 decrypts it
// to exactly pt, and there is one public-key packet per pinned subkey.
func (s *Store) verify(ctx context.Context, path string, pt []byte, pass string, subkeys []string) ([]byte, error) {
	got, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	back, err := s.BKS.DecryptWithPassphrase(ctx, got, pass)
	if err != nil {
		return nil, fmt.Errorf("unlock-secret door: %w", err)
	}
	if !bytes.Equal(back, pt) {
		return nil, errors.New("unlock-secret door: content differs")
	}
	ids, sym, err := s.BKS.Packets(ctx, got)
	if err != nil {
		return nil, err
	}
	if sym != 1 {
		return nil, fmt.Errorf("expected 1 passphrase packet, found %d", sym)
	}
	have := map[string]bool{}
	for _, id := range ids {
		have[id] = true
	}
	for _, sk := range subkeys {
		if !have[sk[len(sk)-16:]] {
			return nil, fmt.Errorf("GPG door: no packet for recipient subkey %s", sk)
		}
	}
	return got, nil
}

// checkRecipients returns the pinned subkeys, refusing expired or revoked
// ones and warning about coming expiries.
func (s *Store) checkRecipients(ctx context.Context, v *vault.Vault) ([]string, error) {
	if err := s.prepareKeyring(ctx, v); err != nil {
		return nil, err
	}
	now := s.Now()
	var subkeys []string
	for _, r := range v.Recipients {
		k, err := s.BKS.Key(ctx, r.Subkey)
		if err != nil {
			return nil, fmt.Errorf("recipient %q: %w", r.Label, err)
		}
		switch {
		case k.Validity == "r":
			return nil, fmt.Errorf("recipient %q: subkey %s is revoked", r.Label, k.KeyID)
		case !strings.Contains(k.Usage, "e"):
			return nil, fmt.Errorf("recipient %q: subkey %s cannot encrypt", r.Label, k.KeyID)
		case k.Expired(now):
			return nil, fmt.Errorf("recipient %q: subkey %s expired on %s; extend it with gpg --quick-set-expire",
				r.Label, k.KeyID, k.Expires.Format("2006-01-02"))
		case !k.Expires.IsZero() && k.Expires.Sub(now) < expiryWarning:
			s.warn("recipient %q: subkey %s expires on %s", r.Label, k.KeyID, k.Expires.Format("2006-01-02"))
		}
		subkeys = append(subkeys, r.Subkey)
	}
	return subkeys, nil
}

// AddRecipient adds a key from the user's keyring as another way to open
// the vault and saves.
func (s *Store) AddRecipient(ctx context.Context, sess *Session, key string) (vault.Recipient, error) {
	r, err := s.resolveRecipient(ctx, key)
	if err != nil {
		return vault.Recipient{}, err
	}
	for _, have := range sess.Vault.Recipients {
		if have.Subkey == r.Subkey {
			return vault.Recipient{}, fmt.Errorf("subkey %s is already a recipient (%s)", r.Subkey, have.Label)
		}
	}
	sess.Vault.Recipients = append(sess.Vault.Recipients, r)
	if err := s.Save(ctx, sess); err != nil {
		sess.Vault.Recipients = sess.Vault.Recipients[:len(sess.Vault.Recipients)-1]
		return vault.Recipient{}, err
	}
	return r, nil
}

// RecipientKey returns the pinned subkey of r as bks's keyring sees it.
func (s *Store) RecipientKey(ctx context.Context, r vault.Recipient) (gpg.Key, error) {
	return s.BKS.Key(ctx, r.Subkey)
}

// device is this Mac's state.
type device struct {
	Pin     string   `json:"unlock_secret_sha256"`
	TouchID *touchID `json:"touch_id,omitempty"`
}

// touchID is U sealed to this Mac's Secure Enclave; useless elsewhere.
type touchID struct {
	Key      string    `json:"se_key"`        // Secure Enclave key blob (base64)
	Sealed   string    `json:"sealed_secret"` // U sealed to that key (base64)
	Enrolled time.Time `json:"enrolled"`
}

// Sealer keeps the unlock secret behind Touch ID (bks-mac).
type Sealer interface {
	Enroll(ctx context.Context, secret []byte) (key, sealed string, err error)
	Unseal(ctx context.Context, key, sealed string) ([]byte, error)
}

// ErrNoTouchID means Touch ID is not enrolled on this Mac.
var ErrNoTouchID = errors.New("this Mac has no Touch ID enrolment: run bks touchid enroll")

// TouchIDEnrolled reports whether this Mac can unlock with Touch ID.
func (s *Store) TouchIDEnrolled() bool {
	d, err := s.loadDevice()
	return err == nil && d.TouchID != nil
}

// EnrollTouchID seals the open vault's unlock secret with a new Secure
// Enclave key. The vault must already be pinned on this Mac.
func (s *Store) EnrollTouchID(ctx context.Context, sess *Session, sealer Sealer) error {
	d, err := s.loadDevice()
	if err != nil {
		return err
	}
	if d.Pin != sess.Vault.Pin() {
		return ErrNotTrusted
	}
	key, sealed, err := sealer.Enroll(ctx, sess.Vault.UnlockSecret)
	if err != nil {
		return err
	}
	d.TouchID = &touchID{Key: key, Sealed: sealed, Enrolled: s.Now().UTC()}
	return s.saveDevice(d)
}

// RemoveTouchID forgets this Mac's Touch ID enrolment.
func (s *Store) RemoveTouchID() error {
	d, err := s.loadDevice()
	if err != nil {
		return err
	}
	d.TouchID = nil
	return s.saveDevice(d)
}

// UnlockTouchID opens the vault through door 2 with the secret Touch ID
// releases. A vault whose secret changed (forged, or rotated) fails the
// pin check or the decryption.
func (s *Store) UnlockTouchID(ctx context.Context, sealer Sealer) (*Session, error) {
	d, err := s.loadDevice()
	if err != nil {
		return nil, err
	}
	if d.TouchID == nil {
		return nil, ErrNoTouchID
	}
	u, err := sealer.Unseal(ctx, d.TouchID.Key, d.TouchID.Sealed)
	if err != nil {
		return nil, err
	}
	return s.UnlockWithSecret(ctx, u)
}

func (s *Store) devicePath() string { return filepath.Join(s.StateDir, "device.json") }

func (s *Store) loadDevice() (device, error) {
	var d device
	b, err := os.ReadFile(s.devicePath())
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	return d, json.Unmarshal(b, &d)
}

func (s *Store) saveDevice(d device) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.devicePath(), b)
}

// lock serialises saves by bks processes on this Mac. The lock file lives
// in the state dir, never next to a synced vault.
func (s *Store) lock() (func(), error) {
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.StateDir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func writeTemp(dir, base string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Chmod(0o600); err == nil {
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			return name, nil
		}
	} else {
		f.Close()
	}
	os.Remove(name)
	return "", err
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := writeTemp(filepath.Dir(path), filepath.Base(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
