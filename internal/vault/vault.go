// Package vault is the decrypted vault: entries, recipients, settings and the
// unlock secret U. It knows nothing about files or gpg.
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/Zurlys/bks/internal/otp"
)

// Format is the vault JSON format version.
const Format = 1

const secretLen = 32

// Vault is the plaintext inside vault.gpg.
type Vault struct {
	Format int `json:"format"`
	// UnlockSecret is U: the random secret behind door 2 (Touch ID). It is
	// stored here so that after a GPG unlock bks can rewrite door 2.
	UnlockSecret     []byte      `json:"unlock_secret"`
	PrevUnlockSecret []byte      `json:"prev_unlock_secret,omitempty"`
	Recipients       []Recipient `json:"recipients"`
	Settings         Settings    `json:"settings"`
	SettingsUpdated  time.Time   `json:"settings_updated"`
	Entries          []Entry     `json:"entries"`
	Tombstones       []Tombstone `json:"tombstones,omitempty"`
}

// Recipient is a GPG encryption subkey that opens door 1.
type Recipient struct {
	Label  string `json:"label"`
	Subkey string `json:"subkey"` // full fingerprint of the exact encryption subkey
	PubKey string `json:"pubkey"` // armored public key, imported into bks's own keyring
}

// Settings are synced with the vault.
type Settings struct {
	IdleLock       string `json:"idle_lock"`
	MaxUnlocked    string `json:"max_unlocked"`
	ClipboardClear string `json:"clipboard_clear"`
}

// DefaultSettings are used for new vaults.
var DefaultSettings = Settings{IdleLock: "5m", MaxUnlocked: "8h", ClipboardClear: "30s"}

// Entry is one login.
type Entry struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Username string           `json:"username,omitempty"`
	Password string           `json:"password,omitempty"`
	OTP      string           `json:"otp,omitempty"` // otpauth:// URI
	URLs     []string         `json:"urls,omitempty"`
	Tags     []string         `json:"tags,omitempty"`
	Notes    string           `json:"notes,omitempty"`
	Fields   []Field          `json:"fields,omitempty"`
	History  []PasswordChange `json:"history,omitempty"`
	Created  time.Time        `json:"created"`
	Updated  time.Time        `json:"updated"`
	// Source identifies where an imported entry came from, e.g.
	// "1password:<item uuid>", so a re-import does not duplicate it.
	Source string `json:"source,omitempty"`
}

// Field is a custom field.
type Field struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Secret bool   `json:"secret,omitempty"`
}

// PasswordChange is a previous password, valid until Until.
type PasswordChange struct {
	Password string    `json:"password"`
	Until    time.Time `json:"until"`
}

// Tombstone records a deletion so that sync merges don't resurrect it.
type Tombstone struct {
	ID      string    `json:"id"`
	Deleted time.Time `json:"deleted"`
}

// New creates an empty vault with a fresh unlock secret.
func New(recipients []Recipient, now time.Time) (*Vault, error) {
	u := make([]byte, secretLen)
	if _, err := rand.Read(u); err != nil {
		return nil, err
	}
	v := &Vault{
		Format:          Format,
		UnlockSecret:    u,
		Recipients:      recipients,
		Settings:        DefaultSettings,
		SettingsUpdated: now.UTC(),
		Entries:         []Entry{},
	}
	return v, v.Validate()
}

// Passphrase is the text form of U handed to gpg. gpg reads --passphrase-fd
// as one line, so raw bytes (which may contain '\n' or NUL) would be
// silently truncated; hex never is.
func (v *Vault) Passphrase() string { return PassphraseFor(v.UnlockSecret) }

// PassphraseFor returns the gpg passphrase for an unlock secret.
func PassphraseFor(u []byte) string { return hex.EncodeToString(u) }

// Pin is the per-Mac fingerprint of U: hex(sha256(U)).
func (v *Vault) Pin() string { return PinFor(v.UnlockSecret) }

// PinFor returns the pin for an unlock secret.
func PinFor(u []byte) string {
	sum := sha256.Sum256(u)
	return hex.EncodeToString(sum[:])
}

// Validate checks the invariants bks relies on.
func (v *Vault) Validate() error {
	if v.Format != Format {
		return fmt.Errorf("unsupported vault format %d", v.Format)
	}
	if len(v.UnlockSecret) != secretLen {
		return errors.New("vault has no valid unlock secret")
	}
	if len(v.Recipients) == 0 {
		return errors.New("vault has no recipients")
	}
	seen := map[string]bool{}
	for _, r := range v.Recipients {
		if len(r.Subkey) != 40 || strings.ToUpper(r.Subkey) != r.Subkey || r.PubKey == "" {
			return fmt.Errorf("invalid recipient %q", r.Label)
		}
		if seen[r.Subkey] {
			return fmt.Errorf("duplicate recipient %s", r.Subkey)
		}
		seen[r.Subkey] = true
	}
	for _, d := range []string{v.Settings.IdleLock, v.Settings.MaxUnlocked, v.Settings.ClipboardClear} {
		if _, err := time.ParseDuration(d); err != nil {
			return fmt.Errorf("invalid setting: %w", err)
		}
	}
	ids := map[string]bool{}
	for _, e := range v.Entries {
		if e.ID == "" || ids[e.ID] {
			return fmt.Errorf("missing or duplicate entry id %q", e.ID)
		}
		ids[e.ID] = true
		if strings.TrimSpace(e.Title) == "" {
			return fmt.Errorf("entry %s has no title", e.ID)
		}
		if e.OTP != "" {
			if err := checkOTP(e.OTP); err != nil {
				return fmt.Errorf("entry %q: %w", e.Title, err)
			}
		}
	}
	return nil
}

func checkOTP(s string) error {
	if _, err := otp.Parse(s); err != nil {
		return fmt.Errorf("otp: %w", err)
	}
	return nil
}

// Parse decodes and validates vault JSON.
func Parse(b []byte) (*Vault, error) {
	var v Vault
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("vault is not valid JSON: %w", err)
	}
	if v.Entries == nil {
		v.Entries = []Entry{}
	}
	return &v, v.Validate()
}

// Marshal encodes the vault after validating it.
func (v *Vault) Marshal() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	// No HTML escaping: the JSON stays readable after a plain `gpg -d`.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Add stores a new entry and returns it with ID and timestamps set.
func (v *Vault) Add(e Entry, now time.Time) (Entry, error) {
	e.ID = NewID(now)
	e.Created, e.Updated = now.UTC(), now.UTC()
	if strings.TrimSpace(e.Title) == "" {
		return Entry{}, errors.New("title is required")
	}
	if e.OTP != "" {
		if err := checkOTP(e.OTP); err != nil {
			return Entry{}, err
		}
	}
	v.Entries = append(v.Entries, e)
	return e, nil
}

// historyLen is how many previous passwords an entry keeps.
const historyLen = 5

// Get returns the entry with id, or nil.
func (v *Vault) Get(id string) *Entry {
	for i := range v.Entries {
		if v.Entries[i].ID == id {
			return &v.Entries[i]
		}
	}
	return nil
}

// Update replaces the entry with id by e, keeping its ID and creation time.
// A changed password moves the old one into the history (newest first,
// at most historyLen).
func (v *Vault) Update(id string, e Entry, now time.Time) (Entry, error) {
	old := v.Get(id)
	if old == nil {
		return Entry{}, fmt.Errorf("no entry %s", id)
	}
	if strings.TrimSpace(e.Title) == "" {
		return Entry{}, errors.New("title is required")
	}
	if e.OTP != "" {
		if err := checkOTP(e.OTP); err != nil {
			return Entry{}, err
		}
	}
	e.ID, e.Created, e.Updated = old.ID, old.Created, now.UTC()
	e.History = old.History
	if old.Password != "" && e.Password != old.Password {
		e.History = append([]PasswordChange{{Password: old.Password, Until: now.UTC()}}, e.History...)
		if len(e.History) > historyLen {
			e.History = e.History[:historyLen]
		}
	}
	*old = e
	return e, nil
}

// Delete removes the entry with id and records a tombstone, so a sync merge
// will not bring it back.
func (v *Vault) Delete(id string, now time.Time) error {
	for i := range v.Entries {
		if v.Entries[i].ID == id {
			v.Entries = append(v.Entries[:i:i], v.Entries[i+1:]...)
			v.Tombstones = append(v.Tombstones, Tombstone{ID: id, Deleted: now.UTC()})
			return nil
		}
	}
	return fmt.Errorf("no entry %s", id)
}

// Field returns a named value of the entry: password (default), username,
// url, notes, title, otp, or a custom field name.
func (e *Entry) Field(name string) (string, bool) {
	switch strings.ToLower(name) {
	case "", "password", "pass", "p":
		return e.Password, true
	case "username", "user", "u":
		return e.Username, true
	case "url":
		if len(e.URLs) == 0 {
			return "", false
		}
		return e.URLs[0], true
	case "notes":
		return e.Notes, true
	case "title":
		return e.Title, true
	case "otp":
		return e.OTP, e.OTP != ""
	}
	for _, f := range e.Fields {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns a ULID: 48-bit millisecond time + 80 random bits, Crockford
// base32, so IDs sort by creation time.
func NewID(now time.Time) string {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	n := new(big.Int).SetBytes(b[:])
	out := make([]byte, 26)
	mod := new(big.Int)
	for i := 25; i >= 0; i-- {
		n.DivMod(n, big.NewInt(32), mod)
		out[i] = crockford[mod.Int64()]
	}
	return string(out)
}
