// Package vaults remembers the vaults this Mac knows, in a small config file
// (~/.config/bks/vaults.json), and decides which one a command opens.
//
// Each vault has its own per-Mac state directory (pin, last good copy,
// Touch ID enrolment, keyring, lock): sharing one would make each vault's
// anti-forgery pin reject the other.
package vaults

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Vault is one entry of the config.
type Vault struct {
	Name  string `json:"name"`
	Path  string `json:"path"`  // the vault file
	State string `json:"state"` // this Mac's state directory for it
	// NoICloudReminder: "don't remind me again" about moving it to iCloud Drive.
	NoICloudReminder bool `json:"no_icloud_reminder,omitempty"`
}

// Config is the list of vaults on this Mac.
type Config struct {
	Default  string  `json:"default,omitempty"`   // for commands run without -v
	LastUsed string  `json:"last_used,omitempty"` // preselected in the picker
	Vaults   []Vault `json:"vaults"`
}

// Env says where things live; tests point it at throwaway directories.
type Env struct {
	Home   string // the user's home directory
	Config string // the config file
}

// DefaultEnv is the real home, with $BKS_CONFIG overriding the config file.
func DefaultEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, err
	}
	cfg := os.Getenv("BKS_CONFIG")
	if cfg == "" {
		cfg = filepath.Join(home, ".config", "bks", "vaults.json")
	}
	return Env{Home: home, Config: cfg}, nil
}

// LegacyVault and LegacyState are where bks kept its only vault before it
// knew several; that vault keeps its state directory.
func (e Env) LegacyVault() string {
	return filepath.Join(e.Home, ".local", "share", "bks", "vault.gpg")
}
func (e Env) LegacyState() string { return filepath.Join(e.Home, ".local", "state", "bks") }

// StateFor is the state directory of a new vault. Names are short, so the
// gpg-agent socket paths below it stay within the OS limit.
func (e Env) StateFor(name string) string { return filepath.Join(e.LegacyState(), "v", name) }

// adHocState is the state directory of a vault file opened by path that
// the config does not list: derived from the path, never shared.
func (e Env) adHocState(path string) string {
	if path == e.LegacyVault() {
		return e.LegacyState()
	}
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(e.LegacyState(), "p", hex.EncodeToString(sum[:6]))
}

// ICloudDrive is the iCloud Drive folder.
func (e Env) ICloudDrive() string {
	return filepath.Join(e.Home, "Library", "Mobile Documents", "com~apple~CloudDocs")
}

// ICloudAvailable reports whether iCloud Drive is on for this user.
func (e Env) ICloudAvailable() bool {
	fi, err := os.Stat(e.ICloudDrive())
	return err == nil && fi.IsDir()
}

// ICloudPath and LocalPath are the two places init proposes for a vault.
func (e Env) ICloudPath(name string) string {
	return filepath.Join(e.ICloudDrive(), "bks", name, "vault.gpg")
}
func (e Env) LocalPath(name string) string {
	return filepath.Join(e.Home, ".local", "share", "bks", name, "vault.gpg")
}

// Display shortens a path for people: "iCloud Drive/…" or "~/…".
func (e Env) Display(path string) string {
	if rest, ok := within(path, e.ICloudDrive()); ok {
		return filepath.Join("iCloud Drive", rest)
	}
	if rest, ok := within(path, e.Home); ok {
		return filepath.Join("~", rest)
	}
	return path
}

// Expand turns "~/x" into an absolute path; other paths become absolute.
func (e Env) Expand(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = filepath.Join(e.Home, strings.TrimPrefix(p, "~"))
	}
	return filepath.Abs(p)
}

func within(path, dir string) (string, bool) {
	if path == dir {
		return ".", true
	}
	rest, ok := strings.CutPrefix(path, dir+string(os.PathSeparator))
	return rest, ok
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,15}$`)

// ValidName accepts 1–16 lowercase letters, digits and hyphens. Such a name
// never contains the space, dot or brackets of a sync tool's conflict-copy
// name, and keeps state paths short.
func ValidName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("vault name %q: use 1–16 lowercase letters, digits or hyphens, starting with a letter or digit", name)
	}
	return nil
}

// Load reads the config. Without one, a vault at the legacy path becomes
// the vault "personal" (keeping its state directory), and that is saved.
func Load(e Env) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(e.Config)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Config, err)
		}
		return c, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	if _, err := os.Stat(e.LegacyVault()); err == nil {
		c.Vaults = []Vault{{Name: "personal", Path: e.LegacyVault(), State: e.LegacyState()}}
		c.Default = "personal"
		if err := c.Save(e); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Save writes the config atomically, private to the user.
func (c *Config) Save(e Env) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(e.Config)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".vaults.*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, e.Config)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// Find returns the vault with this name, or nil.
func (c *Config) Find(name string) *Vault {
	for i := range c.Vaults {
		if c.Vaults[i].Name == name {
			return &c.Vaults[i]
		}
	}
	return nil
}

// FindPath returns the vault whose file is path (absolute), or nil.
func (c *Config) FindPath(path string) *Vault {
	for i := range c.Vaults {
		if c.Vaults[i].Path == path {
			return &c.Vaults[i]
		}
	}
	return nil
}

// Add registers a vault; the first one becomes the default.
func (c *Config) Add(v Vault) error {
	if err := ValidName(v.Name); err != nil {
		return err
	}
	if c.Find(v.Name) != nil {
		return fmt.Errorf("a vault named %q already exists", v.Name)
	}
	if o := c.FindPath(v.Path); o != nil {
		return fmt.Errorf("%s is already the vault %q", v.Path, o.Name)
	}
	for _, o := range c.Vaults {
		if o.State == v.State {
			return fmt.Errorf("state directory %s is already used by the vault %q", v.State, o.Name)
		}
	}
	c.Vaults = append(c.Vaults, v)
	if c.Default == "" {
		c.Default = v.Name
	}
	return nil
}

// Remove forgets a vault (its file and state stay where they are).
func (c *Config) Remove(name string) error {
	for i, v := range c.Vaults {
		if v.Name == name {
			c.Vaults = append(c.Vaults[:i], c.Vaults[i+1:]...)
			if c.Default == name {
				c.Default = ""
				if len(c.Vaults) == 1 {
					c.Default = c.Vaults[0].Name
				}
			}
			if c.LastUsed == name {
				c.LastUsed = ""
			}
			return nil
		}
	}
	return fmt.Errorf("no vault named %q", name)
}

// Rename changes a vault's name; its file and state directory stay.
func (c *Config) Rename(old, name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	v := c.Find(old)
	if v == nil {
		return fmt.Errorf("no vault named %q", old)
	}
	if c.Find(name) != nil {
		return fmt.Errorf("a vault named %q already exists", name)
	}
	v.Name = name
	if c.Default == old {
		c.Default = name
	}
	if c.LastUsed == old {
		c.LastUsed = name
	}
	return nil
}

var (
	// ErrNone: no vault is configured yet.
	ErrNone = errors.New("no vault yet: create one with bks init")
	// ErrChoose: several vaults and nothing says which.
	ErrChoose = errors.New("several vaults: choose one with -v <name> (bks vault list), or set a default: bks vault default <name>")
)

// IsPath tells a vault path from a vault name in -v and $BKS_VAULT.
func IsPath(s string) bool {
	return strings.ContainsRune(s, os.PathSeparator) || strings.HasPrefix(s, "~") || strings.HasSuffix(s, ".gpg")
}

// Resolve picks the vault for sel (from -v, else $BKS_VAULT): a name, or a
// path (listed or not). With neither, the only vault; with several it
// returns ErrChoose, and the caller asks (UI) or uses the default.
// stateOverride ($BKS_STATE_DIR) applies only to a vault given by path, so
// two vaults can never share a state directory through it.
func (c *Config) Resolve(e Env, sel, stateOverride string) (Vault, error) {
	if sel != "" && IsPath(sel) {
		p, err := e.Expand(sel)
		if err != nil {
			return Vault{}, err
		}
		v := Vault{Path: p, State: e.adHocState(p)}
		if known := c.FindPath(p); known != nil {
			v = *known
		}
		if stateOverride != "" {
			v.State = stateOverride
		}
		return v, nil
	}
	if stateOverride != "" {
		return Vault{}, errors.New("BKS_STATE_DIR works only with a vault given by path (BKS_VAULT=/path/to/vault.gpg)")
	}
	if sel != "" {
		if v := c.Find(sel); v != nil {
			return *v, nil
		}
		return Vault{}, fmt.Errorf("no vault named %q (bks vault list)", sel)
	}
	switch len(c.Vaults) {
	case 0:
		return Vault{}, ErrNone
	case 1:
		return c.Vaults[0], nil
	}
	return Vault{}, ErrChoose
}
