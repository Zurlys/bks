package vaults

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testEnv is a throwaway home; nothing here can reach the real one.
func testEnv(t *testing.T) Env {
	t.Helper()
	home := t.TempDir()
	return Env{Home: home, Config: filepath.Join(home, ".config", "bks", "vaults.json")}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEmpty(t *testing.T) {
	e := testEnv(t)
	c, err := Load(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Vaults) != 0 {
		t.Fatalf("vaults = %v", c.Vaults)
	}
	if _, err := os.Stat(e.Config); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an empty config must not be written")
	}
	if _, err := c.Resolve(e, "", ""); !errors.Is(err, ErrNone) {
		t.Fatalf("resolve = %v, want ErrNone", err)
	}
}

func TestLoadAdoptsLegacyVault(t *testing.T) {
	e := testEnv(t)
	touch(t, e.LegacyVault())
	c, err := Load(e)
	if err != nil {
		t.Fatal(err)
	}
	want := Vault{Name: "personal", Path: e.LegacyVault(), State: e.LegacyState()}
	if len(c.Vaults) != 1 || c.Vaults[0] != want || c.Default != "personal" {
		t.Fatalf("config = %+v", c)
	}
	// saved: loading again reads the file, the same answer
	c2, err := Load(e)
	if err != nil || len(c2.Vaults) != 1 || c2.Vaults[0] != want {
		t.Fatalf("reloaded = %+v, %v", c2, err)
	}
	fi, err := os.Stat(e.Config)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %v, %v", fi.Mode(), err)
	}
	// a legacy file showing up later is not adopted once a config exists
	c2.Vaults = nil
	c2.Default = ""
	if err := c2.Save(e); err != nil {
		t.Fatal(err)
	}
	c3, _ := Load(e)
	if len(c3.Vaults) != 0 {
		t.Fatalf("legacy vault adopted again: %+v", c3)
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"personal", "work", "a", "team-2", "0123456789abcdef"} {
		if err := ValidName(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Work", "my vault", "v.1", "-x", "x (1)", "0123456789abcdefg", "ž", "a/b"} {
		if err := ValidName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAddRemoveRename(t *testing.T) {
	e := testEnv(t)
	c := &Config{}
	p := Vault{Name: "personal", Path: e.ICloudPath("personal"), State: e.StateFor("personal")}
	w := Vault{Name: "work", Path: e.LocalPath("work"), State: e.StateFor("work")}
	if err := c.Add(p); err != nil {
		t.Fatal(err)
	}
	if c.Default != "personal" {
		t.Fatalf("first vault is not the default: %q", c.Default)
	}
	if err := c.Add(w); err != nil {
		t.Fatal(err)
	}
	if c.Default != "personal" {
		t.Fatalf("default changed to %q", c.Default)
	}
	for _, dup := range []Vault{
		{Name: "work", Path: "/x/vault.gpg", State: "/s/x"},     // same name
		{Name: "other", Path: w.Path, State: "/s/y"},            // same file
		{Name: "other", Path: "/z/vault.gpg", State: w.State},   // same state
		{Name: "Bad Name", Path: "/q/vault.gpg", State: "/s/q"}, // bad name
	} {
		if err := c.Add(dup); err == nil {
			t.Errorf("added %+v", dup)
		}
	}
	if err := c.Rename("work", "business"); err != nil {
		t.Fatal(err)
	}
	if v := c.Find("business"); v == nil || v.State != w.State || v.Path != w.Path {
		t.Fatalf("rename lost the vault's file or state: %+v", v)
	}
	if err := c.Rename("business", "personal"); err == nil {
		t.Error("renamed onto an existing name")
	}
	c.LastUsed = "personal"
	if err := c.Remove("personal"); err != nil {
		t.Fatal(err)
	}
	if c.Default != "business" || c.LastUsed != "" {
		t.Fatalf("after removing the default: default %q, last used %q", c.Default, c.LastUsed)
	}
	if err := c.Remove("nope"); err == nil {
		t.Error("removed a vault that does not exist")
	}
}

func TestResolve(t *testing.T) {
	e := testEnv(t)
	c := &Config{}
	p := Vault{Name: "personal", Path: e.ICloudPath("personal"), State: e.StateFor("personal")}
	w := Vault{Name: "work", Path: e.LocalPath("work"), State: e.StateFor("work")}
	_ = c.Add(p)

	if v, err := c.Resolve(e, "", ""); err != nil || v != p {
		t.Fatalf("only vault: %+v, %v", v, err)
	}
	_ = c.Add(w)
	if _, err := c.Resolve(e, "", ""); !errors.Is(err, ErrChoose) {
		t.Fatalf("two vaults, no choice: %v", err)
	}
	if v, err := c.Resolve(e, "work", ""); err != nil || v != w {
		t.Fatalf("by name: %+v, %v", v, err)
	}
	if _, err := c.Resolve(e, "nope", ""); err == nil {
		t.Fatal("unknown name resolved")
	}
	// a listed vault by path keeps its name and state
	if v, err := c.Resolve(e, w.Path, ""); err != nil || v != w {
		t.Fatalf("listed path: %+v, %v", v, err)
	}
	// "~/…" expands
	if v, err := c.Resolve(e, "~/.local/share/bks/work/vault.gpg", ""); err != nil || v != w {
		t.Fatalf("~ path: %+v, %v", v, err)
	}
	// an unlisted path gets its own state directory, never another vault's
	other := filepath.Join(e.Home, "elsewhere", "vault.gpg")
	v, err := c.Resolve(e, other, "")
	if err != nil || v.Name != "" || v.Path != other {
		t.Fatalf("unlisted path: %+v, %v", v, err)
	}
	if v.State == p.State || v.State == w.State || v.State == e.LegacyState() || !strings.HasPrefix(v.State, e.LegacyState()) {
		t.Fatalf("unlisted path state %s", v.State)
	}
	if v2, _ := c.Resolve(e, other, ""); v2.State != v.State {
		t.Fatal("the derived state directory is not stable")
	}
	// the legacy path, unlisted, keeps the legacy state
	if v, _ := c.Resolve(e, e.LegacyVault(), ""); v.State != e.LegacyState() {
		t.Fatalf("legacy path state %s", v.State)
	}
	// BKS_STATE_DIR only together with a path
	if v, err := c.Resolve(e, other, "/tmp/st"); err != nil || v.State != "/tmp/st" {
		t.Fatalf("state override with a path: %+v, %v", v, err)
	}
	for _, sel := range []string{"", "work"} {
		if _, err := c.Resolve(e, sel, "/tmp/st"); err == nil {
			t.Fatalf("state override accepted without a path (sel %q)", sel)
		}
	}
}

func TestIsPath(t *testing.T) {
	for s, want := range map[string]bool{
		"work": false, "personal-2": false,
		"~/v.gpg": true, "/a/b": true, "vault.gpg": true, "./x": true,
	} {
		if IsPath(s) != want {
			t.Errorf("IsPath(%q) = %v", s, !want)
		}
	}
}

func TestICloudAndDisplay(t *testing.T) {
	e := testEnv(t)
	if e.ICloudAvailable() {
		t.Fatal("iCloud Drive available in an empty home")
	}
	if err := os.MkdirAll(e.ICloudDrive(), 0o700); err != nil {
		t.Fatal(err)
	}
	if !e.ICloudAvailable() {
		t.Fatal("iCloud Drive not detected")
	}
	if got := e.Display(e.ICloudPath("work")); got != "iCloud Drive/bks/work/vault.gpg" {
		t.Errorf("display iCloud = %q", got)
	}
	if got := e.Display(e.LocalPath("work")); got != "~/.local/share/bks/work/vault.gpg" {
		t.Errorf("display local = %q", got)
	}
	if got := e.Display("/Volumes/usb/vault.gpg"); got != "/Volumes/usb/vault.gpg" {
		t.Errorf("display other = %q", got)
	}
	// state paths stay short enough for gpg-agent sockets (104 bytes on macOS)
	long := filepath.Join("/Users/a-rather-long-user-name", ".local", "state", "bks", "v", "0123456789abcdef", "gnupg", "S.gpg-agent.browser")
	if len(long) > 104 {
		t.Errorf("state socket path %d bytes", len(long))
	}
}

func TestSaveIsPrivate(t *testing.T) {
	e := testEnv(t)
	c := &Config{}
	_ = c.Add(Vault{Name: "personal", Path: e.LocalPath("personal"), State: e.StateFor("personal")})
	if err := c.Save(e); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Dir(e.Config))
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("config dir mode %v", fi.Mode().Perm())
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.Config), ".vaults.*.tmp"))
	if len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}
