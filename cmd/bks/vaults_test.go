package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/gpg"
	"github.com/Zurlys/bks/internal/gpgtest"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/store"
	"github.com/Zurlys/bks/internal/vault"
	"github.com/Zurlys/bks/internal/vaults"
)

// fakeHome points HOME and the config at a throwaway directory, so nothing
// here can reach the real vaults, and makes Time Machine answer "none".
func fakeHome(t *testing.T, icloud bool) vaults.Env {
	t.Helper()
	// short: state directories hold gpg-agent sockets (104-byte paths)
	home, err := os.MkdirTemp("/tmp", "bh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("BKS_CONFIG", "")
	t.Setenv("BKS_VAULT", "")
	t.Setenv("BKS_STATE_DIR", "")
	e, err := vaults.DefaultEnv()
	if err != nil || e.Home != home {
		t.Fatalf("env %+v, %v", e, err)
	}
	if icloud {
		if err := os.MkdirAll(e.ICloudDrive(), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := timeMachine
	timeMachine = func(string) macos.Backup { return macos.BackupNone }
	t.Cleanup(func() { timeMachine = old })
	return e
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keys feeds pickVault/remindICloud one key per call.
func keys(s string) func() byte {
	i := 0
	return func() byte {
		if i >= len(s) {
			return 0
		}
		i++
		return s[i-1]
	}
}

func testUI(answers ...string) (*ui, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &ui{in: bufio.NewReader(strings.NewReader(strings.Join(answers, "\n") + "\n")), out: out}, out
}

func TestTakeVaultFlag(t *testing.T) {
	for _, c := range []struct {
		in   []string
		rest []string
		sel  string
	}{
		{nil, nil, ""},
		{[]string{"get", "x"}, []string{"get", "x"}, ""},
		{[]string{"-v", "work"}, []string{}, "work"},
		{[]string{"-v", "work", "get", "x"}, []string{"get", "x"}, "work"},
		{[]string{"get", "-v", "work", "x"}, []string{"get", "x"}, "work"},
		{[]string{"--vault=work", "ls"}, []string{"ls"}, "work"},
		{[]string{"ls", "--vault", "~/v.gpg"}, []string{"ls"}, "~/v.gpg"},
		{[]string{"get", "-f", "user", "-v", "work"}, []string{"get", "-f", "user", "-v", "work"}, ""}, // left for the flag error
	} {
		rest, sel, err := takeVaultFlag(c.in)
		if err != nil || sel != c.sel || strings.Join(rest, " ") != strings.Join(c.rest, " ") {
			t.Errorf("%q → %q %q %v", c.in, rest, sel, err)
		}
	}
	if _, _, err := takeVaultFlag([]string{"get", "-v"}); err == nil {
		t.Error("-v without a value accepted")
	}
	// later -v gets a clear message, not "flag provided but not defined"
	fs := flags("get")
	fs.SetOutput(&bytes.Buffer{})
	err := fs.Parse([]string{"-v", "work"})
	if err == nil || !strings.Contains(err.Error(), "right after the command") {
		t.Errorf("misplaced -v: %v", err)
	}
}

func TestWithEnv(t *testing.T) {
	got := withEnv([]string{"A=1", "BKS_VAULT=work", "B=2", "BKS_VAULTX=keep"}, "BKS_VAULT", "/p/vault.gpg")
	want := "A=1 B=2 BKS_VAULTX=keep BKS_VAULT=/p/vault.gpg"
	if strings.Join(got, " ") != want {
		t.Fatalf("%q", got)
	}
}

func twoVaults(t *testing.T, e vaults.Env) *vaults.Config {
	t.Helper()
	cfg := &vaults.Config{}
	for _, n := range []string{"personal", "work"} {
		v := vaults.Vault{Name: n, Path: e.LocalPath(n), State: e.StateFor(n)}
		writeFile(t, v.Path, "vault "+n)
		if err := cfg.Add(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.Save(e); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPickVault(t *testing.T) {
	e := fakeHome(t, false)
	cfg := twoVaults(t, e)
	var out bytes.Buffer
	if v, err := pickVault(&out, keys("\r"), e, cfg); err != nil || v.Name != "personal" {
		t.Fatalf("enter with no last used: %+v, %v", v, err)
	}
	cfg.LastUsed = "work"
	if v, _ := pickVault(&out, keys("\r"), e, cfg); v.Name != "work" {
		t.Fatalf("enter must open the last used: %+v", v)
	}
	if v, _ := pickVault(&out, keys("x91"), e, cfg); v.Name != "personal" {
		t.Fatalf("1 after ignored keys: %+v", v)
	}
	if _, err := pickVault(&out, keys("q"), e, cfg); !errors.Is(err, errQuit) {
		t.Fatalf("q: %v", err)
	}
	if !strings.Contains(out.String(), "~/.local/share/bks/work/vault.gpg") {
		t.Fatalf("picker output:\n%s", out.String())
	}
}

func TestRemindICloud(t *testing.T) {
	e := fakeHome(t, true)
	cfg := twoVaults(t, e)
	var out bytes.Buffer
	v := *cfg.Find("personal")

	// enter: not now, nothing changes
	got, err := remindICloud(&out, keys("\r"), e, cfg, v)
	if err != nil || got != v {
		t.Fatalf("enter: %+v, %v", got, err)
	}
	if !strings.Contains(out.String(), "bks sees no Time Machine backup") {
		t.Fatalf("no backup note:\n%s", out.String())
	}

	// n: never again for this vault, saved
	if _, err := remindICloud(&out, keys("n"), e, cfg, v); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := vaults.Load(e)
	if !reloaded.Find("personal").NoICloudReminder || reloaded.Find("work").NoICloudReminder {
		t.Fatalf("reminder flags: %+v", reloaded.Vaults)
	}
	out.Reset()
	if _, err := remindICloud(&out, keys("m"), e, reloaded, *reloaded.Find("personal")); err != nil || out.Len() != 0 {
		t.Fatalf("reminded again: %q, %v", out.String(), err)
	}

	// m: moved into iCloud Drive, old copy renamed aside
	w := *cfg.Find("work")
	moved, err := remindICloud(&out, keys("m"), e, cfg, w)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Path != e.ICloudPath("work") || moved.State != w.State {
		t.Fatalf("moved: %+v", moved)
	}
	if b, _ := os.ReadFile(moved.Path); string(b) != "vault work" {
		t.Fatalf("content at the new place: %q", b)
	}
	if _, err := os.Stat(w.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the old copy is still at the old path")
	}
	aside, _ := filepath.Glob(w.Path + ".moved-*")
	if len(aside) != 1 {
		t.Fatalf("old copy aside: %v", aside)
	}
	reloaded, _ = vaults.Load(e)
	if reloaded.Find("work").Path != e.ICloudPath("work") {
		t.Fatal("config not updated")
	}

	// in iCloud already, or no iCloud Drive: no question at all
	out.Reset()
	if _, err := remindICloud(&out, keys("m"), e, reloaded, *reloaded.Find("work")); err != nil || out.Len() != 0 {
		t.Fatalf("asked about a vault already in iCloud: %q", out.String())
	}
	e2 := fakeHome(t, false)
	cfg2 := twoVaults(t, e2)
	out.Reset()
	if _, err := remindICloud(&out, keys("m"), e2, cfg2, *cfg2.Find("work")); err != nil || out.Len() != 0 {
		t.Fatalf("asked without iCloud Drive: %q", out.String())
	}
}

func TestChooseLocation(t *testing.T) {
	e := fakeHome(t, true)
	cfg := &vaults.Config{}

	// first vault: name defaults to personal, place to iCloud Drive
	u, out := testUI("", "", "")
	v, existing, err := chooseLocation(u, e, cfg, vaults.Vault{}, "")
	if err != nil || existing {
		t.Fatalf("%v %v\n%s", existing, err, out)
	}
	if v.Name != "personal" || v.Path != e.ICloudPath("personal") || v.State != e.StateFor("personal") {
		t.Fatalf("first vault: %+v", v)
	}
	if !strings.Contains(out.String(), "If this vault already exists on another Mac") {
		t.Errorf("no other-Mac hint:\n%s", out)
	}

	// second vault: a name is required and must be valid and new
	_ = cfg.Add(v)
	u, out = testUI("", "Work", "personal", "work", "2")
	v, _, err = chooseLocation(u, e, cfg, vaults.Vault{}, "")
	if err != nil || v.Name != "work" || v.Path != e.LocalPath("work") {
		t.Fatalf("second vault: %+v, %v\n%s", v, err, out)
	}
	if !strings.Contains(out.String(), "bks sees no Time Machine backup") {
		t.Errorf("no backup warning for a local vault:\n%s", out)
	}

	// another folder; a directory gets vault.gpg appended
	other := filepath.Join(e.Home, "Vaults")
	_ = os.MkdirAll(other, 0o700)
	u, _ = testUI("3", other)
	v, _, err = chooseLocation(u, e, cfg, vaults.Vault{Name: "team"}, "")
	if err != nil || v.Path != filepath.Join(other, "vault.gpg") {
		t.Fatalf("other folder: %+v, %v", v, err)
	}

	// a file already there (synced from another Mac): add it
	writeFile(t, e.ICloudPath("shared"), "theirs")
	u, _ = testUI("1", "")
	v, existing, err = chooseLocation(u, e, cfg, vaults.Vault{Name: "shared"}, "")
	if err != nil || !existing || v.Path != e.ICloudPath("shared") {
		t.Fatalf("existing: %+v %v %v", v, existing, err)
	}

	// the folder exists in iCloud but no file yet: ask, default no
	_ = os.MkdirAll(filepath.Dir(e.ICloudPath("late")), 0o700)
	u, out = testUI("1", "")
	if _, _, err = chooseLocation(u, e, cfg, vaults.Vault{Name: "late"}, ""); err == nil {
		t.Fatalf("created next to a vault still syncing\n%s", out)
	}
	u, _ = testUI("1", "y")
	if v, existing, err = chooseLocation(u, e, cfg, vaults.Vault{Name: "late"}, ""); err != nil || existing {
		t.Fatalf("confirmed: %+v %v %v", v, existing, err)
	}

	// a stale state directory with an earlier vault's pin is refused
	writeFile(t, filepath.Join(e.StateFor("old"), "device.json"), "{}")
	u, _ = testUI("2")
	if _, _, err = chooseLocation(u, e, cfg, vaults.Vault{Name: "old"}, ""); err == nil {
		t.Fatal("reused a state directory holding another vault's pin")
	}
}

func TestCmdVault(t *testing.T) {
	e := fakeHome(t, true)
	run := func(args ...string) error { return cmdVault(ctx, args) }

	writeFile(t, filepath.Join(e.Home, "x", "vault.gpg"), "x")
	if err := run("add", "work", "~/x"); err != nil {
		t.Fatal(err)
	}
	if err := run("add", "work2", "~/nothing-here"); err == nil {
		t.Fatal("added a missing file")
	}
	if err := run("add", "Bad", "~/x/vault.gpg"); err == nil {
		t.Fatal("added a bad name")
	}
	cfg, _ := vaults.Load(e)
	if v := cfg.Find("work"); v == nil || v.Path != filepath.Join(e.Home, "x", "vault.gpg") || cfg.Default != "work" {
		t.Fatalf("after add: %+v", cfg)
	}
	if err := run("rename", "work", "business"); err != nil {
		t.Fatal(err)
	}
	if err := run("move", "business"); err != nil {
		t.Fatal(err)
	}
	cfg, _ = vaults.Load(e)
	if cfg.Find("business").Path != e.ICloudPath("business") || cfg.Default != "business" {
		t.Fatalf("after rename+move: %+v", cfg)
	}
	if err := run("move", "business"); err == nil {
		t.Fatal("moved onto itself")
	}
	if err := run("default", "nope"); err == nil {
		t.Fatal("default to a missing vault")
	}
	if err := run("remove", "business"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.ICloudPath("business")); err != nil {
		t.Fatal("remove deleted the vault file")
	}
	cfg, _ = vaults.Load(e)
	if len(cfg.Vaults) != 0 {
		t.Fatalf("after remove: %+v", cfg)
	}
	if err := run("frobnicate"); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestOpenStoreChoice(t *testing.T) {
	e := fakeHome(t, false)
	if _, err := openStore(""); !errors.Is(err, vaults.ErrNone) {
		t.Fatalf("no vaults: %v", err)
	}
	cfg := twoVaults(t, e)
	s, err := openStore("")
	if err != nil || s.VaultPath != e.LocalPath("personal") || s.StateDir != e.StateFor("personal") {
		t.Fatalf("default: %+v, %v", s, err)
	}
	if s, err = openStore("work"); err != nil || s.StateDir != e.StateFor("work") {
		t.Fatalf("-v work: %v", err)
	}
	cfg.Default = ""
	_ = cfg.Save(e)
	var ee exitError
	if _, err := openStore(""); !errors.As(err, &ee) || ee.code != 2 {
		t.Fatalf("several, no default: %v", err)
	}
}

func TestLegacyVaultAdopted(t *testing.T) {
	e := fakeHome(t, false)
	writeFile(t, e.LegacyVault(), "old")
	s, err := openStore("")
	if err != nil || s.VaultPath != e.LegacyVault() || s.StateDir != e.LegacyState() {
		t.Fatalf("legacy: %+v, %v", s, err)
	}
	cfg, _ := vaults.Load(e)
	if cfg.Default != "personal" || cfg.Find("personal") == nil {
		t.Fatalf("config after adoption: %+v", cfg)
	}
}

// A vault synced from another Mac is added, not replaced: init finds the
// file, unlocks it once with the GPG key, pins it and lists it.
func TestInitAddsExistingVault(t *testing.T) {
	e := fakeHome(t, true)
	gpgtest.Isolate(t)
	t.Setenv("BKS_HELPER", "/nonexistent/bks-mac")
	userHome := gpgtest.Home(t)
	key := gpgtest.NewKey(t, userHome, "me@test.invalid", "")

	// "Another Mac" creates the vault in iCloud Drive with its own state.
	theirs := store.New(e.ICloudPath("personal"), filepath.Join(e.Home, "other-mac"), gpg.GPG{Home: userHome})
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", theirs.BKS.Home, "--kill", "all").Run() })
	sess, err := theirs.Init(ctx, []string{key.Primary})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Vault.Add(vault.Entry{Title: "synced", Password: "pw"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := theirs.Save(ctx, sess); err != nil {
		t.Fatal(err)
	}

	// This Mac: init with the defaults finds it and adds it.
	cfg := &vaults.Config{}
	u, out := testUI("", "", "")
	v, existing, err := chooseLocation(u, e, cfg, vaults.Vault{}, "")
	if err != nil || !existing || v.Path != e.ICloudPath("personal") || v.State != e.StateFor("personal") {
		t.Fatalf("location: %+v %v %v\n%s", v, existing, err, out)
	}
	s := store.New(v.Path, v.State, gpg.GPG{Home: userHome})
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", s.BKS.Home, "--kill", "all").Run() })
	trusted := false
	s.Confirm = func(q string) bool { trusted = strings.Contains(q, "First unlock"); return trusted }
	if err := addExisting(ctx, u, e, cfg, v, s); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !trusted {
		t.Fatal("no first-use trust question")
	}
	reloaded, _ := vaults.Load(e)
	if got := reloaded.Find("personal"); got == nil || *got != v || reloaded.Default != "personal" {
		t.Fatalf("config: %+v", reloaded)
	}
	// pinned: the next unlock asks nothing and sees the synced entry
	s.Confirm = func(q string) bool { t.Errorf("asked again: %s", q); return false }
	again, err := s.UnlockGPG(ctx)
	if err != nil || len(again.Vault.Entries) != 1 || again.Vault.Entries[0].Title != "synced" {
		t.Fatalf("second unlock: %v", err)
	}
}
