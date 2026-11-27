package main

import (
	"bufio"
	"bytes"
	"context"
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
)

var ctx = context.Background()

type initEnv struct {
	s        *store.Store
	userHome string
	dir      string
	out      *bytes.Buffer
}

// newInitEnv builds a store on throwaway homes; GNUPGHOME points at an empty
// temp home so nothing can reach the real keyring.
func newInitEnv(t *testing.T) initEnv {
	t.Helper()
	gpgtest.Isolate(t)
	t.Setenv("BKS_HELPER", "/nonexistent/bks-mac") // never offer Touch ID unless a test asks
	userHome, dir := gpgtest.Home(t), gpgtest.Home(t)
	s := store.New(filepath.Join(dir, "vault.gpg"), filepath.Join(dir, "st"), gpg.GPG{Home: userHome})
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", s.BKS.Home, "--kill", "all").Run() })
	s.Warn = func(m string) { t.Logf("warn: %s", m) }
	return initEnv{s: s, userHome: userHome, dir: dir, out: &bytes.Buffer{}}
}

func (e initEnv) run(answers ...string) error {
	u := &ui{in: bufio.NewReader(strings.NewReader(strings.Join(answers, "\n") + "\n")), out: e.out}
	return initInteractive(ctx, e.s, u)
}

func (e initEnv) recipients(t *testing.T) []string {
	t.Helper()
	sess, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var subkeys []string
	for _, r := range sess.Vault.Recipients {
		subkeys = append(subkeys, r.Subkey)
	}
	return subkeys
}

func TestInitChoosesExistingKey(t *testing.T) {
	e := newInitEnv(t)
	mine := gpgtest.NewKey(t, e.userHome, "mine@test.invalid", "")
	otherHome := gpgtest.Home(t)
	theirs := gpgtest.NewKey(t, otherHome, "theirs@test.invalid", "")
	gpgtest.CopyPublic(t, otherHome, e.userHome, theirs.Primary)

	// choose 1, skip the export, accept "create the vault"
	if err := e.run("1", "", ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	out := e.out.String()
	if strings.Contains(out, "theirs@test.invalid") {
		t.Error("listed a key whose secret is not on this machine")
	}
	for _, want := range []string{mine.Primary, "cv25519 subkey", "Keep these OFFLINE", "--export-secret-keys " + mine.Primary,
		filepath.Join(e.userHome, "openpgp-revocs.d", mine.Primary+".rev"), "not even you", "Skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if got := e.recipients(t); len(got) != 1 || got[0] != mine.Subkey {
		t.Fatalf("recipients %v, want [%s]", got, mine.Subkey)
	}
}

func TestInitRepromptsOnBadChoice(t *testing.T) {
	e := newInitEnv(t)
	gpgtest.NewKey(t, e.userHome, "mine@test.invalid", "")
	if err := e.run("7", "x", "1", "", ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if strings.Count(e.out.String(), "Please answer 1-1 or n.") != 2 {
		t.Fatalf("expected two re-prompts:\n%s", e.out)
	}
}

func TestInitWizardWhenNoKeys(t *testing.T) {
	e := newInitEnv(t)
	gpgtest.UsePinentry(t, e.userHome, "wizard-pass-123")
	export := filepath.Join(e.dir, "bks-key.asc")

	// create? yes · name · email · expiry default · export path · create vault
	if err := e.run("", "Wizard Person", "wp@test.invalid", "", export, ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	out := e.out.String()
	for _, want := range []string{"No GPG key on this Mac can encrypt", "master password", "Created key Wizard Person <wp@test.invalid>", "Wrote " + export} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if b, err := os.ReadFile(export); err != nil || !bytes.Contains(b, []byte("PRIVATE KEY BLOCK")) {
		t.Fatalf("export missing: %v", err)
	}
	keys, _ := e.s.User.SecretKeys(ctx)
	if c := gpg.EncryptionCandidates(keys, time.Now()); len(c) != 1 || e.recipients(t)[0] != c[0].Encrypt.Fingerprint {
		t.Fatalf("vault not encrypted to the new key's subkey")
	}
}

func TestInitWizardDeclined(t *testing.T) {
	e := newInitEnv(t)
	err := e.run("n")
	if err == nil || !strings.Contains(err.Error(), "init cancelled") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(e.s.VaultPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vault created despite cancel")
	}
}

func TestInitNewKeyFromMenu(t *testing.T) {
	e := newInitEnv(t)
	old := gpgtest.NewKey(t, e.userHome, "old@test.invalid", "")
	gpgtest.UsePinentry(t, e.userHome, "wizard-pass-123")
	// n = new key · name · no email · bad expiry, then 2y · skip export · create
	if err := e.run("n", "Fresh Key", "", "soon", "2y", "", ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !strings.Contains(e.out.String(), "Please answer never, or a number") {
		t.Error("bad expiry not re-asked")
	}
	if got := e.recipients(t); len(got) != 1 || got[0] == old.Subkey {
		t.Fatalf("recipients %v: want the new key, not %s", got, old.Subkey)
	}
}

func TestInitRefusesExistingVault(t *testing.T) {
	e := newInitEnv(t)
	gpgtest.NewKey(t, e.userHome, "mine@test.invalid", "")
	if err := e.run("1", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.run("1", "", ""); !errors.Is(err, store.ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

// With the real helper, init offers Touch ID and enrols it. Enrolment only
// creates a Secure Enclave key and seals: no Touch ID prompt.
func TestInitOffersTouchID(t *testing.T) {
	helper, _ := filepath.Abs("../../bin/bks-mac")
	if _, err := os.Stat(helper); err != nil {
		t.Skip("bin/bks-mac not built (run make)")
	}
	secret := make([]byte, 32)
	if _, _, err := (macos.Helper{Path: helper}).Enroll(ctx, secret); errors.Is(err, macos.ErrTouchIDUnavailable) {
		t.Skipf("no Secure Enclave here: %v", err)
	}
	e := newInitEnv(t)
	t.Setenv("BKS_HELPER", helper)
	gpgtest.NewKey(t, e.userHome, "mine@test.invalid", "")
	// key 1 · skip export · create vault · enable Touch ID
	if err := e.run("1", "", "", ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out)
	}
	if !e.s.TouchIDEnrolled() || !strings.Contains(e.out.String(), "Touch ID enrolled") {
		t.Fatalf("not enrolled:\n%s", e.out)
	}
}
