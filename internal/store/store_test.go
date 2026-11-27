package store

import (
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
	"github.com/Zurlys/bks/internal/vault"
)

var ctx = context.Background()

type env struct {
	s        *Store
	key      gpgtest.Key
	userHome string
	dir      string
}

// newEnv builds a store on throwaway homes only. GNUPGHOME points at an
// empty temp home, so nothing can fall through to the real ~/.gnupg.
func newEnv(t *testing.T) env {
	t.Helper()
	gpgtest.Isolate(t)
	userHome := gpgtest.Home(t)
	key := gpgtest.NewKey(t, userHome, "me@test.invalid", "")
	dir := gpgtest.Home(t) // short temp dir for vault + state
	s := newStore(t, dir, "st", userHome)
	return env{s: s, key: key, userHome: userHome, dir: dir}
}

func newStore(t *testing.T, dir, state, userHome string) *Store {
	t.Helper()
	s := New(filepath.Join(dir, "vault.gpg"), filepath.Join(dir, state), gpg.GPG{Home: userHome})
	if n := len(filepath.Join(s.BKS.Home, "S.gpg-agent.browser")); n > maxSocketPath {
		t.Fatalf("socket path too long: %d", n)
	}
	t.Cleanup(func() { _ = exec.Command("gpgconf", "--homedir", s.BKS.Home, "--kill", "all").Run() })
	s.Confirm = func(q string) bool { t.Errorf("unexpected trust question: %s", q); return false }
	s.Warn = func(m string) { t.Logf("warn: %s", m) }
	return s
}

func (e env) init(t *testing.T) *Session {
	t.Helper()
	sess, err := e.s.Init(ctx, []string{e.key.Primary})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func add(t *testing.T, s *Store, sess *Session, title string) {
	t.Helper()
	if _, err := sess.Vault.Add(vault.Entry{Title: title, Username: "u", Password: "pw-" + title}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, sess); err != nil {
		t.Fatal(err)
	}
}

func TestInitUnlockSave(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	if got := sess.Vault.Recipients[0].Subkey; got != e.key.Subkey {
		t.Fatalf("pinned %s, want encryption subkey %s", got, e.key.Subkey)
	}
	add(t, e.s, sess, "GitLab")

	for name, unlock := range map[string]func() (*Session, error){
		"door 1 (GPG)":           func() (*Session, error) { return e.s.UnlockGPG(ctx) },
		"door 2 (unlock secret)": func() (*Session, error) { return e.s.UnlockWithSecret(ctx, sess.Vault.UnlockSecret) },
	} {
		got, err := unlock()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got.Vault.Entries) != 1 || got.Vault.Entries[0].Password != "pw-GitLab" {
			t.Fatalf("%s: entries %+v", name, got.Vault.Entries)
		}
	}
	if _, err := os.Stat(e.s.VaultPath + ".bak"); err != nil {
		t.Fatalf("no .bak after second save: %v", err)
	}
	// plain gpg can always read the vault (disaster recovery)
	out, err := exec.Command("gpg", "--homedir", e.userHome, "--batch", "--quiet", "--decrypt", e.s.VaultPath).Output()
	if err != nil || !bytes.Contains(out, []byte("pw-GitLab")) {
		t.Fatalf("plain gpg -d failed: %v", err)
	}
}

func TestBKSKeyringHasNoSecretKeys(t *testing.T) {
	e := newEnv(t)
	e.init(t)
	out, err := exec.Command("gpg", "--homedir", e.s.BKS.Home, "--batch", "--with-colons", "--list-secret-keys").Output()
	if err != nil && len(out) > 0 || strings.Contains(string(out), "sec:") || strings.Contains(string(out), "ssb:") {
		t.Fatalf("bks keyring must hold public keys only:\n%s", out)
	}
}

func TestInitRefusesExistingVault(t *testing.T) {
	e := newEnv(t)
	e.init(t)
	if _, err := e.s.Init(ctx, []string{e.key.Primary}); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

// Anyone who can write to the synced folder can build a vault that the GPG
// key opens. Its unlock secret differs from the pinned one, so bks refuses.
func TestForgedVaultRefused(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	forged, err := vault.New(sess.Vault.Recipients, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pt, _ := forged.Marshal()
	ct, err := e.s.BKS.Encrypt(ctx, pt, []string{e.key.Subkey}, forged.Passphrase())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.s.VaultPath, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.UnlockGPG(ctx); !errors.Is(err, ErrForged) {
		t.Fatalf("door 1: got %v, want ErrForged", err)
	}
	if _, err := e.s.UnlockWithSecret(ctx, forged.UnlockSecret); !errors.Is(err, ErrForged) {
		t.Fatalf("door 2: got %v, want ErrForged", err)
	}
}

func TestTrustOnFirstUse(t *testing.T) {
	e := newEnv(t)
	e.init(t)
	other := newStore(t, e.dir, "s2", e.userHome) // same vault, another "Mac"
	asked := 0
	other.Confirm = func(q string) bool { asked++; return false }
	if _, err := other.UnlockGPG(ctx); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("declined: got %v, want ErrNotTrusted", err)
	}
	other.Confirm = func(q string) bool {
		asked++
		if !strings.Contains(q, "entries:    0") || !strings.Contains(q, "me@test.invalid") {
			t.Errorf("question lacks details: %s", q)
		}
		return true
	}
	if _, err := other.UnlockGPG(ctx); err != nil {
		t.Fatal(err)
	}
	other.Confirm = nil // pinned now: no more questions
	if _, err := other.UnlockGPG(ctx); err != nil {
		t.Fatal(err)
	}
	if asked != 2 {
		t.Fatalf("asked %d times, want 2", asked)
	}
}

func TestVerifyBeforeReplace(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, e env, sess *Session, tmp string){
		"corrupted file": func(t *testing.T, e env, sess *Session, tmp string) {
			if err := os.WriteFile(tmp, []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		// opens with U but lost the GPG recipient packet: would lock out
		// every GPG-only unlock, and door 2 alone would not notice
		"no GPG recipient": func(t *testing.T, e env, sess *Session, tmp string) {
			pt, err := sess.Vault.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("gpg", "--homedir", e.s.BKS.Home, "--batch", "--quiet", "--yes",
				"--pinentry-mode", "loopback", "--passphrase-fd", "3", "--no-symkey-cache",
				"--s2k-cipher-algo", "AES256", "--output", tmp, "--symmetric")
			r, w, _ := os.Pipe()
			cmd.ExtraFiles = []*os.File{r}
			cmd.Stdin = bytes.NewReader(pt)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			r.Close()
			w.WriteString(sess.Vault.Passphrase())
			w.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("building symmetric-only file: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			sess := e.init(t)
			before, _ := os.ReadFile(e.s.VaultPath)
			e.s.afterWrite = func(tmp string) { tamper(t, e, sess, tmp) }
			if _, err := sess.Vault.Add(vault.Entry{Title: "x"}, time.Now()); err != nil {
				t.Fatal(err)
			}
			err := e.s.Save(ctx, sess)
			if err == nil || !strings.Contains(err.Error(), "verification") {
				t.Fatalf("got %v, want verification failure", err)
			}
			t.Logf("refused: %v", err)
			after, _ := os.ReadFile(e.s.VaultPath)
			if !bytes.Equal(before, after) {
				t.Fatal("vault changed despite failed verification")
			}
			if left, _ := filepath.Glob(filepath.Join(e.dir, ".vault.gpg.*.tmp")); len(left) != 0 {
				t.Fatalf("temp files left behind: %v", left)
			}
		})
	}
}

func TestAddRecipient(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	backupHome := gpgtest.Home(t)
	backup := gpgtest.NewKey(t, backupHome, "backup@test.invalid", "")
	gpgtest.CopyPublic(t, backupHome, e.userHome, backup.Primary) // public only, like an offline key

	r, err := e.s.AddRecipient(ctx, sess, backup.Primary)
	if err != nil {
		t.Fatal(err)
	}
	if r.Subkey != backup.Subkey {
		t.Fatalf("pinned %s, want %s", r.Subkey, backup.Subkey)
	}
	ct, _ := os.ReadFile(e.s.VaultPath)
	ids, _, err := e.s.BKS.Packets(ctx, ct)
	if err != nil || len(ids) != 2 {
		t.Fatalf("packets %v %v", ids, err)
	}
	// the backup key alone opens the vault
	out, err := exec.Command("gpg", "--homedir", backupHome, "--batch", "--quiet", "--decrypt", e.s.VaultPath).Output()
	if err != nil || !bytes.Contains(out, []byte(backup.Subkey)) {
		t.Fatalf("backup key cannot decrypt: %v", err)
	}
	if _, err := e.s.AddRecipient(ctx, sess, backup.Primary); err == nil {
		t.Fatal("duplicate recipient accepted")
	}
	// still opens through door 1 and door 2
	if _, err := e.s.UnlockGPG(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.UnlockWithSecret(ctx, sess.Vault.UnlockSecret); err != nil {
		t.Fatal(err)
	}
}

func TestNoVault(t *testing.T) {
	e := newEnv(t)
	if _, err := e.s.UnlockGPG(ctx); !errors.Is(err, ErrNoVault) {
		t.Fatalf("got %v, want ErrNoVault", err)
	}
}

// fakeSealer stands in for bks-mac: "sealing" keeps the secret in memory.
type fakeSealer struct {
	secret []byte
	err    error
}

func (f *fakeSealer) Enroll(_ context.Context, secret []byte) (string, string, error) {
	f.secret = append([]byte(nil), secret...)
	return "key-blob", "sealed-blob", nil
}

func (f *fakeSealer) Unseal(_ context.Context, key, sealed string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if key != "key-blob" || sealed != "sealed-blob" {
		return nil, errors.New("wrong blobs")
	}
	return f.secret, nil
}

func TestTouchIDEnrolUnlockRemove(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	add(t, e.s, sess, "GitLab")
	f := &fakeSealer{}
	if e.s.TouchIDEnrolled() {
		t.Fatal("enrolled before enrolment")
	}
	if _, err := e.s.UnlockTouchID(ctx, f); !errors.Is(err, ErrNoTouchID) {
		t.Fatalf("got %v, want ErrNoTouchID", err)
	}
	if err := e.s.EnrollTouchID(ctx, sess, f); err != nil {
		t.Fatal(err)
	}
	if !e.s.TouchIDEnrolled() {
		t.Fatal("not enrolled")
	}
	got, err := e.s.UnlockTouchID(ctx, f)
	if err != nil || len(got.Vault.Entries) != 1 {
		t.Fatalf("unlock: %v", err)
	}
	f.err = errors.New("cancelled")
	if _, err := e.s.UnlockTouchID(ctx, f); err == nil {
		t.Fatal("sealer error ignored")
	}
	if err := e.s.RemoveTouchID(); err != nil || e.s.TouchIDEnrolled() {
		t.Fatalf("remove: %v", err)
	}
	// the pin survives removal
	if _, err := e.s.UnlockGPG(ctx); err != nil {
		t.Fatal(err)
	}
}

// Touch ID releases the secret it sealed; if the vault file is replaced
// by one with another secret, the unlock fails instead of opening it.
func TestTouchIDRefusesSwappedVault(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	f := &fakeSealer{}
	if err := e.s.EnrollTouchID(ctx, sess, f); err != nil {
		t.Fatal(err)
	}
	forged, _ := vault.New(sess.Vault.Recipients, time.Now())
	pt, _ := forged.Marshal()
	ct, err := e.s.BKS.Encrypt(ctx, pt, []string{e.key.Subkey}, forged.Passphrase())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(e.s.VaultPath, ct, 0o600)
	if _, err := e.s.UnlockTouchID(ctx, f); err == nil {
		t.Fatal("Touch ID opened a vault with a different unlock secret")
	}
	f.secret = forged.UnlockSecret // even if the sealed secret matched the forgery, the pin refuses it
	if _, err := e.s.UnlockTouchID(ctx, f); !errors.Is(err, ErrForged) {
		t.Fatalf("got %v, want ErrForged", err)
	}
}

func TestEnrollRequiresPinnedVault(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	other := newStore(t, e.dir, "s2", e.userHome) // a Mac that never trusted this vault
	if err := other.EnrollTouchID(ctx, sess, &fakeSealer{}); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("got %v, want ErrNotTrusted", err)
	}
}

func execGPG(home string, args ...string) ([]byte, error) {
	return exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--quiet"}, args...)...).Output()
}
