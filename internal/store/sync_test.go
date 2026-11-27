package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/gpgtest"
	"github.com/Zurlys/bks/internal/vault"
)

// secondMac is another Mac: its own state dir, same vault file and key. It
// trusts the vault on first use.
func secondMac(t *testing.T, e env) *Store {
	t.Helper()
	b := newStore(t, e.dir, "s2", e.userHome)
	b.Confirm = func(string) bool { return true }
	return b
}

func titlesOf(v *vault.Vault) string {
	var s []string
	for _, e := range v.Entries {
		s = append(s, e.Title)
	}
	return strings.Join(s, ",")
}

func addEntry(t *testing.T, v *vault.Vault, title string) {
	t.Helper()
	if _, err := v.Add(vault.Entry{Title: title}, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestSaveMergesWhenAnotherMacSaved(t *testing.T) {
	e := newEnv(t)
	e.init(t)
	b := secondMac(t, e)
	onA, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	onB, err := b.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addEntry(t, onA.Vault, "from A")
	if err := e.s.Save(ctx, onA); err != nil {
		t.Fatal(err)
	}
	addEntry(t, onB.Vault, "from B")
	if err := b.Save(ctx, onB); err != nil {
		t.Fatalf("B's save after A's: %v", err)
	}
	if !onB.Merged || titlesOf(onB.Vault) != "from B,from A" {
		t.Fatalf("B's session after merge: %s (merged %v)", titlesOf(onB.Vault), onB.Merged)
	}
	again, err := e.s.UnlockGPG(ctx)
	if err != nil || len(again.Vault.Entries) != 2 {
		t.Fatalf("A sees %v, %v", again, err)
	}
}

// An older genuine file arriving via sync cannot roll back what this Mac
// saved: the last good copy is merged back in and saved.
func TestRollbackIsUndone(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	old, _ := os.ReadFile(e.s.VaultPath)
	add(t, e.s, sess, "newer")
	if err := os.WriteFile(e.s.VaultPath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	var warned []string
	e.s.Warn = func(m string) { warned = append(warned, m) }
	got, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if titlesOf(got.Vault) != "newer" || !got.Merged {
		t.Fatalf("after rollback: %q", titlesOf(got.Vault))
	}
	if now, _ := os.ReadFile(e.s.VaultPath); bytes.Equal(now, old) {
		t.Fatal("restored state was not saved back to the vault file")
	}
	if len(warned) == 0 || !strings.Contains(warned[0], "lacked changes") {
		t.Fatalf("no warning: %v", warned)
	}
}

func TestConflictCopyMergedAndRemoved(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	add(t, e.s, sess, "base")
	base, _ := os.ReadFile(e.s.VaultPath)
	// another Mac's save ended up as a conflict copy next to the vault
	b := secondMac(t, e)
	onB, err := b.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	add(t, b, onB, "only in the conflict copy")
	conflict := filepath.Join(e.dir, "vault 2.gpg")
	if err := os.Rename(e.s.VaultPath, conflict); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(e.s.VaultPath, base, 0o600)
	// and a stranger's file that happens to match the pattern
	stranger := filepath.Join(e.dir, "vault.sync-conflict-20261127-120000-ABC.gpg")
	os.WriteFile(stranger, []byte("not a vault"), 0o600)

	got, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if titlesOf(got.Vault) != "base,only in the conflict copy" {
		t.Fatalf("merged: %q", titlesOf(got.Vault))
	}
	if _, err := os.Stat(conflict); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("merged conflict copy was not removed after saving")
	}
	if _, err := os.Stat(stranger); err != nil {
		t.Fatal("a file that is not this vault was removed")
	}
}

func TestReadOnlyWhenVaultUnreadable(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	add(t, e.s, sess, "kept on this Mac")
	os.Remove(e.s.VaultPath)
	got, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ReadOnly || titlesOf(got.Vault) != "kept on this Mac" {
		t.Fatalf("read-only fallback: %+v", got)
	}
	if err := e.s.Save(ctx, got); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("save of read-only copy: %v", err)
	}
}

func TestRotationAcceptedOnOtherMac(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	b := secondMac(t, e)
	if _, err := b.UnlockGPG(ctx); err != nil { // B pins the original secret
		t.Fatal(err)
	}
	if err := b.EnrollTouchID(ctx, mustUnlock(t, b), &fakeSealer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Rotate(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.UnlockGPG(ctx); err != nil {
		t.Fatalf("rotating Mac cannot unlock: %v", err)
	}
	asked := ""
	b.Confirm = func(q string) bool { asked = q; return false }
	if _, err := b.UnlockGPG(ctx); !errors.Is(err, ErrNotTrusted) || !strings.Contains(asked, "rotated") {
		t.Fatalf("declined rotation: %v (asked %q)", err, asked)
	}
	b.Confirm = func(string) bool { return true }
	if _, err := b.UnlockGPG(ctx); err != nil {
		t.Fatal(err)
	}
	if b.TouchIDEnrolled() {
		t.Fatal("Touch ID for the old secret still enrolled")
	}
	b.Confirm = nil
	if _, err := b.UnlockGPG(ctx); err != nil {
		t.Fatal("asked again after accepting")
	}
}

// A vault whose prev secret is not the pinned one is still a forgery.
func TestFakeRotationRefused(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	forged, _ := vault.New(sess.Vault.Recipients, time.Now())
	forged.PrevUnlockSecret, _ = vault.NewSecret()
	pt, _ := forged.Marshal()
	ct, _ := e.s.BKS.Encrypt(ctx, pt, []string{e.key.Subkey}, forged.Passphrase())
	os.WriteFile(e.s.VaultPath, ct, 0o600)
	e.s.Confirm = func(string) bool { t.Error("asked about a fake rotation"); return true }
	if _, err := e.s.UnlockGPG(ctx); !errors.Is(err, ErrForged) {
		t.Fatalf("got %v, want ErrForged", err)
	}
}

func TestRemoveRecipientRotatesAndStaysRemoved(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	backupHome := gpgtest.Home(t)
	backup := gpgtest.NewKey(t, backupHome, "backup@test.invalid", "")
	gpgtest.CopyPublic(t, backupHome, e.userHome, backup.Primary)
	if _, err := e.s.AddRecipient(ctx, sess, backup.Primary); err != nil {
		t.Fatal(err)
	}
	b := secondMac(t, e)
	if _, err := b.UnlockGPG(ctx); err != nil { // B's last good copy has both recipients
		t.Fatal(err)
	}
	oldSecret := append([]byte(nil), sess.Vault.UnlockSecret...)
	if _, _, err := e.s.RemoveRecipient(ctx, sess, "backup@test.invalid"); err == nil {
		t.Fatal("removing by partial label should not match") // label is "test <backup@test.invalid>"
	}
	removed, _, err := e.s.RemoveRecipient(ctx, sess, backup.Subkey[24:])
	if err != nil || removed.Subkey != backup.Subkey {
		t.Fatalf("remove: %+v %v", removed, err)
	}
	if bytes.Equal(sess.Vault.UnlockSecret, oldSecret) || !bytes.Equal(sess.Vault.PrevUnlockSecret, oldSecret) {
		t.Fatal("removing a recipient did not rotate the unlock secret")
	}
	// the backup key no longer opens the new file
	if _, err := (gpgHome{backupHome}).decrypt(e.s.VaultPath); err == nil {
		t.Fatal("removed key still decrypts the vault")
	}
	// B accepts the rotation; its old last good copy must not re-add the key
	onB, err := b.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(onB.Vault.Recipients) != 1 {
		t.Fatalf("removed recipient came back through B's old copy: %d recipients", len(onB.Vault.Recipients))
	}
	if _, _, err := e.s.RemoveRecipient(ctx, mustUnlock(t, e.s), e.key.Subkey); err == nil {
		t.Fatal("removed the only recipient")
	}
}

func TestSaveAfterRotationElsewhereAsksToUnlockAgain(t *testing.T) {
	e := newEnv(t)
	sess := e.init(t)
	b := secondMac(t, e)
	onB, err := b.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Rotate(ctx, sess); err != nil {
		t.Fatal(err)
	}
	addEntry(t, onB.Vault, "late")
	if err := b.Save(ctx, onB); !errors.Is(err, ErrChanged) {
		t.Fatalf("got %v, want ErrChanged", err)
	}
}

func mustUnlock(t *testing.T, s *Store) *Session {
	t.Helper()
	sess, err := s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

type gpgHome struct{ dir string }

func (g gpgHome) decrypt(path string) ([]byte, error) {
	return execGPG(g.dir, "--decrypt", path)
}
