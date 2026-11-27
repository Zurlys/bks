package gpg_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/gpg"
	"github.com/Zurlys/bks/internal/gpgtest"
)

func TestSecretKeysAndCandidates(t *testing.T) {
	gpgtest.Isolate(t)
	home, other := gpgtest.Home(t), gpgtest.Home(t)
	mine := gpgtest.NewKey(t, home, "mine@test.invalid", "")
	theirs := gpgtest.NewKey(t, other, "theirs@test.invalid", "")
	gpgtest.CopyPublic(t, other, home, theirs.Primary) // public only: not a candidate
	g := gpg.GPG{Home: home}

	keys, err := g.SecretKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := gpg.EncryptionCandidates(keys, time.Now())
	if len(c) != 1 || c[0].Primary.Fingerprint != mine.Primary || c[0].Encrypt.Fingerprint != mine.Subkey {
		t.Fatalf("candidates = %+v", c)
	}
	if c[0].Encrypt.AlgoName() != "cv25519" || c[0].Encrypt.Token != "+" || !strings.Contains(c[0].Primary.UID, "mine@") {
		t.Fatalf("details: %+v", c[0])
	}
}

// A stub subkey (secret elsewhere) must never be chosen, even when newer.
func TestCandidatesSkipStubs(t *testing.T) {
	listing := strings.Join([]string{
		"sec:u:4096:1:1111222233334444:1513123456:::u:::scESC:::+:::23::0:",
		"fpr:::::::::9999888877776666555544441111222233334444:",
		"uid:u::::1513123456::H::Me <me@test.invalid>::::::::::0:",
		"ssb:u:3072:1:8888999900001111:1725462502::::::e:::+:::23:",
		"fpr:::::::::DDDDDDDDDDDDDDDDDDDDDDDD8888999900001111:",
		"ssb:u:4096:1:4444555566667777:1790000000::::::e:::#:::23:",
		"fpr:::::::::EEEEEEEEEEEEEEEEEEEEEEEE4444555566667777:",
		"sec:u:4096:1:7777888899990000:1780000000:1790000000::u:::scESC:::+:::23::0:",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAA7777888899990000:",
		"ssb:u:4096:1:2222333344445555:1780000000:1790000000:::::e:::+:::23:",
		"fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBB2222333344445555:",
		"",
	}, "\n")
	keys, err := gpg.ParseKeys([]byte(listing))
	if err != nil {
		t.Fatal(err)
	}
	c := gpg.EncryptionCandidates(keys, time.Unix(1_800_000_000, 0))
	if len(c) != 1 || c[0].Encrypt.KeyID != "8888999900001111" || c[0].Encrypt.AlgoName() != "rsa3072" {
		t.Fatalf("want only the primary key via its 8888… subkey (stub and expired key skipped), got %+v", c)
	}
}

func TestGenerateAndExportKey(t *testing.T) {
	gpgtest.Isolate(t)
	home := gpgtest.Home(t)
	gpgtest.UsePinentry(t, home, "wizard-pass-123")
	g := gpg.GPG{Home: home}

	k, err := g.GenerateKey(ctx, "Wizard Test <wiz@test.invalid>", "never")
	if err != nil {
		t.Fatal(err)
	}
	if k.UID != "Wizard Test <wiz@test.invalid>" || k.AlgoName() != "ed25519" {
		t.Fatalf("key = %+v", k)
	}
	keys, _ := g.SecretKeys(ctx)
	c := gpg.EncryptionCandidates(keys, time.Now())
	if len(c) != 1 || c[0].Encrypt.AlgoName() != "cv25519" {
		t.Fatalf("no cv25519 encryption subkey: %+v", c)
	}
	// protected by the passphrase pinentry supplied (P), never clear (C)
	out, _ := exec.Command("gpg-connect-agent", "--homedir", home, "KEYINFO "+c[0].Encrypt.Keygrip, "/bye").Output()
	if f := strings.Fields(string(out)); len(f) < 8 || f[7] != "P" {
		t.Fatalf("new key not passphrase-protected: %s", out)
	}
	dir, err := g.Homedir(ctx)
	if err != nil || dir != home {
		t.Fatalf("Homedir = %q, %v; want %q", dir, err, home)
	}
	if _, err := os.Stat(filepath.Join(home, "openpgp-revocs.d", k.Fingerprint+".rev")); err != nil {
		t.Fatalf("no revocation certificate: %v", err)
	}

	path := filepath.Join(home, "export.asc")
	if err := g.ExportSecretKey(ctx, k.Fingerprint, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	st, _ := os.Stat(path)
	if !strings.Contains(string(b), "PRIVATE KEY BLOCK") || st.Mode().Perm() != 0o600 {
		t.Fatalf("export: mode %v, %d bytes", st.Mode().Perm(), len(b))
	}
	if err := g.ExportSecretKey(ctx, k.Fingerprint, path); err == nil {
		t.Fatal("export overwrote an existing file")
	}

	for _, bad := range []string{"", "-oops", "a:b", "x\ny"} {
		if _, err := g.GenerateKey(ctx, bad, "never"); err == nil {
			t.Errorf("GenerateKey accepted uid %q", bad)
		}
	}
	for exp, ok := range map[string]bool{"never": true, "2y": true, "18m": true, "90": true, "0": false, "2x": false, "": false, "-1y": false} {
		if gpg.ValidExpiry(exp) != ok {
			t.Errorf("ValidExpiry(%q) != %v", exp, ok)
		}
	}
}
