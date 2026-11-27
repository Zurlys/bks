package gpg_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/gpg"
	"github.com/Zurlys/bks/internal/gpgtest"
)

var ctx = context.Background()

// setup: user home holds key A (secret) and B's public key; the bks home holds
// only public keys, like production.
func setup(t *testing.T) (user, bks gpg.GPG, a, b gpgtest.Key) {
	gpgtest.Isolate(t)
	userHome, otherHome, bksHome := gpgtest.Home(t), gpgtest.Home(t), gpgtest.Home(t)
	a = gpgtest.NewKey(t, userHome, "a@test.invalid", "")
	b = gpgtest.NewKey(t, otherHome, "b@test.invalid", "")
	gpgtest.CopyPublic(t, otherHome, userHome, b.Primary)
	gpgtest.CopyPublic(t, userHome, bksHome, a.Primary)
	gpgtest.CopyPublic(t, otherHome, bksHome, b.Primary)
	return gpg.GPG{Home: userHome}, gpg.GPG{Home: bksHome}, a, b
}

func TestBothDoors(t *testing.T) {
	user, bks, a, b := setup(t)
	pass := randomHex(t) // same shape as production: 64 hex chars
	plain := []byte(`{"hello":"vault"}`)

	msg, err := bks.Encrypt(ctx, plain, []string{a.Subkey, b.Subkey}, pass)
	if err != nil {
		t.Fatal(err)
	}
	// door 2: passphrase, in a home without secret keys
	got, err := bks.DecryptWithPassphrase(ctx, msg, pass)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("door 2: %q, %v", got, err)
	}
	// door 1: the user's secret key
	got, err = user.Decrypt(ctx, msg)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("door 1: %q, %v", got, err)
	}
	// wrong passphrase fails
	if _, err := bks.DecryptWithPassphrase(ctx, msg, randomHex(t)); err == nil {
		t.Fatal("wrong passphrase decrypted")
	}
}

func randomHex(t *testing.T) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestPackets(t *testing.T) {
	_, bks, a, b := setup(t)
	msg, err := bks.Encrypt(ctx, []byte("x"), []string{a.Subkey, b.Subkey}, "pass")
	if err != nil {
		t.Fatal(err)
	}
	ids, sym, err := bks.Packets(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if sym != 1 {
		t.Errorf("passphrase packets = %d, want 1", sym)
	}
	want := map[string]bool{a.Subkey[24:]: true, b.Subkey[24:]: true}
	if len(ids) != 2 || !want[ids[0]] || !want[ids[1]] {
		t.Errorf("key IDs = %v, want %v", ids, want)
	}
}

func TestPassphraseMustBeOneLine(t *testing.T) {
	_, bks, a, _ := setup(t)
	for _, p := range []string{"", "abc\ndef", "abc\x00def", "abc\r"} {
		if _, err := bks.Encrypt(ctx, []byte("x"), []string{a.Subkey}, p); err == nil {
			t.Errorf("Encrypt accepted passphrase %q", p)
		}
	}
}

func TestRecipientMustBeFullFingerprint(t *testing.T) {
	_, bks, a, _ := setup(t)
	if _, err := bks.Encrypt(ctx, []byte("x"), []string{a.Subkey[24:]}, "p"); err == nil {
		t.Fatal("Encrypt accepted a short key ID")
	}
}

func TestEncryptionKeyResolvesSubkey(t *testing.T) {
	user, _, a, b := setup(t)
	for _, id := range []string{a.Primary, a.Subkey, "0x" + strings.ToLower(a.Primary[24:])} {
		k, err := user.EncryptionKey(ctx, id, time.Now())
		if err != nil || k.Fingerprint != a.Subkey || k.Keygrip == "" || !strings.Contains(k.UID, "a@test.invalid") {
			t.Errorf("EncryptionKey(%s) = %+v, %v", id, k, err)
		}
	}
	if k, err := user.EncryptionKey(ctx, b.Primary, time.Now()); err != nil || k.Fingerprint != b.Subkey {
		t.Errorf("public-only key: %+v, %v", k, err)
	}
	if _, err := user.EncryptionKey(ctx, "not a key", time.Now()); err == nil {
		t.Error("accepted garbage key ID")
	}
}

func TestExportImport(t *testing.T) {
	user, _, a, _ := setup(t)
	fresh := gpg.GPG{Home: gpgtest.Home(t)}
	pub, err := user.ExportPublic(ctx, a.Primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Import(ctx, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Key(ctx, a.Subkey); err != nil {
		t.Fatal(err)
	}
}

func TestClearPassphrase(t *testing.T) {
	gpgtest.Isolate(t)
	home := gpgtest.Home(t)
	k := gpgtest.NewKey(t, home, "p@test.invalid", "secret-pass")
	g := gpg.GPG{Home: home}
	key, err := g.Key(ctx, k.Subkey)
	if err != nil {
		t.Fatal(err)
	}
	enc := exec.Command("gpg", "--homedir", home, "--batch", "--quiet", "--trust-model", "always",
		"--encrypt", "--recipient", k.Subkey+"!")
	enc.Stdin = strings.NewReader("x")
	msg, err := enc.Output()
	if err != nil {
		t.Fatal(err)
	}
	// decrypt with the key passphrase via loopback so gpg-agent caches it
	dec := exec.Command("gpg", "--homedir", home, "--batch", "--quiet", "--pinentry-mode", "loopback",
		"--passphrase", "secret-pass", "--decrypt")
	dec.Stdin = bytes.NewReader(msg)
	if out, err := dec.CombinedOutput(); err != nil {
		t.Fatalf("decrypt: %v %s", err, out)
	}
	if !cached(t, home, key.Keygrip) {
		t.Fatal("passphrase not cached after decrypt; test is not exercising the cache")
	}
	if err := g.ClearPassphrase(ctx, key.Keygrip); err != nil {
		t.Fatal(err)
	}
	if cached(t, home, key.Keygrip) {
		t.Fatal("passphrase still cached after ClearPassphrase")
	}
}

func cached(t *testing.T, home, grip string) bool {
	out, err := exec.Command("gpg-connect-agent", "--homedir", home, "KEYINFO "+grip, "/bye").Output()
	if err != nil {
		t.Fatal(err)
	}
	// S KEYINFO <grip> <type> <serial> <idstr> <cached> ...
	f := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	return len(f) > 6 && f[6] == "1"
}

func TestParseKeysAndPick(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	listing := strings.Join([]string{
		"pub:u:4096:1:1111222233334444:1513123456:::u:::scESC::::::23::0:",
		"fpr:::::::::9999888877776666555544441111222233334444:",
		"grp:::::::::1234123412341234123412341234123412341234:",
		"uid:u::::1513123456::HASH::Test User <t@test.invalid>::::::::::0:",
		"sub:e:4096:1:5555666677778888:1513123456:1700000000:::::e::::::23:",
		"fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAA5555666677778888:",
		"grp:::::::::1111111111111111111111111111111111111111:",
		"sub:u:3072:1:6666777788889999:1725462502::::::s::::::23:",
		"fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCC6666777788889999:",
		"grp:::::::::2222222222222222222222222222222222222222:",
		"sub:u:3072:1:8888999900001111:1725462502::::::e::::::23:",
		"fpr:::::::::DDDDDDDDDDDDDDDDDDDDDDDD8888999900001111:",
		"grp:::::::::ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD:",
		"sub:u:4096:1:4444555566667777:1693526400:1819843200:::::e::::::23:",
		"fpr:::::::::EEEEEEEEEEEEEEEEEEEEEEEE4444555566667777:",
		"grp:::::::::3333333333333333333333333333333333333333:",
		"sub:r:4096:1:1234567812345678:1800000001::::::e::::::23:",
		"fpr:::::::::00000000000000000000000012345678123456781:",
		"",
	}, "\n")
	keys, err := gpg.ParseKeys([]byte(listing))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 6 || keys[3].UID != "Test User <t@test.invalid>" || keys[3].Primary != "9999888877776666555544441111222233334444" {
		t.Fatalf("parse: %+v", keys)
	}
	// newest valid encryption subkey: 89DA (2024) beats 4B57 (2023); expired 5697 and revoked one are skipped
	k, err := gpg.PickEncryptionKey(keys, "9999888877776666555544441111222233334444", now)
	if err != nil || k.KeyID != "8888999900001111" || k.Keygrip != "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD" {
		t.Fatalf("pick primary: %+v %v", k, err)
	}
	// an explicitly named subkey is used as-is
	if k, err := gpg.PickEncryptionKey(keys, "EEEEEEEEEEEEEEEEEEEEEEEE4444555566667777", now); err != nil || k.KeyID != "4444555566667777" {
		t.Fatalf("pick subkey: %+v %v", k, err)
	}
	// ...unless it is expired, revoked or cannot encrypt
	for _, id := range []string{"AAAAAAAAAAAAAAAAAAAAAAAA5555666677778888", "CCCCCCCCCCCCCCCCCCCCCCCC6666777788889999"} {
		if _, err := gpg.PickEncryptionKey(keys, id, now); !errors.Is(err, gpg.ErrNoEncryptionKey) {
			t.Errorf("pick %s: want ErrNoEncryptionKey, got %v", id, err)
		}
	}
	// after 4B57 expires (2027-09-01) it is reported expired
	if !keys[4].Expired(time.Date(2027, 9, 2, 0, 0, 0, 0, time.UTC)) || keys[4].Expired(now) {
		t.Error("expiry check wrong")
	}
}
