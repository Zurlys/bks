package gpg_test

import (
	"bytes"
	"testing"

	"github.com/Zurlys/bks/internal/gpg"
)

func TestWithoutPassphrasePackets(t *testing.T) {
	user, bks, a, b := setup(t)
	pass := randomHex(t)
	msg, err := bks.Encrypt(ctx, []byte("secret data"), []string{a.Subkey, b.Subkey}, pass)
	if err != nil {
		t.Fatal(err)
	}
	stripped := gpg.WithoutPassphrasePackets(msg)
	ids, sym, err := bks.Packets(ctx, stripped)
	if err != nil || len(ids) != 2 || sym != 0 {
		t.Fatalf("stripped message: %d key packets, %d passphrase packets, %v", len(ids), sym, err)
	}
	if len(stripped) >= len(msg) || !bytes.HasSuffix(msg, stripped[len(stripped)-64:]) {
		t.Fatal("encrypted data was not copied unchanged")
	}
	// the key still opens it, the unlock secret no longer can
	if got, err := user.Decrypt(ctx, stripped); err != nil || string(got) != "secret data" {
		t.Fatalf("key decrypt of stripped message: %q %v", got, err)
	}
	if _, err := bks.DecryptWithPassphrase(ctx, stripped, pass); err == nil {
		t.Fatal("passphrase still opens the stripped message")
	}
	// idempotent
	if !bytes.Equal(gpg.WithoutPassphrasePackets(stripped), stripped) {
		t.Fatal("stripping twice changed the message")
	}
}

func TestWithoutPassphrasePacketsLeavesOtherInputAlone(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     {},
		"armored":   []byte("-----BEGIN PGP MESSAGE-----\n\nhQIMA...\n"),
		"garbage":   {0x01, 0x02, 0x03},
		"truncated": {0x85, 0x01},             // old-format PKESK whose 2-byte length is cut off
		"only ESK":  {0xc1, 0x02, 0xaa, 0xbb}, // a PKESK and no encrypted data
	} {
		if got := gpg.WithoutPassphrasePackets(in); !bytes.Equal(got, in) {
			t.Errorf("%s: changed to %x", name, got)
		}
	}
}

// Old- and new-format headers with every length encoding, built by hand.
func TestWithoutPassphrasePacketsHeaderFormats(t *testing.T) {
	body := func(n int) []byte { return bytes.Repeat([]byte{0x5a}, n) }
	data := append([]byte{0xd2, 0x03}, body(3)...) // new-format SEIPD, 3 bytes
	cases := map[string]struct{ pkesk, skesk []byte }{
		"old 1-byte length": {append([]byte{0x84, 4}, body(4)...), append([]byte{0x8c, 5}, body(5)...)},
		"old 2-byte length": {append([]byte{0x85, 0x01, 0x00}, body(256)...), append([]byte{0x8d, 0x00, 0x06}, body(6)...)},
		"old 4-byte length": {append([]byte{0x86, 0, 0, 0, 7}, body(7)...), append([]byte{0x8e, 0, 0, 0, 8}, body(8)...)},
		"new 1-octet":       {append([]byte{0xc1, 9}, body(9)...), append([]byte{0xc3, 10}, body(10)...)},
		"new 2-octet":       {append([]byte{0xc1, 192, 8}, body(200)...), append([]byte{0xc3, 192, 0}, body(192)...)},
		"new 5-octet":       {append([]byte{0xc1, 255, 0, 0, 1, 0}, body(256)...), append([]byte{0xc3, 255, 0, 0, 0, 11}, body(11)...)},
	}
	for name, c := range cases {
		msg := append(append(append([]byte{}, c.pkesk...), c.skesk...), data...)
		want := append(append([]byte{}, c.pkesk...), data...)
		if got := gpg.WithoutPassphrasePackets(msg); !bytes.Equal(got, want) {
			t.Errorf("%s: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}
