package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

func recips() []Recipient {
	return []Recipient{{Label: "test", Subkey: strings.Repeat("A", 40), PubKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----"}}
}

func TestNewAndRoundTrip(t *testing.T) {
	v, err := New(recips(), now)
	if err != nil {
		t.Fatal(err)
	}
	pw := randomSecret(t)
	if _, err := v.Add(Entry{Title: "GitLab (work)", Username: randomSecret(t) + "@example.invalid", Password: pw,
		OTP: "otpauth://totp/GitLab:m?secret=JBSWY3DPEHPK3PXP&issuer=GitLab", Tags: []string{"work"}}, now); err != nil {
		t.Fatal(err)
	}
	b, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	w, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.UnlockSecret, v.UnlockSecret) || len(w.Entries) != 1 || w.Entries[0].Password != pw {
		t.Fatalf("round trip lost data: %+v", w)
	}
}

func randomSecret(t *testing.T) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Vault){
		"format":        func(v *Vault) { v.Format = 2 },
		"short secret":  func(v *Vault) { v.UnlockSecret = v.UnlockSecret[:16] },
		"no recipients": func(v *Vault) { v.Recipients = nil },
		"dup recipient": func(v *Vault) { v.Recipients = append(v.Recipients, v.Recipients[0]) },
		"short subkey":  func(v *Vault) { v.Recipients[0].Subkey = "ABCD" },
		"bad duration":  func(v *Vault) { v.Settings.IdleLock = "soon" },
		"dup entry id": func(v *Vault) {
			v.Entries = []Entry{{ID: "X", Title: "a"}, {ID: "X", Title: "b"}}
		},
		"bad otp": func(v *Vault) { v.Entries = []Entry{{ID: "X", Title: "a", OTP: "JBSWY3DP"}} },
	} {
		v, _ := New(recips(), now)
		mutate(v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}

// U is binary; gpg reads the passphrase as one line. Two secrets that differ
// only after an embedded newline must still yield different, newline-free
// passphrases.
func TestPassphraseIsOneLineHex(t *testing.T) {
	u1 := append([]byte("abc\n"), bytes.Repeat([]byte{1}, 28)...)
	u2 := append([]byte("abc\n"), bytes.Repeat([]byte{2}, 28)...)
	p1, p2 := PassphraseFor(u1), PassphraseFor(u2)
	if p1 == p2 || len(p1) != 64 || strings.ContainsAny(p1+p2, "\n\r\x00") {
		t.Fatalf("passphrases %q %q", p1, p2)
	}
	if PinFor(u1) == PinFor(u2) || len(PinFor(u1)) != 64 {
		t.Fatal("pins must differ and be hex sha256")
	}
}

func TestField(t *testing.T) {
	e := Entry{Password: "p", Username: "u", URLs: []string{"https://x"}, Fields: []Field{{Name: "Recovery", Value: "r"}}}
	for name, want := range map[string]string{"": "p", "user": "u", "url": "https://x", "recovery": "r"} {
		if got, ok := e.Field(name); !ok || got != want {
			t.Errorf("Field(%q) = %q, %v", name, got, ok)
		}
	}
	if _, ok := e.Field("missing"); ok {
		t.Error("missing field found")
	}
}

func TestNewIDSortsByTime(t *testing.T) {
	a, b := NewID(now), NewID(now.Add(time.Millisecond))
	if len(a) != 26 || a >= b || NewID(now) == a {
		t.Fatalf("ids %s %s", a, b)
	}
}

func TestUpdateKeepsHistory(t *testing.T) {
	v, _ := New(recips(), now)
	pw := []string{randomSecret(t)}
	e, err := v.Add(Entry{Title: "Bank", Password: pw[0]}, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now
	for i := 1; i <= 7; i++ {
		later = later.Add(time.Hour)
		pw = append(pw, randomSecret(t))
		if _, err := v.Update(e.ID, Entry{Title: "Bank", Password: pw[i]}, later); err != nil {
			t.Fatal(err)
		}
	}
	got := v.Get(e.ID)
	if got.Password != pw[7] || got.Created != e.Created || !got.Updated.Equal(later) || got.ID != e.ID {
		t.Fatalf("update: %+v", got)
	}
	if len(got.History) != 5 || got.History[0].Password != pw[6] || got.History[4].Password != pw[2] {
		t.Fatalf("history (newest first, 5 kept): %+v", got.History)
	}
	// same password again: no new history entry
	if _, err := v.Update(e.ID, Entry{Title: "Bank renamed", Password: pw[7]}, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(v.Get(e.ID).History) != 5 || v.Get(e.ID).Title != "Bank renamed" {
		t.Fatal("rename without password change touched history")
	}
	if _, err := v.Update(e.ID, Entry{Title: " "}, now); err == nil {
		t.Fatal("empty title accepted")
	}
	if _, err := v.Update(e.ID, Entry{Title: "x", OTP: "nope"}, now); err == nil {
		t.Fatal("bad otp accepted")
	}
	if _, err := v.Update("missing", Entry{Title: "x"}, now); err == nil {
		t.Fatal("missing id accepted")
	}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteLeavesTombstone(t *testing.T) {
	v, _ := New(recips(), now)
	a, _ := v.Add(Entry{Title: "a"}, now)
	b, _ := v.Add(Entry{Title: "b"}, now)
	if err := v.Delete(a.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if v.Get(a.ID) != nil || v.Get(b.ID) == nil || len(v.Entries) != 1 {
		t.Fatalf("entries after delete: %+v", v.Entries)
	}
	if len(v.Tombstones) != 1 || v.Tombstones[0].ID != a.ID {
		t.Fatalf("tombstones: %+v", v.Tombstones)
	}
	if err := v.Delete(a.ID, now); err == nil {
		t.Fatal("deleting twice succeeded")
	}
}
