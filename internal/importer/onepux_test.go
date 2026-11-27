package importer

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zurlys/bks/internal/vault"
)

func rnd(t *testing.T) string {
	b := make([]byte, 10)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type fixture struct {
	pw, oldPW, pin, card, key, apiSecret string
}

// write1PUX builds a .1pux zip with the structure 1Password exports.
func write1PUX(t *testing.T, data any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "export.1pux")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("export.attributes")
	w.Write([]byte(`{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}`))
	w, _ = zw.Create("export.data")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		t.Fatal(err)
	}
	w, _ = zw.Create("files/abc__scan.pdf")
	w.Write([]byte("%PDF"))
	zw.Close()
	f.Close()
	return path
}

func field(title, kind string, value any) map[string]any {
	return map[string]any{"title": title, "id": "f-" + title, "value": map[string]any{kind: value}}
}

func sampleExport(t *testing.T) (map[string]any, fixture) {
	fx := fixture{pw: rnd(t), oldPW: rnd(t), pin: rnd(t), card: "4111" + rnd(t)[:12], key: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + rnd(t), apiSecret: rnd(t)}
	login := map[string]any{
		"uuid": "login-uuid", "createdAt": 1600000000, "updatedAt": 1700000000, "state": "active", "categoryUuid": "001",
		"details": map[string]any{
			"loginFields": []any{
				map[string]any{"value": "jonas.petraitis@corp.example", "name": "email", "fieldType": "E", "designation": "username"},
				map[string]any{"value": fx.pw, "name": "password", "fieldType": "P", "designation": "password"},
				map[string]any{"value": "✓", "name": "remember", "fieldType": "C"},
			},
			"notesPlain": "line one\nline two",
			"sections": []any{
				map[string]any{"title": "", "fields": []any{
					field("one-time password", "totp", "otpauth://totp/GitLab:m?secret=JBSWY3DPEHPK3PXP&issuer=GitLab"),
					field("backup one-time password", "totp", "JBSWY3DPEHPK3PXQ"),
				}},
				map[string]any{"title": "Security", "fields": []any{
					field("PIN", "concealed", fx.pin),
					field("recovery email", "email", map[string]any{"email_address": "r@example.invalid", "provider": "x"}),
					field("since", "date", 1600000000),
					field("scan", "file", map[string]any{"fileName": "scan.pdf"}),
				}},
			},
			"passwordHistory": []any{
				map[string]any{"value": fx.oldPW, "time": 1650000000},
				map[string]any{"value": fx.pw, "time": 1690000000},
			},
		},
		"overview": map[string]any{
			"title": "GitLab (work)", "url": "https://gitlab.corp.example",
			"urls": []any{map[string]any{"label": "", "url": "https://gitlab.corp.example"}, map[string]any{"label": "sso", "url": "https://sso.corp.example"}},
			"tags": []any{"work", "git"},
		},
	}
	items := []any{
		login,
		map[string]any{"uuid": "pw-uuid", "state": "active", "categoryUuid": "005",
			"details": map[string]any{"password": fx.pw + "x"}, "overview": map[string]any{"title": "Wi-Fi password"}},
		map[string]any{"uuid": "note-uuid", "state": "active", "categoryUuid": "003",
			"details": map[string]any{"notesPlain": "a secure note"}, "overview": map[string]any{"title": "Note"}},
		map[string]any{"uuid": "card-uuid", "state": "active", "categoryUuid": "002",
			"details": map[string]any{"sections": []any{map[string]any{"title": "", "fields": []any{
				field("number", "creditCardNumber", fx.card), field("expiry", "monthYear", 202812), field("type", "creditCardType", "visa"),
			}}}}, "overview": map[string]any{"title": "Visa"}},
		map[string]any{"uuid": "ssh-uuid", "state": "active", "categoryUuid": "114",
			"details": map[string]any{"sections": []any{map[string]any{"title": "", "fields": []any{
				field("private key", "sshKey", map[string]any{"privateKey": fx.key, "metadata": map[string]any{"publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:abc"}}),
			}}}}, "overview": map[string]any{"title": "deploy key"}},
		map[string]any{"uuid": "api-uuid", "state": "active", "categoryUuid": "999",
			"details": map[string]any{"sections": []any{map[string]any{"title": "", "fields": []any{
				field("token", "somethingNew", fx.apiSecret),
			}}}}, "overview": map[string]any{"title": "Future item"}},
		map[string]any{"uuid": "doc-uuid", "state": "active", "categoryUuid": "006", "overview": map[string]any{"title": "Passport scan"}},
		map[string]any{"uuid": "old-uuid", "state": "archived", "categoryUuid": "001", "overview": map[string]any{"title": "Old login"}},
	}
	data := map[string]any{"accounts": []any{map[string]any{
		"attrs": map[string]any{"accountName": "x"},
		"vaults": []any{
			map[string]any{"attrs": map[string]any{"name": "Private"}, "items": items},
			map[string]any{"attrs": map[string]any{"name": "Shared Work"}, "items": []any{}},
		},
	}}}
	return data, fx
}

func byTitle(r *Result, title string) *vault.Entry {
	for i := range r.Entries {
		if r.Entries[i].Title == title {
			return &r.Entries[i]
		}
	}
	return nil
}

func fieldOf(e *vault.Entry, name string) *vault.Field {
	for i := range e.Fields {
		if e.Fields[i].Name == name {
			return &e.Fields[i]
		}
	}
	return nil
}

func TestParse1PUX(t *testing.T) {
	data, fx := sampleExport(t)
	r, err := Parse1PUX(write1PUX(t, data), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 6 {
		t.Fatalf("imported %d entries, want 6", len(r.Entries))
	}

	l := byTitle(r, "GitLab (work)")
	if l.Username != "jonas.petraitis@corp.example" || l.Password != fx.pw || l.Source != "1password:login-uuid" {
		t.Fatalf("login basics: %+v", l)
	}
	if !strings.HasPrefix(l.OTP, "otpauth://totp/") || strings.Join(l.URLs, " ") != "https://gitlab.corp.example https://sso.corp.example" {
		t.Fatalf("otp/urls: %q %v", l.OTP, l.URLs)
	}
	if strings.Join(l.Tags, ",") != "work,git,private" {
		t.Fatalf("tags: %v (want 1Password tags plus the vault name)", l.Tags)
	}
	if f := fieldOf(l, "PIN"); f == nil || f.Value != fx.pin || !f.Secret {
		t.Fatalf("concealed field: %+v", f)
	}
	if f := fieldOf(l, "backup one-time password"); f == nil || !f.Secret {
		t.Fatal("second TOTP not kept as a secret field")
	}
	if f := fieldOf(l, "recovery email"); f == nil || f.Value != "r@example.invalid" || f.Secret {
		t.Fatalf("email field: %+v", f)
	}
	if f := fieldOf(l, "since"); f == nil || f.Value != "2020-09-13" {
		t.Fatalf("date field: %+v", f)
	}
	if len(l.History) != 1 || l.History[0].Password != fx.oldPW {
		t.Fatalf("history (current password excluded): %+v", l.History)
	}
	if l.Notes != "line one\nline two" || l.Created.Unix() != 1600000000 {
		t.Fatal("notes or created time lost")
	}

	if e := byTitle(r, "Wi-Fi password"); e == nil || e.Password != fx.pw+"x" {
		t.Fatal("password item")
	}
	if e := byTitle(r, "Note"); e == nil || e.Notes != "a secure note" || !contains(e.Tags, "secure-note") {
		t.Fatalf("secure note: %+v", e)
	}
	card := byTitle(r, "Visa")
	if f := fieldOf(card, "number"); f == nil || f.Value != fx.card || !f.Secret || fieldOf(card, "expiry").Value != "2028-12" {
		t.Fatalf("card: %+v", card.Fields)
	}
	ssh := byTitle(r, "deploy key")
	if f := fieldOf(ssh, "private key"); f == nil || f.Value != fx.key || !f.Secret || fieldOf(ssh, "public key") == nil {
		t.Fatalf("ssh key: %+v", ssh.Fields)
	}
	if f := fieldOf(byTitle(r, "Future item"), "token (somethingNew)"); f == nil || !f.Secret || f.Value != fx.apiSecret {
		t.Fatal("unknown field kinds must be kept, as secrets")
	}

	reasons := map[string]string{}
	for _, s := range r.Skipped {
		reasons[s.Title] += s.Reason + ";"
	}
	if !strings.Contains(reasons["Passport scan"], "document") || !strings.Contains(reasons["Old login"], "archived") {
		t.Fatalf("skipped: %v", reasons)
	}
	// an attachment does not stop its item from being imported
	if reasons["GitLab (work)"] != "" || len(r.Partial) != 1 || r.Partial[0].Title != "GitLab (work)" ||
		!strings.Contains(r.Partial[0].Reason, `attachment "scan" left out`) {
		t.Fatalf("partial: %+v, skipped: %v", r.Partial, reasons)
	}
	if r.Counts["login"] != 1 || r.Counts["credit card"] != 1 {
		t.Fatalf("counts: %v", r.Counts)
	}

	// every imported entry is valid for the vault
	v, _ := vault.New([]vault.Recipient{{Label: "t", Subkey: strings.Repeat("A", 40), PubKey: "k"}}, l.Created)
	for _, e := range r.Entries {
		if _, err := v.Add(e, l.Created); err != nil {
			t.Fatalf("%s: %v", e.Title, err)
		}
	}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestArchivedOnRequest(t *testing.T) {
	data, _ := sampleExport(t)
	r, err := Parse1PUX(write1PUX(t, data), true)
	if err != nil || byTitle(r, "Old login") == nil {
		t.Fatalf("archived item not imported with includeArchived: %v", err)
	}
}

func TestNotA1PUX(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.1pux")
	os.WriteFile(p, []byte("not a zip"), 0o600)
	if _, err := Parse1PUX(p, false); err == nil {
		t.Fatal("accepted a non-zip")
	}
	empty := write1PUX(t, map[string]any{})
	if r, err := Parse1PUX(empty, false); err != nil || len(r.Entries) != 0 {
		t.Fatalf("empty export: %v", err)
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
