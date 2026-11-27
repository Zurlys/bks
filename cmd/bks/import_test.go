package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Zurlys/bks/internal/gpgtest"
	"github.com/Zurlys/bks/internal/importer"
)

func random(t *testing.T) string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func tiny1PUX(t *testing.T, pw string) string {
	path := filepath.Join(t.TempDir(), "e.1pux")
	f, _ := os.Create(path)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("export.data")
	json.NewEncoder(w).Encode(map[string]any{"accounts": []any{map[string]any{"vaults": []any{map[string]any{
		"attrs": map[string]any{"name": "Private"},
		"items": []any{map[string]any{
			"uuid": "u1", "state": "active", "categoryUuid": "001", "createdAt": 1600000000,
			"details":  map[string]any{"loginFields": []any{map[string]any{"value": pw, "designation": "password", "fieldType": "P"}}},
			"overview": map[string]any{"title": "Imported login"},
		}},
	}}}}})
	zw.Close()
	f.Close()
	return path
}

func TestImportIntoAndNoDuplicates(t *testing.T) {
	e := newInitEnv(t)
	gpgtest.NewKey(t, e.userHome, "mine@test.invalid", "")
	if err := e.run("1", "", ""); err != nil {
		t.Fatal(err)
	}
	pw := random(t)
	r, err := importer.Parse1PUX(tiny1PUX(t, pw), false)
	if err != nil {
		t.Fatal(err)
	}
	var plan bytes.Buffer
	printPlan(&plan, r, true)
	if strings.Contains(plan.String(), pw) || !strings.Contains(plan.String(), "Imported login") {
		t.Fatalf("plan leaks secrets or lacks titles:\n%s", plan.String())
	}
	sess, err := e.s.UnlockGPG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if added, dup, err := importInto(ctx, e.s, sess, r); err != nil || added != 1 || dup != 0 {
		t.Fatalf("first import: %d %d %v", added, dup, err)
	}
	again, _ := e.s.UnlockGPG(ctx)
	if added, dup, err := importInto(ctx, e.s, again, r); err != nil || added != 0 || dup != 1 {
		t.Fatalf("re-import duplicated: %d %d %v", added, dup, err)
	}
	got := again.Vault.Entries[0]
	if got.Password != pw || got.Created.Unix() != 1600000000 || got.Source != "1password:u1" {
		t.Fatalf("stored: %+v", got)
	}
}
