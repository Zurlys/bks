package vault

import (
	"strings"
	"testing"
	"time"
)

// twoCopies returns a vault and an identical copy (same secret), as two
// Macs would hold after a sync.
func twoCopies(t *testing.T) (*Vault, *Vault) {
	t.Helper()
	a, _ := New(recips(), now)
	if _, err := a.Add(Entry{Title: "shared"}, now); err != nil {
		t.Fatal(err)
	}
	b, err := Parse(mustMarshal(t, a))
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func mustMarshal(t *testing.T, v *Vault) []byte {
	b, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func titles(v *Vault) string {
	var s []string
	for _, e := range v.Entries {
		s = append(s, e.Title)
	}
	return strings.Join(s, ",")
}

func TestMergeIdenticalIsUnchanged(t *testing.T) {
	a, b := twoCopies(t)
	if _, changed := Merge(a, b, true); changed {
		t.Fatal("merging identical copies reported a change")
	}
}

func TestMergeAddsBothSides(t *testing.T) {
	a, b := twoCopies(t)
	a.Add(Entry{Title: "from A"}, now.Add(time.Minute))
	b.Add(Entry{Title: "from B"}, now.Add(2*time.Minute))
	m, changed := Merge(a, b, true)
	if !changed || titles(m) != "shared,from A,from B" {
		t.Fatalf("merge = %s (changed %v)", titles(m), changed)
	}
	// and the other way round reaches the same set
	m2, _ := Merge(b, a, true)
	if len(m2.Entries) != 3 {
		t.Fatalf("reverse merge = %s", titles(m2))
	}
}

func TestMergeNewerEditWins(t *testing.T) {
	a, b := twoCopies(t)
	id := a.Entries[0].ID
	a.Update(id, Entry{Title: "edited on A"}, now.Add(time.Minute))
	b.Update(id, Entry{Title: "edited on B later"}, now.Add(2*time.Minute))
	if m, _ := Merge(a, b, true); titles(m) != "edited on B later" {
		t.Fatalf("got %s", titles(m))
	}
	if m, _ := Merge(b, a, true); titles(m) != "edited on B later" {
		t.Fatalf("order changed the winner: %s", titles(m))
	}
}

func TestMergeTombstones(t *testing.T) {
	// deleted on A, older edit on B: stays deleted
	a, b := twoCopies(t)
	id := a.Entries[0].ID
	b.Update(id, Entry{Title: "edited before the delete"}, now.Add(time.Minute))
	a.Delete(id, now.Add(2*time.Minute))
	m, _ := Merge(b, a, true)
	if len(m.Entries) != 0 || len(m.Tombstones) != 1 {
		t.Fatalf("deleted entry came back: %s", titles(m))
	}
	// deleted on A, edited on B after the delete: the edit wins
	a, b = twoCopies(t)
	id = a.Entries[0].ID
	a.Delete(id, now.Add(time.Minute))
	b.Update(id, Entry{Title: "edited after the delete"}, now.Add(2*time.Minute))
	if m, _ := Merge(a, b, true); titles(m) != "edited after the delete" {
		t.Fatalf("newer edit lost to an older delete: %s", titles(m))
	}
	// an old copy without the delete cannot resurrect it (rollback)
	a, b = twoCopies(t)
	a.Delete(a.Entries[0].ID, now.Add(time.Minute))
	if m, changed := Merge(a, b, true); len(m.Entries) != 0 || changed {
		t.Fatalf("old copy resurrected a deleted entry: %s", titles(m))
	}
}

func TestMergeRollbackKeepsNewer(t *testing.T) {
	a, b := twoCopies(t) // b is an old copy
	id := a.Entries[0].ID
	pw := randomSecret(t)
	a.Update(id, Entry{Title: "shared", Password: pw}, now.Add(time.Hour))
	m, changed := Merge(a, b, true)
	if changed || m.Entries[0].Password != pw {
		t.Fatal("an older copy rolled back a newer password")
	}
}

func TestMergeSettingsAndRecipients(t *testing.T) {
	a, b := twoCopies(t)
	b.Settings.IdleLock, b.SettingsUpdated = "2m", now.Add(time.Hour)
	b.Recipients = append(b.Recipients, Recipient{Label: "backup", Subkey: strings.Repeat("B", 40), PubKey: "k"})
	m, changed := Merge(a, b, true)
	if !changed || m.Settings.IdleLock != "2m" || len(m.Recipients) != 2 || m.Recipients[0].Subkey != a.Recipients[0].Subkey {
		t.Fatalf("settings %+v, recipients %d", m.Settings, len(m.Recipients))
	}
	// older settings on the other side lose
	a.Settings.IdleLock, a.SettingsUpdated = "9m", now.Add(2*time.Hour)
	if m, _ := Merge(a, b, true); m.Settings.IdleLock != "9m" {
		t.Fatal("older settings won")
	}
}

func TestMergeKeepsOwnSecret(t *testing.T) {
	a, b := twoCopies(t)
	b.UnlockSecret, _ = NewSecret()
	if m, _ := Merge(a, b, true); string(m.UnlockSecret) != string(a.UnlockSecret) {
		t.Fatal("merge took the other side's unlock secret")
	}
}

func TestMergeWithoutRecipientUnion(t *testing.T) {
	a, b := twoCopies(t)
	b.Recipients = append(b.Recipients, Recipient{Label: "removed", Subkey: strings.Repeat("C", 40), PubKey: "k"})
	if m, _ := Merge(a, b, false); len(m.Recipients) != 1 {
		t.Fatal("a pre-rotation copy brought back a removed recipient")
	}
}
