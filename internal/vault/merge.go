package vault

import (
	"bytes"
	"crypto/rand"
)

// NewSecret returns a fresh random unlock secret.
func NewSecret() ([]byte, error) {
	u := make([]byte, secretLen)
	_, err := rand.Read(u)
	return u, err
}

// Merge combines a (this Mac's view) with b, another copy of the same vault
// (same unlock secret; the caller checks). The result keeps a's unlock
// secrets. Rules:
//   - per entry, the newer `updated` wins;
//   - a tombstone removes an entry unless the entry was edited after the
//     deletion;
//   - settings: the newer settings_updated wins;
//   - recipients: union by subkey, a's first — only when unionRecipients is
//     set. A copy from before an unlock-secret rotation must not bring back
//     a recipient that was removed (removal always rotates).
//
// changed reports whether the result differs from a.
func Merge(a, b *Vault, unionRecipients bool) (out *Vault, changed bool) {
	m := *a

	m.Tombstones = append([]Tombstone(nil), a.Tombstones...)
	at := map[string]int{}
	for i, t := range m.Tombstones {
		at[t.ID] = i
	}
	for _, t := range b.Tombstones {
		if i, ok := at[t.ID]; ok {
			if t.Deleted.After(m.Tombstones[i].Deleted) {
				m.Tombstones[i].Deleted = t.Deleted
			}
			continue
		}
		at[t.ID] = len(m.Tombstones)
		m.Tombstones = append(m.Tombstones, t)
	}

	byID := map[string]int{}
	entries := make([]Entry, 0, len(a.Entries)+len(b.Entries))
	for _, e := range append(append([]Entry(nil), a.Entries...), b.Entries...) {
		if i, ok := byID[e.ID]; ok {
			if e.Updated.After(entries[i].Updated) {
				entries[i] = e
			}
			continue
		}
		byID[e.ID] = len(entries)
		entries = append(entries, e)
	}
	m.Entries = make([]Entry, 0, len(entries))
	for _, e := range entries {
		if i, ok := at[e.ID]; ok && !e.Updated.After(m.Tombstones[i].Deleted) {
			continue
		}
		m.Entries = append(m.Entries, e)
	}

	if b.SettingsUpdated.After(a.SettingsUpdated) {
		m.Settings, m.SettingsUpdated = b.Settings, b.SettingsUpdated
	}

	m.Recipients = append([]Recipient(nil), a.Recipients...)
	have := map[string]bool{}
	for _, r := range m.Recipients {
		have[r.Subkey] = true
	}
	for _, r := range b.Recipients {
		if unionRecipients && !have[r.Subkey] {
			have[r.Subkey] = true
			m.Recipients = append(m.Recipients, r)
		}
	}

	before, err1 := a.Marshal()
	after, err2 := m.Marshal()
	return &m, err1 != nil || err2 != nil || !bytes.Equal(before, after)
}
