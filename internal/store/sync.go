package store

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Zurlys/bks/internal/vault"
)

// lastGoodPath is this Mac's copy of the last vault it opened or saved. It
// is merged into every unlock, so an older file arriving through sync (or
// planted) can never roll anything back. It is never synced.
func (s *Store) lastGoodPath() string { return filepath.Join(s.StateDir, "last-good.gpg") }

func (s *Store) writeLastGood(ct []byte) {
	if cur, err := os.ReadFile(s.lastGoodPath()); err == nil && bytes.Equal(cur, ct) {
		return
	}
	if err := os.MkdirAll(s.StateDir, 0o700); err != nil {
		s.warn("cannot keep this Mac's last good copy: %v", err)
		return
	}
	if err := writeFileAtomic(s.lastGoodPath(), ct); err != nil {
		s.warn("cannot keep this Mac's last good copy: %v", err)
	}
}

// conflictCopies lists copies that sync tools leave next to the vault:
// iCloud "vault 2.gpg", Syncthing "vault.sync-conflict-….gpg", Dropbox
// "vault (… conflicted copy …).gpg".
func (s *Store) conflictCopies() []string {
	dir, base := filepath.Dir(s.VaultPath), filepath.Base(s.VaultPath)
	ext := filepath.Ext(base)
	stem := globEscape(strings.TrimSuffix(base, ext))
	seen := map[string]bool{}
	var out []string
	for _, pat := range []string{stem + " *" + ext, stem + ".sync-conflict-*" + ext, stem + " (*conflicted copy*)" + ext} {
		matches, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, m := range matches {
			if !seen[m] && m != s.VaultPath {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

// openCopy decrypts another copy of this vault with its unlock secret, or
// the previous one after a rotation, and checks it carries that secret.
// union says whether the copy's recipients may be merged in: not for a copy
// from before a rotation.
func (s *Store) openCopy(ctx context.Context, data []byte, v *vault.Vault) (*vault.Vault, bool, error) {
	for i, u := range [][]byte{v.UnlockSecret, v.PrevUnlockSecret} {
		if len(u) == 0 {
			continue
		}
		pass := vault.PassphraseFor(u)
		pt, err := s.BKS.DecryptWithPassphrase(ctx, data, pass)
		if err != nil {
			continue
		}
		o, err := vault.Parse(pt)
		if err != nil {
			return nil, false, err
		}
		if subtle.ConstantTimeCompare([]byte(o.Passphrase()), []byte(pass)) != 1 {
			return nil, false, ErrForged
		}
		return o, i == 0, nil
	}
	return nil, false, errors.New("does not open with this vault's unlock secret")
}

// mergeCopies merges this Mac's last good copy and any sync-conflict copies
// into sess.Vault. It reports whether the result must be saved.
func (s *Store) mergeCopies(ctx context.Context, sess *Session, ct []byte) bool {
	changed := false
	if lg, err := os.ReadFile(s.lastGoodPath()); err == nil && !bytes.Equal(lg, ct) {
		if o, union, err := s.openCopy(ctx, lg, sess.Vault); err == nil {
			if m, ch := vault.Merge(sess.Vault, o, union); ch {
				*sess.Vault = *m
				changed = true
				s.warn("the vault file lacked changes this Mac had saved; merged them back")
			}
		}
	}
	for _, p := range s.conflictCopies() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		o, union, err := s.openCopy(ctx, data, sess.Vault)
		if err != nil {
			s.warn("ignoring %s: %v", filepath.Base(p), err)
			continue
		}
		m, ch := vault.Merge(sess.Vault, o, union)
		*sess.Vault = *m
		changed = changed || ch
		sess.conflicts = append(sess.conflicts, p)
		s.warn("merged the sync-conflict copy %s; it is removed after saving", filepath.Base(p))
	}
	sess.Merged = changed
	return changed || len(sess.conflicts) > 0
}

// Rotate gives the vault a new unlock secret, keeping the old one as
// prev_unlock_secret so other Macs can accept the change (after asking).
// It reports whether Touch ID was enrolled on this Mac: it must be
// re-enrolled for the new secret.
func (s *Store) Rotate(ctx context.Context, sess *Session) (bool, error) {
	if sess.ReadOnly {
		return false, errors.New("read-only vault")
	}
	v := sess.Vault
	u, err := vault.NewSecret()
	if err != nil {
		return false, err
	}
	oldU, oldPrev := v.UnlockSecret, v.PrevUnlockSecret
	v.PrevUnlockSecret, v.UnlockSecret = oldU, u
	if err := s.Save(ctx, sess); err != nil {
		v.UnlockSecret, v.PrevUnlockSecret = oldU, oldPrev
		return false, err
	}
	d, err := s.loadDevice()
	if err != nil {
		return false, err
	}
	hadTouchID := d.TouchID != nil
	d.Pin, d.TouchID = v.Pin(), nil
	return hadTouchID, s.saveDevice(d)
}

// RemoveRecipient removes a recipient (by subkey fingerprint, its last 16+
// hex digits, or label) and rotates the unlock secret, since the removed
// key's holder may know the old one.
func (s *Store) RemoveRecipient(ctx context.Context, sess *Session, which string) (vault.Recipient, bool, error) {
	v := sess.Vault
	w := strings.TrimPrefix(strings.ToUpper(strings.ReplaceAll(which, " ", "")), "0X")
	idx := -1
	for i, r := range v.Recipients {
		if r.Subkey == w || (len(w) >= 16 && strings.HasSuffix(r.Subkey, w)) || strings.EqualFold(r.Label, which) {
			if idx >= 0 {
				return vault.Recipient{}, false, fmt.Errorf("%q matches more than one recipient", which)
			}
			idx = i
		}
	}
	if idx < 0 {
		return vault.Recipient{}, false, fmt.Errorf("no recipient %q", which)
	}
	if len(v.Recipients) == 1 {
		return vault.Recipient{}, false, errors.New("cannot remove the only recipient")
	}
	removed, old := v.Recipients[idx], v.Recipients
	v.Recipients = append(v.Recipients[:idx:idx], v.Recipients[idx+1:]...)
	touch, err := s.Rotate(ctx, sess)
	if err != nil {
		v.Recipients = old
		return vault.Recipient{}, false, err
	}
	return removed, touch, nil
}
