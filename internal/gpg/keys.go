package gpg

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Key is one primary key or subkey from a gpg --with-colons listing.
type Key struct {
	Fingerprint string
	KeyID       string // long key ID: last 16 hex digits of Fingerprint
	Keygrip     string
	Primary     string // fingerprint of the primary key
	UID         string // first user ID of the primary key
	Created     time.Time
	Expires     time.Time // zero: never
	Validity    string    // gpg validity letter
	Usage       string    // this key's own capabilities, e.g. "e", "sc"
	Algo        int       // OpenPGP public-key algorithm number
	Bits        int
	Curve       string // ECC curve name, e.g. "cv25519"
	// Token is set in secret-key listings only: "+" secret on this machine,
	// "#" secret not available (stub), otherwise a smartcard serial number.
	Token string
}

// AlgoName is a short algorithm label such as "rsa3072" or "cv25519".
func (k Key) AlgoName() string {
	switch {
	case k.Curve != "":
		return k.Curve
	case k.Algo >= 1 && k.Algo <= 3:
		return fmt.Sprintf("rsa%d", k.Bits)
	case k.Algo == 16:
		return fmt.Sprintf("elg%d", k.Bits)
	case k.Algo == 17:
		return fmt.Sprintf("dsa%d", k.Bits)
	}
	return fmt.Sprintf("algo%d", k.Algo)
}

// SecretHere reports whether a secret-key listing shows the secret part as
// usable here (on disk or on a smartcard), not as a stub.
func (k Key) SecretHere() bool { return k.Token != "" && k.Token != "#" }

// OnCard reports whether the secret part lives on a smartcard.
func (k Key) OnCard() bool { return k.SecretHere() && k.Token != "+" }

// Expired reports whether the key has expired at now.
func (k Key) Expired(now time.Time) bool {
	return k.Validity == "e" || (!k.Expires.IsZero() && !now.Before(k.Expires))
}

// usable reports whether the key can encrypt at now.
func (k Key) usableForEncryption(now time.Time) bool {
	switch k.Validity {
	case "r", "i", "d", "e":
		return false
	}
	return strings.Contains(k.Usage, "e") && !k.Expired(now)
}

// ParseKeys reads a `gpg --with-colons --with-keygrip --fixed-list-mode`
// listing (public or secret) into keys, primary keys and subkeys alike.
func ParseKeys(listing []byte) ([]Key, error) {
	var keys []Key
	var primary, uid string
	firstOfBlock := 0
	for _, line := range strings.Split(string(listing), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 10 {
			continue
		}
		switch f[0] {
		case "pub", "sub", "sec", "ssb":
			if f[0] == "pub" || f[0] == "sec" {
				primary, uid = "", ""
				firstOfBlock = len(keys)
			}
			if len(f) < 12 {
				return nil, fmt.Errorf("short %s record", f[0])
			}
			created, err := epoch(f[5])
			if err != nil {
				return nil, err
			}
			expires, err := epoch(f[6])
			if err != nil {
				return nil, err
			}
			k := Key{
				KeyID: strings.ToUpper(f[4]), Created: created, Expires: expires,
				Validity: f[1], Usage: f[11], Primary: primary, UID: uid,
			}
			k.Bits, _ = strconv.Atoi(f[2])
			k.Algo, _ = strconv.Atoi(f[3])
			if len(f) > 14 {
				k.Token = f[14]
			}
			if len(f) > 16 {
				k.Curve = f[16]
			}
			keys = append(keys, k)
		case "fpr":
			if len(keys) == 0 {
				continue
			}
			k := &keys[len(keys)-1]
			if k.Fingerprint == "" {
				k.Fingerprint = strings.ToUpper(f[9])
				if primary == "" {
					primary = k.Fingerprint
					k.Primary = primary
				}
			}
		case "grp":
			if len(keys) > 0 && keys[len(keys)-1].Keygrip == "" {
				keys[len(keys)-1].Keygrip = strings.ToUpper(f[9])
			}
		case "uid":
			if uid == "" {
				uid = f[9]
				for i := firstOfBlock; i < len(keys); i++ {
					keys[i].UID = uid
				}
			}
		}
	}
	for i := range keys {
		if keys[i].Primary == "" {
			keys[i].Primary = primary
		}
	}
	return keys, nil
}

func epoch(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if strings.Contains(s, "T") { // ISO form, only with --fixed-list-mode off
		return time.Parse("20060102T150405", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad timestamp %q", s)
	}
	return time.Unix(n, 0), nil
}

// ErrNoEncryptionKey means no valid encryption-capable (sub)key was found.
var ErrNoEncryptionKey = errors.New("no valid encryption subkey")

var hexID = regexp.MustCompile(`^[0-9A-Fa-f]{16}([0-9A-Fa-f]{24})?$`)

// EncryptionKey resolves fpr to the exact key bks pins as a recipient:
//   - fpr names a subkey: that subkey, if it can encrypt;
//   - fpr names a primary key: its newest valid encryption-capable key.
func (g GPG) EncryptionKey(ctx context.Context, fpr string, now time.Time) (Key, error) {
	fpr = strings.TrimPrefix(strings.ToUpper(strings.ReplaceAll(fpr, " ", "")), "0X")
	if !hexID.MatchString(fpr) {
		return Key{}, fmt.Errorf("%q is not a key ID or fingerprint", fpr)
	}
	keys, err := g.ListKeys(ctx, fpr)
	if err != nil {
		return Key{}, err
	}
	return PickEncryptionKey(keys, fpr, now)
}

// PickEncryptionKey applies EncryptionKey's rule to a parsed listing.
func PickEncryptionKey(keys []Key, fpr string, now time.Time) (Key, error) {
	for _, k := range keys { // exact subkey (or primary) requested by fingerprint or key ID
		if (k.Fingerprint == fpr || k.KeyID == fpr) && k.Fingerprint != k.Primary {
			if !k.usableForEncryption(now) {
				return Key{}, fmt.Errorf("subkey %s cannot encrypt (usage %q, validity %q, expires %s): %w",
					k.KeyID, k.Usage, k.Validity, fmtExpiry(k.Expires), ErrNoEncryptionKey)
			}
			return k, nil
		}
	}
	var candidates []Key
	for _, k := range keys {
		if (k.Primary == fpr || strings.HasSuffix(k.Primary, fpr)) && k.usableForEncryption(now) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return Key{}, fmt.Errorf("key %s: %w", fpr, ErrNoEncryptionKey)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Created.After(candidates[j].Created) })
	return candidates[0], nil
}

// Candidate is a key bks can encrypt a vault to: a primary key and the
// subkey that would be pinned.
type Candidate struct {
	Primary Key
	Encrypt Key
}

// EncryptionCandidates picks, for every valid primary key in a secret-key
// listing, its newest valid encryption key whose secret part is here (on
// disk or a smartcard). Keys with only stubs are left out: they could not
// open the vault on this machine.
func EncryptionCandidates(keys []Key, now time.Time) []Candidate {
	var out []Candidate
	for _, p := range keys {
		if p.Fingerprint == "" || p.Fingerprint != p.Primary {
			continue
		}
		switch p.Validity {
		case "r", "e", "i", "d":
			continue
		}
		if p.Expired(now) {
			continue
		}
		var best *Key
		for i := range keys {
			k := &keys[i]
			if k.Primary != p.Fingerprint || !k.usableForEncryption(now) || !k.SecretHere() {
				continue
			}
			if best == nil || k.Created.After(best.Created) {
				best = k
			}
		}
		if best != nil {
			out = append(out, Candidate{Primary: p, Encrypt: *best})
		}
	}
	return out
}

// Key returns the key (primary or subkey) with exactly this fingerprint.
func (g GPG) Key(ctx context.Context, fpr string) (Key, error) {
	keys, err := g.ListKeys(ctx, fpr)
	if err != nil {
		return Key{}, err
	}
	for _, k := range keys {
		if k.Fingerprint == strings.ToUpper(fpr) || k.KeyID == strings.ToUpper(fpr) {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("key %s not found", fpr)
}

// SecretKeys lists every key whose secret part this keyring knows about.
func (g GPG) SecretKeys(ctx context.Context) ([]Key, error) {
	out, err := g.exec(ctx, "list-secret-keys", nil, nil,
		"--with-colons", "--with-keygrip", "--fixed-list-mode", "--list-secret-keys")
	if err != nil {
		return nil, err
	}
	return ParseKeys(out)
}

// ListKeys lists the public keyblocks matching id.
func (g GPG) ListKeys(ctx context.Context, id string) ([]Key, error) {
	out, err := g.exec(ctx, "list-keys", nil, nil,
		"--with-colons", "--with-keygrip", "--fixed-list-mode", "--list-keys", "--", id)
	if err != nil {
		return nil, err
	}
	return ParseKeys(out)
}

func fmtExpiry(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02")
}
