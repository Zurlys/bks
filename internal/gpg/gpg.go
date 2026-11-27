// Package gpg runs the gpg binary. bks never implements OpenPGP itself, so a
// vault is always readable with plain `gpg -d`.
package gpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// GPG runs gpg against one home directory. An empty Home means the user's
// default home (GNUPGHOME or ~/.gnupg).
type GPG struct {
	Bin  string // gpg binary; "gpg" when empty
	Home string
}

// Error is a failed gpg run with its stderr.
type Error struct {
	Op     string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("gpg %s: %s", e.Op, e.Stderr)
	}
	return fmt.Sprintf("gpg %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func (g GPG) bin() string {
	if g.Bin != "" {
		return g.Bin
	}
	return "gpg"
}

func (g GPG) args(extra ...string) []string {
	a := []string{"--batch", "--quiet", "--no-auto-key-retrieve", "--no-tty"}
	if g.Home != "" {
		a = append([]string{"--homedir", g.Home}, a...)
	}
	return append(a, extra...)
}

// run executes gpg with stdin and, when secret is non-nil, passes secret on
// file descriptor 3 (never argv or env). It returns stdout, stderr and the
// exit error.
func (g GPG) run(ctx context.Context, stdin, secret []byte, args ...string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, g.bin(), g.args(args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	var w *os.File
	if secret != nil {
		r, pw, err := os.Pipe()
		if err != nil {
			return nil, "", err
		}
		cmd.ExtraFiles = []*os.File{r} // fd 3 in the child
		w = pw
		defer r.Close()
	}
	if err := cmd.Start(); err != nil {
		if w != nil {
			w.Close()
		}
		return nil, "", err
	}
	if w != nil {
		cmd.ExtraFiles[0].Close() // the child holds its own copy
		_, werr := w.Write(secret)
		w.Close()
		if werr != nil {
			_ = cmd.Wait()
			return nil, "", fmt.Errorf("passing secret to gpg: %w", werr)
		}
	}
	err := cmd.Wait()
	return stdout.Bytes(), strings.TrimSpace(stderr.String()), err
}

func (g GPG) exec(ctx context.Context, op string, stdin, secret []byte, args ...string) ([]byte, error) {
	out, stderr, err := g.run(ctx, stdin, secret, args...)
	if err != nil {
		return nil, &Error{Op: op, Stderr: stderr, Err: err}
	}
	return out, nil
}

// checkPassphrase enforces what gpg's --passphrase-fd can carry: one line of
// text. Anything else would be silently truncated by gpg.
func checkPassphrase(p string) error {
	if p == "" || strings.ContainsAny(p, "\n\r\x00") {
		return errors.New("passphrase must be non-empty single-line text")
	}
	return nil
}

// Encrypt produces one OpenPGP message that opens with the secret key of any
// recipient subkey (pinned exactly with "!") or with the passphrase.
//
// All three AES256 flags are required: on GnuPG 2.2.41, --cipher-algo AES256
// without --s2k-cipher-algo AES256 yields a message whose passphrase door
// fails with "Bad session key".
func (g GPG) Encrypt(ctx context.Context, plaintext []byte, subkeys []string, passphrase string) ([]byte, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	if len(subkeys) == 0 {
		return nil, errors.New("encrypt: no recipients")
	}
	args := []string{
		"--trust-model", "always", "--no-encrypt-to", "--no-symkey-cache",
		"--pinentry-mode", "loopback", "--passphrase-fd", "3",
		"--cipher-algo", "AES256", "--s2k-cipher-algo", "AES256", "--s2k-digest-algo", "SHA512",
	}
	for _, s := range subkeys {
		if !isFingerprint(s) {
			return nil, fmt.Errorf("encrypt: %q is not a full fingerprint", s)
		}
		args = append(args, "--recipient", s+"!")
	}
	args = append(args, "--output", "-", "--encrypt", "--symmetric")
	return g.exec(ctx, "encrypt", plaintext, []byte(passphrase), args...)
}

// DecryptWithPassphrase opens a message through its passphrase packet. Use it
// only in a home without secret keys: gpg would otherwise offer the
// passphrase to a secret key or a smartcard PIN first.
func (g GPG) DecryptWithPassphrase(ctx context.Context, msg []byte, passphrase string) ([]byte, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	return g.exec(ctx, "decrypt", msg, []byte(passphrase),
		"--no-symkey-cache", "--pinentry-mode", "loopback", "--passphrase-fd", "3", "--decrypt")
}

// Decrypt opens a message with a secret key; gpg-agent asks through the
// normal pinentry, which says which key or card it wants.
func (g GPG) Decrypt(ctx context.Context, msg []byte) ([]byte, error) {
	return g.exec(ctx, "decrypt", msg, nil, "--decrypt")
}

var (
	fingerprintRe = regexp.MustCompile(`^[0-9A-F]{40}$`)
	pubkeyPacket  = regexp.MustCompile(`^:pubkey enc packet:.*\bkeyid ([0-9A-Fa-f]{16})\b`)
	symkeyPacket  = regexp.MustCompile(`^:symkey enc packet:`)
)

// Packets lists, without decrypting, the long key IDs of a message's
// public-key packets and how many passphrase packets it has.
func (g GPG) Packets(ctx context.Context, msg []byte) (keyIDs []string, passphrasePackets int, err error) {
	out, stderr, runErr := g.run(ctx, msg, nil, "--pinentry-mode", "error", "--list-only", "--list-packets")
	for _, line := range strings.Split(string(out), "\n") {
		if m := pubkeyPacket.FindStringSubmatch(line); m != nil {
			keyIDs = append(keyIDs, strings.ToUpper(m[1]))
		} else if symkeyPacket.MatchString(line) {
			passphrasePackets++
		}
	}
	// gpg may exit non-zero because --list-only does not decrypt; the packet
	// listing is still complete.
	if len(keyIDs) == 0 && passphrasePackets == 0 {
		return nil, 0, &Error{Op: "list-packets", Stderr: stderr, Err: runErr}
	}
	return keyIDs, passphrasePackets, nil
}

// ExportPublic returns a minimal armored export of the key that contains fpr.
func (g GPG) ExportPublic(ctx context.Context, fpr string) ([]byte, error) {
	out, err := g.exec(ctx, "export", nil, nil, "--armor", "--export-options", "export-minimal", "--export", fpr)
	if err == nil && len(out) == 0 {
		err = fmt.Errorf("gpg export: no public key %s", fpr)
	}
	return out, err
}

// Import adds armored public keys to this home.
func (g GPG) Import(ctx context.Context, armored []byte) error {
	_, err := g.exec(ctx, "import", armored, nil, "--import-options", "import-minimal", "--import")
	return err
}

// ClearPassphrase drops gpg-agent's cached passphrase for a key, so the next
// decryption asks again.
func (g GPG) ClearPassphrase(ctx context.Context, keygrip string) error {
	if !fingerprintRe.MatchString(keygrip) { // keygrips are 40 hex digits too
		return fmt.Errorf("invalid keygrip %q", keygrip)
	}
	var args []string
	if g.Home != "" {
		args = append(args, "--homedir", g.Home)
	}
	args = append(args, "CLEAR_PASSPHRASE --mode=normal "+keygrip, "/bye")
	out, err := exec.CommandContext(ctx, "gpg-connect-agent", args...).CombinedOutput()
	if err != nil || bytes.Contains(out, []byte("ERR")) {
		return fmt.Errorf("gpg-connect-agent CLEAR_PASSPHRASE: %s %v", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func isFingerprint(s string) bool { return fingerprintRe.MatchString(s) }

var expiryRe = regexp.MustCompile(`^(never|[1-9][0-9]{0,3}[dwmy]?)$`)

// ValidExpiry reports whether s is an expiry gpg's --quick-gen-key accepts
// and bks allows: "never" or a count with optional d/w/m/y unit.
func ValidExpiry(s string) bool { return expiryRe.MatchString(s) }

// GenerateKey creates an ed25519 signing key with a cv25519 encryption
// subkey for uid. gpg-agent asks for the new passphrase through pinentry,
// so bks never sees it. gpg also writes a revocation certificate to
// <homedir>/openpgp-revocs.d/<fingerprint>.rev. It returns the primary key.
func (g GPG) GenerateKey(ctx context.Context, uid, expire string) (Key, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" || strings.HasPrefix(uid, "-") || strings.ContainsAny(uid, "\n\r:") {
		return Key{}, fmt.Errorf("invalid user ID %q", uid)
	}
	if !ValidExpiry(expire) {
		return Key{}, fmt.Errorf("invalid expiry %q: use never, or e.g. 2y, 18m, 90d", expire)
	}
	before, err := g.SecretKeys(ctx)
	if err != nil {
		return Key{}, err
	}
	known := map[string]bool{}
	for _, k := range before {
		known[k.Fingerprint] = true
	}
	if _, err := g.exec(ctx, "generate key", nil, nil, "--quick-gen-key", uid, "future-default", "default", expire); err != nil {
		return Key{}, err
	}
	after, err := g.SecretKeys(ctx)
	if err != nil {
		return Key{}, err
	}
	for _, k := range after {
		if k.Fingerprint == k.Primary && !known[k.Fingerprint] && k.UID == uid {
			return k, nil
		}
	}
	return Key{}, errors.New("gpg reported success but the new key was not found")
}

// ExportSecretKey writes an armored export of the secret key fpr to path
// (never overwriting). gpg-agent asks for the key's passphrase.
func (g GPG) ExportSecretKey(ctx context.Context, fpr, path string) error {
	if !isFingerprint(fpr) {
		return fmt.Errorf("export: %q is not a full fingerprint", fpr)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if _, err := g.exec(ctx, "export secret key", nil, nil, "--armor", "--output", path, "--export-secret-keys", fpr); err != nil {
		os.Remove(path)
		return err
	}
	return os.Chmod(path, 0o600)
}

// Homedir returns the GnuPG home this GPG uses, as gpgconf reports it.
func (g GPG) Homedir(ctx context.Context) (string, error) {
	args := []string{"--list-dirs", "homedir"}
	if g.Home != "" {
		args = append([]string{"--homedir", g.Home}, args...)
	}
	out, err := exec.CommandContext(ctx, "gpgconf", args...).Output()
	if err != nil {
		return "", fmt.Errorf("gpgconf: %w", err)
	}
	return percentUnescape(strings.TrimSpace(string(out))), nil
}

// percentUnescape decodes gpgconf's %XX escapes.
func percentUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var c byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02x", &c); err == nil {
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
