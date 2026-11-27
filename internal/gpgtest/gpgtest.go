// Package gpgtest creates throwaway GnuPG homes and keys for tests. It never
// touches the real ~/.gnupg: every home is a fresh temp dir, and GNUPGHOME is
// pointed at a throwaway dir so an accidental default-home call fails closed.
package gpgtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// maxSocketPath keeps gpg-agent's Unix sockets under the 104-byte macOS limit.
const maxSocketPath = 100

// Home returns a new empty GnuPG home (0700) that is removed, with its
// agents killed, when the test ends. os.MkdirTemp is used rather than
// t.TempDir because test names would make socket paths too long.
func Home(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bks")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if n := len(filepath.Join(dir, "S.gpg-agent.browser")); n > maxSocketPath {
		t.Fatalf("temp GnuPG home path too long for agent sockets (%d bytes): %s", n, dir)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", dir, "--kill", "all").Run()
		_ = os.RemoveAll(dir)
	})
	return dir
}

// Isolate points GNUPGHOME at a throwaway home for the rest of the test, so
// code that forgets to pass a home can never reach the real ~/.gnupg.
func Isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GNUPGHOME", Home(t))
}

// Key is a generated test key.
type Key struct {
	Primary string // primary fingerprint
	Subkey  string // encryption subkey fingerprint
}

// NewKey creates an ed25519 key with a cv25519 encryption subkey in home.
// passphrase may be empty (no protection).
func NewKey(t testing.TB, home, email, passphrase string) Key {
	t.Helper()
	gpg(t, home, "--pinentry-mode", "loopback", "--passphrase", passphrase,
		"--quick-gen-key", "test <"+email+">", "future-default", "default", "never")
	out := gpg(t, home, "--with-colons", "--fixed-list-mode", "--list-keys", email)
	var k Key
	var inSub bool
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ":")
		switch {
		case f[0] == "sub":
			inSub = true
		case f[0] == "fpr" && !inSub && k.Primary == "":
			k.Primary = f[9]
		case f[0] == "fpr" && inSub && k.Subkey == "":
			k.Subkey = f[9]
		}
	}
	if k.Primary == "" || k.Subkey == "" {
		t.Fatalf("could not read generated key:\n%s", out)
	}
	return k
}

// CopyPublic copies the public key fpr from one home to another.
func CopyPublic(t testing.TB, from, to, fpr string) {
	t.Helper()
	pub := gpg(t, from, "--armor", "--export", fpr)
	cmd := exec.Command("gpg", "--homedir", to, "--batch", "--quiet", "--import")
	cmd.Stdin = strings.NewReader(pub)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
}

func gpg(t testing.TB, home string, args ...string) string {
	t.Helper()
	if home == "" {
		t.Fatal("gpgtest: empty home would hit the real keyring")
	}
	cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--quiet"}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("gpg %v: %v\n%s", args, err, stderr)
	}
	return string(out)
}

// UsePinentry makes gpg-agent in home answer every passphrase question
// with passphrase, through a tiny fake pinentry. It lets tests exercise
// passphrase-protected keys and key generation without any dialog.
func UsePinentry(t testing.TB, home, passphrase string) {
	t.Helper()
	if strings.ContainsAny(passphrase, "\n\r%") {
		t.Fatal("UsePinentry: passphrase must be plain single-line text")
	}
	script := filepath.Join(home, "pinentry.sh")
	body := "#!/bin/sh\n" +
		"echo 'OK fake pinentry'\n" +
		"while read -r cmd rest; do\n" +
		"  case \"$cmd\" in\n" +
		"    GETPIN) echo 'D " + passphrase + "'; echo OK;;\n" +
		"    BYE) echo OK; exit 0;;\n" +
		"    *) echo OK;;\n" +
		"  esac\n" +
		"done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "gpg-agent.conf"), []byte("pinentry-program "+script+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = exec.Command("gpgconf", "--homedir", home, "--kill", "gpg-agent").Run()
}
