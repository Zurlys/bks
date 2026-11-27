// Package macos holds small macOS-only checks. On other systems they report
// nothing.
package macos

import (
	"os/exec"
	"runtime"
)

// GnuPGPassphraseSaved reports whether GPG Suite's pinentry has saved the
// passphrase for this keygrip in the login Keychain ("Save in Keychain").
// If so, the GPG door of bks unlocks without asking anything. Only item
// attributes are queried; the secret is never read.
func GnuPGPassphraseSaved(keygrip string) bool {
	if runtime.GOOS != "darwin" || keygrip == "" {
		return false
	}
	return exec.Command("security", "find-generic-password", "-s", "GnuPG", "-a", keygrip).Run() == nil
}
