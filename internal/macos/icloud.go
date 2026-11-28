package macos

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ICloudSynced reports whether path lies in a folder macOS uploads to
// iCloud: iCloud Drive, or Desktop/Documents when "Desktop & Documents
// Folders" sync is on. Key exports and revocation certificates must not.
func ICloudSynced(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	return iCloudSynced(path, home)
}

// ICloudSyncedUnder is ICloudSynced for the given home directory (tests).
func ICloudSyncedUnder(path, home string) bool { return iCloudSynced(path, home) }

func iCloudSynced(path, home string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = resolve(abs)
	home = resolve(home)
	cloud := filepath.Join(home, "Library", "Mobile Documents")
	if within(abs, cloud) {
		return true
	}
	for _, dir := range []string{"Desktop", "Documents"} {
		if within(abs, filepath.Join(home, dir)) {
			if _, err := os.Stat(filepath.Join(cloud, "com~apple~CloudDocs", dir)); err == nil {
				return true
			}
		}
	}
	return false
}

// resolve follows symlinks in the existing part of p; the rest (a vault
// file or folders not created yet) is kept as written.
func resolve(p string) string {
	rest := ""
	for q := p; ; q = filepath.Dir(q) {
		if r, err := filepath.EvalSymlinks(q); err == nil {
			return filepath.Join(r, rest)
		}
		if q == filepath.Dir(q) {
			return p
		}
		rest = filepath.Join(filepath.Base(q), rest)
	}
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(os.PathSeparator))
}
