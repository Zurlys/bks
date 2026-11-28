package macos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestICloudSynced(t *testing.T) {
	home := t.TempDir()
	for _, d := range []string{"Desktop", "Documents", "Downloads", "Library/Mobile Documents/com~apple~CloudDocs/Desktop"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Desktop sync on (CloudDocs/Desktop exists), Documents sync off
	for path, want := range map[string]bool{
		"Desktop/key.asc": true,
		"Library/Mobile Documents/com~apple~CloudDocs/x.asc": true,
		"Documents/key.asc": false,
		"Downloads/key.asc": false,
		"key.asc":           false,
	} {
		if got := iCloudSynced(filepath.Join(home, path), home); got != want {
			t.Errorf("%s: got %v, want %v", path, got, want)
		}
	}
	// folders that do not exist yet, under a home reached through a symlink
	// (/var → /private/var on macOS)
	if !iCloudSynced(filepath.Join(home, "Library/Mobile Documents/com~apple~CloudDocs/bks/new/vault.gpg"), home) {
		t.Error("a new folder in iCloud Drive not seen as synced")
	}
	if iCloudSynced(filepath.Join(home, ".local/share/bks/new/vault.gpg"), home) {
		t.Error("a new local folder seen as synced")
	}
	if iCloudSynced("/Volumes/USB/key.asc", home) {
		t.Error("USB path reported as synced")
	}
}
