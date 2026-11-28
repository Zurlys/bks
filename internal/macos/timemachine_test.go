package macos

import (
	"errors"
	"testing"
)

func TestParseTimeMachine(t *testing.T) {
	fail := errors.New("exit status 1")
	for _, c := range []struct {
		out  string
		err  error
		want Backup
	}{
		{"tmutil: No destinations configured.\n", fail, BackupNone},
		{"====================================================\nName          : Backup\nKind          : Local\nMount Point   : /Volumes/Backup\nID            : 1\n", nil, BackupIncluded},
		{"", fail, BackupUnknown},
		{"something else", nil, BackupUnknown},
	} {
		if got := parseDestinations(c.out, c.err); got != c.want {
			t.Errorf("destinations %q: %v, want %v", c.out, got, c.want)
		}
	}
	for _, c := range []struct {
		out  string
		err  error
		want Backup
	}{
		{"[Excluded]    /Users/x/.local/share/bks/vault.gpg\n", nil, BackupExcluded},
		{"[Included]    /Users/x/.local/share/bks/vault.gpg\n", nil, BackupIncluded},
		{"", fail, BackupUnknown},
	} {
		if got := parseExcluded(c.out, c.err); got != c.want {
			t.Errorf("isexcluded %q: %v, want %v", c.out, got, c.want)
		}
	}
}
