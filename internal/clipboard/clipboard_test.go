package clipboard

import (
	"strings"
	"testing"
)

// These tests never touch the real clipboard: RunClear validates its input
// before it waits or reads anything.
func TestRunClearRejectsBadInput(t *testing.T) {
	good := strings.Repeat("ab", 32)
	for name, c := range map[string]struct {
		args  []string
		stdin string
	}{
		"no args":      {nil, good},
		"two args":     {[]string{"1", "2"}, good},
		"zero delay":   {[]string{"0"}, good},
		"huge delay":   {[]string{"99999"}, good},
		"not a number": {[]string{"x"}, good},
		"short hash":   {[]string{"1"}, "abcd"},
		"not hex":      {[]string{"1"}, strings.Repeat("zz", 32)},
		"bad count":    {[]string{"1"}, "cc:abc"},
		"neg count":    {[]string{"1"}, "cc:-4"},
	} {
		if err := RunClear(c.args, strings.NewReader(c.stdin)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
