package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/vault"
)

func TestPickOne(t *testing.T) {
	v, err := vault.New([]vault.Recipient{{Label: "t", Subkey: strings.Repeat("A", 40), PubKey: "k"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []vault.Entry{
		{Title: "GitHub", OTP: "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"},
		{Title: "GitHub Enterprise"},
		{Title: "Bank"},
	} {
		if _, err := v.Add(e, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	hasOTP := func(e *vault.Entry) bool { return e.OTP != "" }
	cases := []struct {
		query   string
		keep    func(*vault.Entry) bool
		title   string // expected entry, or
		wantErr string // expected error substring
	}{
		{query: "github", title: "GitHub"},                // exact title beats the longer match
		{query: "enterprise", title: "GitHub Enterprise"}, // single match
		{query: "git", wantErr: "2 entries match"},        // ambiguous: never guess
		{query: "git", keep: hasOTP, title: "GitHub"},     // the filter narrows to one
		{query: "bank", keep: hasOTP, wantErr: `"Bank" has no one-time code`},
		{query: "nothing", wantErr: "no entry matches"},
	}
	for _, c := range cases {
		e, err := pickOne(v, c.query, c.keep)
		switch {
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("pickOne(%q): err = %v, want %q", c.query, err, c.wantErr)
		case c.wantErr == "" && (err != nil || e.Title != c.title):
			t.Errorf("pickOne(%q) = %v, %v; want %q", c.query, e, err, c.title)
		}
	}
}
