package search

import (
	"strings"
	"testing"
	"time"

	"github.com/Zurlys/bks/internal/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.New([]vault.Recipient{{Label: "t", Subkey: strings.Repeat("A", 40), PubKey: "k"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []vault.Entry{
		{Title: "GitLab (work)", Username: "jonas.petraitis@corp.example", URLs: []string{"https://gitlab.corp.example/users/sign_in"}, Tags: []string{"work", "git"}},
		{Title: "Grafana prod", Username: "jonas.petraitis@corp.example", Tags: []string{"work"}},
		{Title: "GitHub", Username: "Petraitė", Tags: []string{"personal", "git"}},
		{Title: "Bank", Username: "1234567", URLs: []string{"bank.example"},
			Password: "zebra-password", Notes: "zebra notes",
			OTP:    "otpauth://totp/Bank:x?secret=ZEBRAZEBRA",
			Fields: []vault.Field{{Name: "PIN", Value: "zebra-pin", Secret: true}, {Name: "recovery codes", Value: "printed, in the safe"}}},
		{Title: "Grafana integration test", Username: "ci"},
	} {
		if _, err := v.Add(e, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func titles(es []*vault.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Title)
	}
	return out
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Petraitė":      "petraite",
		"ĄČĘĖĮŠŲŪŽ":     "aceeisuuz",
		"Łódź":          "lodz",
		"Straße":        "strasse",
		"JONAS@Corp":    "jonas@corp",
		"naïve café":    "naive cafe",
		"already plain": "already plain",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// The acceptance tests from DESIGN.md.
func TestAcceptance(t *testing.T) {
	v := testVault(t)
	both := []string{"GitLab (work)", "Grafana prod"}
	for q, want := range map[string][]string{
		"jonas.petraitis@example": both,
		"jonas petraitis example": both,
		"example jonas":           both, // any order
	} {
		got := titles(Find(v, q))
		if len(got) != 2 || !contains(got, want[0]) || !contains(got, want[1]) {
			t.Errorf("Find(%q) = %v, want %v", q, got, want)
		}
	}
	if a, b := titles(Find(v, "petraitė")), titles(Find(v, "petraite")); strings.Join(a, "|") != strings.Join(b, "|") || len(a) != 3 {
		t.Errorf("diacritics: %v vs %v", a, b)
	}
	if got := titles(Find(v, "#work git")); len(got) != 1 || got[0] != "GitLab (work)" {
		t.Errorf("#work git = %v", got)
	}
}

func TestSecretsAreNeverSearched(t *testing.T) {
	v := testVault(t)
	if got := Find(v, "zebra"); len(got) != 0 {
		t.Fatalf("query matched secret content: %v", titles(got))
	}
	// field names, URL hosts and visible (non-secret) field values are searchable
	for _, q := range []string{"recovery codes", "pin", "bank.example", "in the safe"} {
		if got := titles(Find(v, q)); len(got) == 0 || got[0] != "Bank" {
			t.Errorf("Find(%q) = %v, want Bank first", q, got)
		}
	}
	// URL paths are not
	if got := titles(Find(v, "sign_in")); len(got) != 0 {
		t.Errorf("URL path searched: %v", got)
	}
}

func TestRanking(t *testing.T) {
	v := testVault(t)
	// title prefix beats a scattered match ("Grafana integration test")
	got := titles(Find(v, "git"))
	if len(got) < 2 || got[0] != "GitHub" || got[1] != "GitLab (work)" {
		t.Errorf("Find(git) = %v, want GitHub, GitLab first", got)
	}
	if got := titles(Find(v, "graf prod")); got[0] != "Grafana prod" {
		t.Errorf("Find(graf prod) = %v", got)
	}
	// word-start + consecutive matches beat the same letters scattered
	if a, b := match([]rune("grafana prod"), []rune("prod")), match([]rune("pxrxoxd"), []rune("prod")); a <= b {
		t.Errorf("consecutive %d should beat scattered %d", a, b)
	}
}

func TestTagTokens(t *testing.T) {
	v := testVault(t)
	if got := titles(Find(v, "#personal")); len(got) != 1 || got[0] != "GitHub" {
		t.Errorf("#personal = %v", got)
	}
	// '#' tokens only look at tags: "#grafana" is not a tag
	if got := Find(v, "#grafana"); len(got) != 0 {
		t.Errorf("#grafana matched non-tag fields: %v", titles(got))
	}
}

func TestNoMatchAndEmpty(t *testing.T) {
	v := testVault(t)
	if got := Find(v, "xyzzy"); len(got) != 0 {
		t.Errorf("xyzzy = %v", titles(got))
	}
	all := titles(Find(v, "  "))
	if len(all) != 5 || all[0] != "Bank" || all[4] != "Grafana prod" {
		t.Errorf("empty query = %v, want all sorted by title", all)
	}
}

func TestMatchSubsequence(t *testing.T) {
	if match([]rune("abc"), []rune("abd")) != -1 || match([]rune("abc"), []rune("ac")) < 0 || match([]rune(""), []rune("a")) != -1 {
		t.Error("subsequence logic wrong")
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// 1Password keeps the username of non-login items (servers, databases,
// email accounts) in a plain field: its value must be searchable.
func TestNonSecretFieldValues(t *testing.T) {
	es := []vault.Entry{
		{Title: "Cloud VPN", Fields: []vault.Field{{Name: "username", Value: "name.surname@cloud.local"}}},
		{Title: "Vault token", Fields: []vault.Field{{Name: "token", Value: "s3cr3t-local-value", Secret: true}}},
		{Title: "Long note", Fields: []vault.Field{{Name: "info", Value: "name wrote this\nfrom a local machine"}}},
		{Title: "Huge", Fields: []vault.Field{{Name: "info", Value: strings.Repeat("name local ", 20)}}},
	}
	for _, q := range []string{"name local", "name surname local", "name.surname@local", "cloud.local"} {
		got := Search(es, q)
		if len(got) != 1 || got[0].Entry.Title != "Cloud VPN" {
			var names []string
			for _, m := range got {
				names = append(names, m.Entry.Title)
			}
			t.Errorf("%q → %v, want only Cloud VPN", q, names)
		}
	}
	if got := Search(es, "s3cr3t"); len(got) != 0 {
		t.Errorf("a secret field value was searched: %v", got[0].Entry.Title)
	}
}
