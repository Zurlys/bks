package gen

import (
	"strings"
	"testing"
)

func TestPassword(t *testing.T) {
	p, err := Password(24, true)
	if err != nil || len(p) != 24 {
		t.Fatalf("%q %v", p, err)
	}
	for _, c := range p {
		if !strings.ContainsRune(letters+symbols, c) {
			t.Fatalf("char %q not in charset", c)
		}
	}
	if q, _ := Password(24, true); q == p {
		t.Fatal("two passwords equal")
	}
	plain, _ := Password(64, false)
	if strings.ContainsAny(plain, symbols) {
		t.Fatalf("symbols in no-symbols password: %q", plain)
	}
	for _, n := range []int{4, 7, 257} {
		if _, err := Password(n, true); err == nil {
			t.Errorf("accepted length %d", n)
		}
	}
}

func TestWordList(t *testing.T) {
	if len(Words) != 7776 || Words[0] != "abacus" || Words[7775] != "zoom" {
		t.Fatalf("word list: %d words, first %q, last %q", len(Words), Words[0], Words[len(Words)-1])
	}
	seen := map[string]bool{}
	for _, w := range Words {
		if w == "" || seen[w] {
			t.Fatalf("empty or duplicate word %q", w)
		}
		seen[w] = true
	}
}

func TestPassphrase(t *testing.T) {
	p, err := Passphrase(6, "-")
	if err != nil {
		t.Fatal(err)
	}
	// EFF words may contain '-' themselves (e.g. "t-shirt"), so check with another separator
	q, _ := Passphrase(6, " ")
	words := strings.Split(q, " ")
	if len(words) != 6 || p == "" {
		t.Fatalf("%q / %q", p, q)
	}
	index := map[string]bool{}
	for _, w := range Words {
		index[w] = true
	}
	for _, w := range words {
		if !index[w] {
			t.Fatalf("%q is not an EFF word", w)
		}
	}
	for _, n := range []int{2, 21} {
		if _, err := Passphrase(n, "-"); err == nil {
			t.Errorf("accepted %d words", n)
		}
	}
}

func TestBits(t *testing.T) {
	if b := PassphraseBits(6); b < 77.5 || b > 77.6 {
		t.Errorf("6 words = %.2f bits, want ≈77.55", b)
	}
	if b := PasswordBits(24, true); b < 140 {
		t.Errorf("24 chars with symbols = %.1f bits", b)
	}
}
