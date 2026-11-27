// Package gen generates passwords and diceware passphrases.
//
// The passphrase word list is the EFF Large Wordlist (7776 words),
// https://www.eff.org/dice, by the Electronic Frontier Foundation,
// licensed CC BY 3.0 US.
package gen

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"math"
	"math/big"
	"strings"
)

const (
	letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" // no 0/O, 1/l/I
	symbols = "!@#$%^&*()-_=+[]{}:,.?"
)

//go:embed eff_large_wordlist.txt
var effList string

// Words is the EFF Large Wordlist.
var Words = parseList(effList)

func parseList(s string) []string {
	var w []string
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if _, word, ok := strings.Cut(line, "\t"); ok {
			w = append(w, strings.TrimSpace(word))
		}
	}
	return w
}

func charset(withSymbols bool) string {
	if withSymbols {
		return letters + symbols
	}
	return letters
}

// Password returns n characters drawn uniformly from letters and digits
// without look-alikes, plus symbols when withSymbols is set.
func Password(n int, withSymbols bool) (string, error) {
	if n < 8 || n > 256 {
		return "", errors.New("password length must be 8..256")
	}
	cs := charset(withSymbols)
	out := make([]byte, n)
	for i := range out {
		j, err := uniform(len(cs))
		if err != nil {
			return "", err
		}
		out[i] = cs[j]
	}
	return string(out), nil
}

// Passphrase returns words random EFF words joined by sep.
func Passphrase(words int, sep string) (string, error) {
	if words < 3 || words > 20 {
		return "", errors.New("passphrase must have 3..20 words")
	}
	out := make([]string, words)
	for i := range out {
		j, err := uniform(len(Words))
		if err != nil {
			return "", err
		}
		out[i] = Words[j]
	}
	return strings.Join(out, sep), nil
}

// PasswordBits and PassphraseBits estimate the entropy of a generated secret.
func PasswordBits(n int, withSymbols bool) float64 {
	return float64(n) * math.Log2(float64(len(charset(withSymbols))))
}

func PassphraseBits(words int) float64 { return float64(words) * math.Log2(float64(len(Words))) }

func uniform(n int) (int, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(r.Int64()), nil
}
