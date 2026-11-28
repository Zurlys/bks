// Package search ranks vault entries against a query, fzf-style.
//
// The query is split on whitespace; every token must match, in any order.
// A token matches a field when its characters appear in the field in order
// (a subsequence), so "jonas.petraitis@example" finds
// "jonas.petraitis@corp.example". Matches at word starts and runs of
// consecutive characters score higher; gaps cost a little. A token starting
// with '#' matches tags only. Case and diacritics are ignored.
//
// Only non-secret fields are searched: title, username, URL hosts, tags and
// custom field names. Passwords, OTP secrets, notes and field values never
// are.
package search

import (
	"net/url"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"github.com/Zurlys/bks/internal/vault"
)

// Scoring, after fzf's v1 algorithm.
const (
	scoreMatch        = 16
	scoreGapStart     = -3
	scoreGapExtension = -1
	bonusBoundary     = scoreMatch / 2 // match right after a separator or at field start
	bonusConsecutive  = -(scoreGapStart + scoreGapExtension)
	firstCharFactor   = 2   // a boundary bonus on the token's first char counts double
	bonusTitle        = 4   // prefer title matches over equal matches elsewhere
	maxFieldValue     = 128 // longer field values are not searched
)

// Match is a ranked entry.
type Match struct {
	Entry *vault.Entry
	Score int
}

// Find returns the entries of v matching query, best first. An empty query
// returns every entry, sorted by title.
func Find(v *vault.Vault, query string) []*vault.Entry {
	ms := Search(v.Entries, query)
	out := make([]*vault.Entry, len(ms))
	for i, m := range ms {
		out[i] = m.Entry
	}
	return out
}

// Search ranks entries against query, best first; ties sort by title.
func Search(entries []vault.Entry, query string) []Match {
	tokens := strings.Fields(Normalize(query))
	var out []Match
	for i := range entries {
		e := &entries[i]
		if score, ok := scoreEntry(e, tokens); ok {
			out = append(out, Match{Entry: e, Score: score})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return Normalize(out[i].Entry.Title) < Normalize(out[j].Entry.Title)
	})
	return out
}

type field struct {
	text  []rune
	title bool
}

func scoreEntry(e *vault.Entry, tokens []string) (int, bool) {
	fields := []field{{[]rune(Normalize(e.Title)), true}}
	add := func(s string) {
		if s = Normalize(s); s != "" {
			fields = append(fields, field{text: []rune(s)})
		}
	}
	add(e.Username)
	for _, u := range e.URLs {
		add(host(u))
	}
	for _, f := range e.Fields {
		add(f.Name)
		// Non-secret values are things like a username, email or server
		// that 1Password keeps in fields for non-login items. Secret values
		// are never searched; long or multi-line text would match almost
		// any query as a subsequence, so it is left out too.
		if !f.Secret && len([]rune(f.Value)) <= maxFieldValue && !strings.ContainsAny(f.Value, "\r\n") {
			add(f.Value)
		}
	}
	var tags [][]rune
	for _, t := range e.Tags {
		tags = append(tags, []rune(Normalize(strings.TrimPrefix(t, "#"))))
	}

	total := 0
	for _, tok := range tokens {
		best := -1
		if strings.HasPrefix(tok, "#") {
			pat := []rune(strings.TrimPrefix(tok, "#"))
			if len(pat) == 0 {
				continue
			}
			for _, t := range tags {
				best = max(best, match(t, pat))
			}
		} else {
			pat := []rune(tok)
			for _, f := range fields {
				if s := match(f.text, pat); s >= 0 {
					if f.title {
						s += bonusTitle
					}
					best = max(best, s)
				}
			}
			for _, t := range tags { // plain tokens may match tags too
				best = max(best, match(t, pat))
			}
		}
		if best < 0 {
			return 0, false
		}
		total += best
	}
	return total, true
}

// match scores pat as a subsequence of text, or returns -1. Like fzf v1 it
// finds the first complete match going forward, then walks back from its
// end to the tightest start, and scores that window.
func match(text, pat []rune) int {
	if len(pat) == 0 {
		return 0
	}
	pi, end := 0, -1
	for i, r := range text {
		if r == pat[pi] {
			if pi++; pi == len(pat) {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return -1
	}
	start := end
	for i, pj := end, len(pat)-1; i >= 0; i-- {
		if text[i] == pat[pj] {
			if pj--; pj < 0 {
				start = i
				break
			}
		}
	}

	score, pi, prev, inGap := 0, 0, -2, false
	for i := start; i <= end && pi < len(pat); i++ {
		if text[i] != pat[pi] {
			if pi > 0 {
				if inGap {
					score += scoreGapExtension
				} else {
					score += scoreGapStart
					inGap = true
				}
			}
			continue
		}
		s := scoreMatch
		b := 0
		if i == 0 || isSeparator(text[i-1]) {
			b = bonusBoundary
		}
		if pi == 0 {
			b *= firstCharFactor
		}
		if prev == i-1 {
			s += bonusConsecutive
		}
		score += s + b
		prev, pi, inGap = i, pi+1, false
	}
	return score
}

func isSeparator(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }

// host returns the host of a URL, or the text before the first '/' when it
// has no scheme ("gitlab.corp.example/x").
func host(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Hostname()
	}
	h, _, _ := strings.Cut(raw, "/")
	return h
}

// fold maps letters that Unicode does not decompose to their ASCII
// spelling; everything else loses its marks via NFD.
var fold = strings.NewReplacer("ł", "l", "ø", "o", "đ", "d", "ß", "ss", "æ", "ae", "œ", "oe", "ı", "i")

// Normalize lowercases s and strips diacritics: "Petraitė" → "petraite".
func Normalize(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	out, _, err := transform.String(t, strings.ToLower(s))
	if err != nil {
		out = strings.ToLower(s)
	}
	return fold.Replace(out)
}
