// Package importer reads other password managers' exports.
package importer

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Zurlys/bks/internal/otp"
	"github.com/Zurlys/bks/internal/vault"
)

// maxExportData bounds how much of export.data is decompressed (zip bombs).
const maxExportData = 512 << 20

// Skipped is an item that was not imported, and why.
type Skipped struct {
	Title  string
	Reason string
}

// Result is a parsed export, ready to add to a vault.
type Result struct {
	Entries []vault.Entry  // IDs and timestamps are set when added
	Skipped []Skipped      // items not imported at all
	Partial []Skipped      // items imported without some part (e.g. an attachment)
	Counts  map[string]int // imported items per 1Password category
}

// 1PUX JSON, only the parts bks uses.
type puxData struct {
	Accounts []struct {
		Vaults []struct {
			Attrs struct {
				Name string `json:"name"`
			} `json:"attrs"`
			Items []puxItem `json:"items"`
		} `json:"vaults"`
	} `json:"accounts"`
}

type puxItem struct {
	UUID         string `json:"uuid"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt"`
	State        string `json:"state"`
	CategoryUUID string `json:"categoryUuid"`
	Details      struct {
		LoginFields []struct {
			Value       string `json:"value"`
			Name        string `json:"name"`
			FieldType   string `json:"fieldType"`
			Designation string `json:"designation"`
		} `json:"loginFields"`
		NotesPlain      string       `json:"notesPlain"`
		Password        string       `json:"password"`
		Sections        []puxSection `json:"sections"`
		PasswordHistory []struct {
			Value string `json:"value"`
			Time  int64  `json:"time"`
		} `json:"passwordHistory"`
	} `json:"details"`
	Overview struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		URLs  []struct {
			URL string `json:"url"`
		} `json:"urls"`
		Tags []string `json:"tags"`
	} `json:"overview"`
}

type puxSection struct {
	Title  string `json:"title"`
	Fields []struct {
		Title string                     `json:"title"`
		ID    string                     `json:"id"`
		Value map[string]json.RawMessage `json:"value"`
	} `json:"fields"`
}

// categories maps 1Password category UUIDs to names.
var categories = map[string]string{
	"001": "login", "002": "credit card", "003": "secure note", "004": "identity",
	"005": "password", "006": "document", "100": "software license", "101": "bank account",
	"102": "database", "103": "driver license", "104": "outdoor license", "105": "membership",
	"106": "passport", "107": "reward program", "108": "social security number",
	"109": "wireless router", "110": "server", "111": "email account", "112": "api credential",
	"113": "medical record", "114": "ssh key", "115": "crypto wallet",
}

// Parse1PUX reads a 1Password .1pux export. Archived items are skipped
// unless includeArchived is set.
func Parse1PUX(path string, includeArchived bool) (*Result, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("not a .1pux (zip) file: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "export.data" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, maxExportData+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxExportData {
			return nil, errors.New("export.data is larger than 512 MB")
		}
		return parseData(b, includeArchived)
	}
	return nil, errors.New("no export.data in this file: is it a 1Password .1pux export?")
}

func parseData(b []byte, includeArchived bool) (*Result, error) {
	var d puxData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("export.data: %w", err)
	}
	vaults := 0
	for _, a := range d.Accounts {
		vaults += len(a.Vaults)
	}
	r := &Result{Counts: map[string]int{}}
	for _, a := range d.Accounts {
		for _, v := range a.Vaults {
			vaultTag := ""
			if vaults > 1 { // several 1Password vaults: keep where each item came from
				vaultTag = tagName(v.Attrs.Name)
			}
			for _, it := range v.Items {
				title := strings.TrimSpace(it.Overview.Title)
				if title == "" {
					title = "(untitled)"
				}
				cat, ok := categories[it.CategoryUUID]
				if !ok {
					cat = "item"
				}
				switch {
				case it.State == "archived" && !includeArchived:
					r.Skipped = append(r.Skipped, Skipped{title, "archived (use --archived)"})
					continue
				case it.State != "" && it.State != "active" && it.State != "archived":
					r.Skipped = append(r.Skipped, Skipped{title, "state " + it.State})
					continue
				case cat == "document":
					r.Skipped = append(r.Skipped, Skipped{title, "document: bks has no file attachments"})
					continue
				}
				e, dropped := convert(it, title, cat, vaultTag)
				for _, f := range dropped {
					r.Partial = append(r.Partial, Skipped{title, f})
				}
				r.Entries = append(r.Entries, e)
				r.Counts[cat]++
			}
		}
	}
	return r, nil
}

func tagName(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), "-"))
}

func convert(it puxItem, title, cat, vaultTag string) (vault.Entry, []string) {
	e := vault.Entry{
		Title:   title,
		Notes:   it.Details.NotesPlain,
		Source:  "1password:" + it.UUID,
		Created: time.Unix(it.CreatedAt, 0).UTC(),
	}
	var skipped []string
	for _, f := range it.Details.LoginFields {
		switch {
		case f.Designation == "username" && e.Username == "":
			e.Username = f.Value
		case f.Designation == "password" && e.Password == "":
			e.Password = f.Value
		case f.FieldType == "P" && f.Value != "":
			e.Fields = append(e.Fields, vault.Field{Name: nonEmpty(f.Name, "password"), Value: f.Value, Secret: true})
		}
	}
	if e.Password == "" {
		e.Password = it.Details.Password // "Password" items
	}
	seenURL := map[string]bool{}
	for _, u := range append([]string{it.Overview.URL}, urlsOf(it)...) {
		if u = strings.TrimSpace(u); u != "" && !seenURL[u] {
			seenURL[u] = true
			e.URLs = append(e.URLs, u)
		}
	}
	for _, t := range it.Overview.Tags {
		e.Tags = append(e.Tags, strings.TrimPrefix(t, "#"))
	}
	if vaultTag != "" {
		e.Tags = append(e.Tags, vaultTag)
	}
	if cat != "login" && cat != "password" && cat != "item" {
		e.Tags = append(e.Tags, tagName(cat))
	}

	for _, sec := range it.Details.Sections {
		for _, f := range sec.Fields {
			name := nonEmpty(f.Title, nonEmpty(sec.Title, "field"))
			for kind, raw := range f.Value {
				switch kind {
				case "totp":
					var s string
					json.Unmarshal(raw, &s)
					if s == "" {
						continue
					}
					if uri, err := otp.Normalize(s, title); err == nil && e.OTP == "" {
						e.OTP = uri
					} else {
						e.Fields = append(e.Fields, vault.Field{Name: name, Value: s, Secret: true})
					}
				case "file":
					skipped = append(skipped, "attachment \""+name+"\" left out: bks stores no files, save it elsewhere before leaving 1Password")
				default:
					fields := fieldValues(kind, raw, name)
					e.Fields = append(e.Fields, fields...)
				}
			}
		}
	}

	var hist []vault.PasswordChange
	for _, h := range it.Details.PasswordHistory {
		if h.Value != "" && h.Value != e.Password {
			hist = append(hist, vault.PasswordChange{Password: h.Value, Until: time.Unix(h.Time, 0).UTC()})
		}
	}
	sort.SliceStable(hist, func(i, j int) bool { return hist[i].Until.After(hist[j].Until) })
	if len(hist) > 5 {
		hist = hist[:5]
	}
	e.History = hist
	return e, skipped
}

func urlsOf(it puxItem) []string {
	var out []string
	for _, u := range it.Overview.URLs {
		out = append(out, u.URL)
	}
	return out
}

// fieldValues turns one 1Password field value into custom fields.
func fieldValues(kind string, raw json.RawMessage, name string) []vault.Field {
	str := func() string {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return strings.Trim(string(raw), `"`)
	}
	switch kind {
	case "concealed", "creditCardNumber":
		if s := str(); s != "" {
			return []vault.Field{{Name: name, Value: s, Secret: true}}
		}
	case "string", "url", "phone", "menu", "gender", "creditCardType", "reference":
		if s := str(); s != "" {
			return []vault.Field{{Name: name, Value: s}}
		}
	case "email":
		var o struct {
			Address string `json:"email_address"`
		}
		if json.Unmarshal(raw, &o) == nil && o.Address != "" {
			return []vault.Field{{Name: name, Value: o.Address}}
		}
		if s := str(); s != "" && !strings.HasPrefix(s, "{") {
			return []vault.Field{{Name: name, Value: s}}
		}
	case "date":
		var n int64
		if json.Unmarshal(raw, &n) == nil && n != 0 {
			return []vault.Field{{Name: name, Value: time.Unix(n, 0).UTC().Format("2006-01-02")}}
		}
	case "monthYear":
		var n int
		if json.Unmarshal(raw, &n) == nil && n != 0 {
			return []vault.Field{{Name: name, Value: fmt.Sprintf("%04d-%02d", n/100, n%100)}}
		}
	case "address":
		var a map[string]string
		if json.Unmarshal(raw, &a) == nil {
			var parts []string
			for _, k := range []string{"street", "city", "state", "zip", "country"} {
				if a[k] != "" {
					parts = append(parts, a[k])
				}
			}
			if len(parts) > 0 {
				return []vault.Field{{Name: name, Value: strings.Join(parts, ", ")}}
			}
		}
	case "sshKey":
		var k struct {
			PrivateKey string `json:"privateKey"`
			Metadata   struct {
				PublicKey   string `json:"publicKey"`
				Fingerprint string `json:"fingerprint"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &k) == nil {
			var out []vault.Field
			if k.PrivateKey != "" {
				out = append(out, vault.Field{Name: name, Value: k.PrivateKey, Secret: true})
			}
			if k.Metadata.PublicKey != "" {
				out = append(out, vault.Field{Name: "public key", Value: k.Metadata.PublicKey})
			}
			if k.Metadata.Fingerprint != "" {
				out = append(out, vault.Field{Name: "fingerprint", Value: k.Metadata.Fingerprint})
			}
			return out
		}
	default:
		// unknown kinds are kept, as secret text: better hidden than lost
		if s := strings.TrimSpace(string(raw)); s != "" && s != `""` && s != "null" {
			return []vault.Field{{Name: name + " (" + kind + ")", Value: strings.Trim(s, `"`), Secret: true}}
		}
	}
	return nil
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
