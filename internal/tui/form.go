package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Zurlys/bks/internal/otp"
	"github.com/Zurlys/bks/internal/vault"
)

// Form fields, in tab order; notes is the textarea after them.
const (
	fTitle = iota
	fUser
	fPass
	fURLs
	fTags
	fOTP
	fNotes // the textarea
	fieldCount
)

var fieldLabels = [...]string{"title", "username", "password", "urls", "tags", "otp", "notes"}

// form edits one entry. It holds plain text only; vault rules (history,
// timestamps, validation) apply when the model saves it.
type form struct {
	id       string // "" for a new entry
	base     vault.Entry
	inputs   [fOTP + 1]textinput.Model
	notes    textarea.Model
	focus    int
	showPass bool
	dirty    bool
}

func newForm(e *vault.Entry) form {
	f := form{}
	if e != nil {
		f.id, f.base = e.ID, *e
	}
	for i := range f.inputs {
		in := textinput.New()
		in.Prompt = ""
		in.CharLimit = 4096
		f.inputs[i] = in
	}
	f.inputs[fTitle].SetValue(f.base.Title)
	f.inputs[fUser].SetValue(f.base.Username)
	f.inputs[fPass].SetValue(f.base.Password)
	f.inputs[fPass].EchoMode = textinput.EchoPassword
	f.inputs[fPass].EchoCharacter = '•'
	f.inputs[fURLs].SetValue(strings.Join(f.base.URLs, " "))
	f.inputs[fURLs].Placeholder = "space-separated"
	tags := make([]string, len(f.base.Tags))
	for i, t := range f.base.Tags {
		tags[i] = "#" + t
	}
	f.inputs[fTags].SetValue(strings.Join(tags, " "))
	f.inputs[fTags].Placeholder = "space-separated, e.g. #work"
	f.inputs[fOTP].EchoMode = textinput.EchoPassword
	f.inputs[fOTP].EchoCharacter = '•'
	if f.base.OTP != "" {
		f.inputs[fOTP].Placeholder = "set: empty keeps it, - removes it"
	} else {
		f.inputs[fOTP].Placeholder = "otpauth:// URI or base32 secret"
	}
	f.notes = textarea.New()
	f.notes.ShowLineNumbers = false
	f.notes.Prompt = ""
	f.notes.CharLimit = 0
	f.notes.SetValue(f.base.Notes)
	f.setFocus(fTitle)
	return f
}

func (f *form) setFocus(i int) {
	f.focus = (i + fieldCount) % fieldCount
	for j := range f.inputs {
		if j == f.focus {
			f.inputs[j].Focus()
		} else {
			f.inputs[j].Blur()
		}
	}
	if f.focus == fNotes {
		f.notes.Focus()
	} else {
		f.notes.Blur()
	}
}

func (f *form) toggleShow() {
	f.showPass = !f.showPass
	mode := textinput.EchoPassword
	if f.showPass {
		mode = textinput.EchoNormal
	}
	f.inputs[fPass].EchoMode = mode
	f.inputs[fOTP].EchoMode = mode
}

func (f *form) setPassword(p string) {
	f.inputs[fPass].SetValue(p)
	f.dirty = true
}

// update edits the focused field; tab/shift+tab move between fields.
func (f form) update(msg tea.KeyMsg) (form, tea.Cmd) {
	switch msg.String() {
	case "tab", "down":
		if msg.String() == "tab" || f.focus != fNotes {
			f.setFocus(f.focus + 1)
			return f, nil
		}
	case "shift+tab", "up":
		if msg.String() == "shift+tab" || f.focus != fNotes {
			f.setFocus(f.focus - 1)
			return f, nil
		}
	case "enter":
		if f.focus != fNotes {
			f.setFocus(f.focus + 1)
			return f, nil
		}
	}
	var cmd tea.Cmd
	if f.focus == fNotes {
		before := f.notes.Value()
		f.notes, cmd = f.notes.Update(msg)
		f.dirty = f.dirty || f.notes.Value() != before
		return f, cmd
	}
	before := f.inputs[f.focus].Value()
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	f.dirty = f.dirty || f.inputs[f.focus].Value() != before
	return f, cmd
}

// entry builds the edited entry. Fields the form does not show (custom
// fields, history, timestamps) come from the original.
func (f form) entry() (vault.Entry, error) {
	e := f.base
	e.Title = strings.TrimSpace(f.inputs[fTitle].Value())
	e.Username = strings.TrimSpace(f.inputs[fUser].Value())
	e.Password = f.inputs[fPass].Value()
	e.URLs = strings.Fields(f.inputs[fURLs].Value())
	e.Tags = nil
	seen := map[string]bool{}
	for _, t := range strings.Fields(f.inputs[fTags].Value()) {
		if t = strings.TrimPrefix(t, "#"); t != "" && !seen[t] {
			seen[t] = true
			e.Tags = append(e.Tags, t)
		}
	}
	e.Notes = strings.TrimRight(f.notes.Value(), "\n")
	if e.Title == "" {
		return vault.Entry{}, fmt.Errorf("title is required")
	}
	switch in := strings.TrimSpace(f.inputs[fOTP].Value()); in {
	case "":
		// keep what was there (nothing, for a new entry)
	case "-":
		e.OTP = ""
	default:
		uri, err := otp.Normalize(in, e.Title)
		if err != nil {
			return vault.Entry{}, fmt.Errorf("otp: %w", err)
		}
		e.OTP = uri
	}
	return e, nil
}

func (f form) view(width, height int) string {
	title := "New entry"
	if f.id != "" {
		title = "Edit: " + f.base.Title
	}
	lines := []string{bold.Render(trunc(title, width)), ""}
	inputWidth := max(10, width-labelWidth-5) // the cursor takes one more cell
	for i := range f.inputs {
		marker := " "
		if f.focus == i {
			marker = selStyle.Render("▌")
		}
		in := f.inputs[i]
		in.Width = inputWidth
		lines = append(lines, fmt.Sprintf("%s %s %s", marker, dim.Render(fmt.Sprintf("%-*s", labelWidth, fieldLabels[i])), in.View()))
	}
	marker := " "
	if f.focus == fNotes {
		marker = selStyle.Render("▌")
	}
	f.notes.SetWidth(inputWidth)
	f.notes.SetHeight(max(2, min(8, height-len(lines)-2)))
	notes := strings.Split(f.notes.View(), "\n")
	for i, l := range notes {
		label := ""
		if i == 0 {
			label = fieldLabels[fNotes]
		}
		m := " "
		if i == 0 {
			m = marker
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", m, dim.Render(fmt.Sprintf("%-*s", labelWidth, label)), l))
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}
