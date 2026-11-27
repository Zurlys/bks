package tui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Zurlys/bks/internal/otp"
	"github.com/Zurlys/bks/internal/vault"
)

type copyCall struct {
	value string
	after time.Duration
}

type fakeClipboard struct{ calls []copyCall }

func (f *fakeClipboard) Copy(v string, after time.Duration) error {
	f.calls = append(f.calls, copyCall{v, after})
	return nil
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func secret(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

const otpURI = "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP"

type harness struct {
	t       *testing.T
	m       Model
	clip    *fakeClipboard
	clock   *fakeClock
	pw      map[string]string // title → password
	saves   int
	saveErr error
	genPW   string
}

func newHarness(t *testing.T, settings ...func(*vault.Settings)) *harness {
	t.Helper()
	v, err := vault.New([]vault.Recipient{{Label: "t", Subkey: strings.Repeat("A", 40), PubKey: "k"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range settings {
		s(&v.Settings)
	}
	h := &harness{t: t, clip: &fakeClipboard{}, clock: &fakeClock{t: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}, pw: map[string]string{}}
	for _, e := range []vault.Entry{
		{Title: "GitLab (work)", Username: "jonas.petraitis@corp.example", Tags: []string{"work"}},
		{Title: "Grafana prod", Username: "admin", URLs: []string{"https://grafana.example"}},
		{Title: "GitHub", Username: "jonas", OTP: otpURI, Notes: "line one\nline two",
			Fields: []vault.Field{{Name: "recovery", Value: "rc-" + secret(t), Secret: true}}},
	} {
		e.Password = secret(t)
		h.pw[e.Title] = e.Password
		if _, err := v.Add(e, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	h.genPW = "gen-" + secret(t)
	h.m = New(Options{Vault: v, Clipboard: h.clip, Now: h.clock.now,
		Save:     func() error { h.saves++; return h.saveErr },
		Generate: func() (string, error) { return h.genPW, nil },
	})
	h.send(tea.WindowSizeMsg{Width: 110, Height: 30})
	return h
}

func (h *harness) send(msg tea.Msg) tea.Cmd {
	h.t.Helper()
	m, cmd := h.m.Update(msg)
	h.m = m.(Model)
	return cmd
}

func (h *harness) key(k tea.KeyType) tea.Cmd { return h.send(tea.KeyMsg{Type: k}) }

func (h *harness) typ(s string) {
	for _, r := range s {
		h.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (h *harness) lastCopy() string {
	if len(h.clip.calls) == 0 {
		return ""
	}
	return h.clip.calls[len(h.clip.calls)-1].value
}

// isQuit reports whether the model asked to quit. The returned tea.Cmd is
// never run: Bubble Tea's tick commands sleep when executed.
func isQuit(m Model) bool { return m.Done() }

func TestSearchAndCopyPassword(t *testing.T) {
	h := newHarness(t)
	h.typ("graf")
	if len(h.m.matches) != 1 || h.m.current().Title != "Grafana prod" {
		t.Fatalf("matches after 'graf': %d", len(h.m.matches))
	}
	h.key(tea.KeyEnter)
	if h.lastCopy() != h.pw["Grafana prod"] || h.clip.calls[0].after != 30*time.Second {
		t.Fatalf("copied %+v", h.clip.calls)
	}
	if v := h.m.View(); !strings.Contains(v, "password copied (also reaches other Apple devices) · clipboard clears in 30s") {
		t.Fatalf("status missing:\n%s", v)
	}
	h.clock.advance(31 * time.Second)
	if strings.Contains(h.m.View(), "clipboard clears") {
		t.Fatal("countdown still shown after clearing time")
	}
}

func TestSecretsHiddenUntilRevealed(t *testing.T) {
	h := newHarness(t)
	h.typ("github")
	view := h.m.View()
	for title, pw := range h.pw {
		if strings.Contains(view, pw) {
			t.Fatalf("password of %s visible", title)
		}
	}
	if !strings.Contains(view, mask) {
		t.Fatal("no mask shown")
	}
	h.key(tea.KeyTab)  // detail: username
	h.key(tea.KeyDown) // password
	h.typ("r")
	if !strings.Contains(h.m.View(), h.pw["GitHub"]) {
		t.Fatal("reveal did not show the password")
	}
	h.clock.advance(revealFor + time.Second)
	if strings.Contains(h.m.View(), h.pw["GitHub"]) {
		t.Fatal("password still visible after reveal timeout")
	}
	h.typ("r")
	h.key(tea.KeyEsc) // back to the list hides it at once
	if strings.Contains(h.m.View(), h.pw["GitHub"]) {
		t.Fatal("password visible after leaving the detail pane")
	}
}

func TestDetailCopyAndOTP(t *testing.T) {
	h := newHarness(t)
	h.typ("github")
	tp, _ := otp.Parse(otpURI)
	h.key(tea.KeyCtrlO)
	if h.lastCopy() != tp.Code(h.clock.now()) {
		t.Fatalf("otp copy = %q", h.lastCopy())
	}
	if v := h.m.View(); !strings.Contains(v, group(tp.Code(h.clock.now()))) {
		t.Fatalf("OTP code not shown:\n%s", v)
	}
	h.key(tea.KeyCtrlU)
	if h.lastCopy() != "jonas" {
		t.Fatalf("username copy = %q", h.lastCopy())
	}
	// detail rows: username, password, one-time, recovery, notes
	h.key(tea.KeyTab)
	h.key(tea.KeyDown)
	h.key(tea.KeyDown)
	h.key(tea.KeyEnter)
	if h.lastCopy() != tp.Code(h.clock.now()) {
		t.Fatalf("enter on one-time row copied %q", h.lastCopy())
	}
	h.key(tea.KeyDown)
	h.key(tea.KeyEnter)
	if !strings.HasPrefix(h.lastCopy(), "rc-") {
		t.Fatalf("custom secret field copy = %q", h.lastCopy())
	}
	// next code is announced near the end of the period
	h.clock.t = time.Unix(1_800_000_027, 0)
	if !strings.Contains(h.m.View(), "next "+group(tp.Code(time.Unix(1_800_000_030, 0)))) {
		t.Fatal("next code not shown in the last seconds")
	}
}

func TestOTPMissing(t *testing.T) {
	h := newHarness(t)
	h.typ("grafana")
	h.key(tea.KeyCtrlO)
	if len(h.clip.calls) != 0 || !strings.Contains(h.m.View(), "has no one-time code") {
		t.Fatal("ctrl-o without OTP should only explain")
	}
}

func TestLockTriggers(t *testing.T) {
	cases := map[string]struct {
		run    func(h *harness)
		reason string
	}{
		"ctrl-l": {func(h *harness) { h.key(tea.KeyCtrlL) }, "ctrl-l"},
		"idle": {func(h *harness) {
			for i := 0; i < 5*60 && !isQuit(h.m); i++ { // one tick per second, no keys
				h.clock.advance(time.Second)
				h.send(tickMsg{})
			}
		}, "idle for 5m"},
		"sleep": {func(h *harness) {
			h.clock.advance(45 * time.Second) // one tick after a long wall-clock gap
			h.send(tickMsg{})
		}, "slept"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			c.run(h)
			r := h.m.Result()
			if !isQuit(h.m) || !r.Lock || !strings.Contains(r.Reason, c.reason) {
				t.Fatalf("result %+v, quit %v", r, isQuit(h.m))
			}
			if h.m.View() != "" {
				t.Fatal("locked model still renders the vault")
			}
		})
	}
}

func TestMaxUnlockedLocksEvenWhenActive(t *testing.T) {
	h := newHarness(t, func(s *vault.Settings) { s.MaxUnlocked = "2m" })
	for i := 0; i < 200 && !isQuit(h.m); i++ {
		h.typ("x") // keep it busy: idle never fires
		h.key(tea.KeyBackspace)
		h.clock.advance(time.Second)
		h.send(tickMsg{})
	}
	if r := h.m.Result(); !r.Lock || !strings.Contains(r.Reason, "unlocked for 2m") {
		t.Fatalf("result %+v", r)
	}
}

func TestKeysResetIdle(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 10*60; i++ {
		if i%60 == 0 {
			h.key(tea.KeyDown)
		}
		h.clock.advance(time.Second)
		if h.send(tickMsg{}); isQuit(h.m) {
			t.Fatalf("locked after %ds despite activity: %+v", i, h.m.Result())
		}
	}
}

func TestEscClearsThenQuits(t *testing.T) {
	h := newHarness(t)
	h.typ("zzz")
	if len(h.m.matches) != 0 || !strings.Contains(h.m.View(), "no matches") {
		t.Fatal("expected no matches")
	}
	h.key(tea.KeyEsc)
	if isQuit(h.m) || h.m.query.Value() != "" || len(h.m.matches) != 3 {
		t.Fatal("first esc should clear the search")
	}
	h.key(tea.KeyEsc)
	if !isQuit(h.m) || h.m.Result().Lock {
		t.Fatal("second esc should quit without a lock")
	}
}

func TestNarrowTerminalShowsOnePane(t *testing.T) {
	h := newHarness(t)
	h.send(tea.WindowSizeMsg{Width: 60, Height: 20})
	v := h.m.View()
	if strings.Contains(v, "username") {
		t.Fatal("narrow list view should not show the detail pane")
	}
	h.key(tea.KeyTab)
	if !strings.Contains(h.m.View(), "username") {
		t.Fatal("tab should show the detail pane full width")
	}
	for _, line := range strings.Split(h.m.View(), "\n") {
		if w := len([]rune(stripANSI(line))); w > 60 {
			t.Fatalf("line wider than terminal (%d): %q", w, stripANSI(line))
		}
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'):
			esc = false
		case !esc:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestRevealedSecretIsWrappedNotCut(t *testing.T) {
	h := newHarness(t)
	long := secret(t) + "-" + secret(t) + "-" + secret(t) // ~75 chars, wider than the pane
	for i := range h.m.opt.Vault.Entries {
		if h.m.opt.Vault.Entries[i].Title == "GitHub" {
			h.m.opt.Vault.Entries[i].Password = long
		}
	}
	h.send(tea.WindowSizeMsg{Width: 80, Height: 24})
	h.typ("github")
	h.key(tea.KeyTab)
	h.key(tea.KeyDown)
	h.typ("r")
	flat := strings.Join(strings.Fields(strings.NewReplacer("│", " ", "▌", " ").Replace(stripANSI(h.m.View()))), "")
	if !strings.Contains(flat, strings.ReplaceAll(long, " ", "")) {
		t.Fatalf("revealed passphrase not shown in full:\n%s", stripANSI(h.m.View()))
	}
}

func TestScreenEventsLock(t *testing.T) {
	for event, reason := range eventReasons {
		h := newHarness(t)
		h.send(screenEventMsg(event))
		if r := h.m.Result(); !r.Lock || r.Reason != reason || !isQuit(h.m) {
			t.Errorf("%s: result %+v", event, r)
		}
	}
	h := newHarness(t)
	h.send(watcherStoppedMsg{})
	if r := h.m.Result(); !r.Lock || !strings.Contains(r.Reason, "watcher stopped") {
		t.Errorf("watcher stop: %+v", r)
	}
}

func TestEventsChannelFeedsTheModel(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "locked"
	if msg := waitEvent(ch)(); msg != screenEventMsg("locked") {
		t.Fatalf("got %#v", msg)
	}
	close(ch)
	if _, ok := waitEvent(ch)().(watcherStoppedMsg); !ok {
		t.Fatal("closed channel must report the watcher stopped")
	}
	// unknown events are ignored, not treated as a lock
	h := newHarness(t)
	h.m.opt.Events = make(chan string)
	h.send(screenEventMsg("something-new"))
	if h.m.Result().Lock {
		t.Fatal("unknown event locked")
	}
	if strings.Contains(h.m.View(), "no screen-lock watch") {
		t.Fatal("watch indicator shown although events are connected")
	}
}

func (h *harness) tabs(n int) {
	for i := 0; i < n; i++ {
		h.key(tea.KeyTab)
	}
}

func (h *harness) entry(title string) *vault.Entry {
	for i := range h.m.opt.Vault.Entries {
		if h.m.opt.Vault.Entries[i].Title == title {
			return &h.m.opt.Vault.Entries[i]
		}
	}
	return nil
}

func TestNewEntryViaForm(t *testing.T) {
	h := newHarness(t)
	h.send(tea.KeyMsg{Type: tea.KeyCtrlN})
	if h.m.focus != focusForm || !strings.Contains(h.m.View(), "New entry") {
		t.Fatal("ctrl-n did not open the form")
	}
	pw := secret(t)
	h.typ("Mail")
	h.key(tea.KeyTab)
	h.typ("me@mail.example")
	h.key(tea.KeyTab)
	h.typ(pw)
	if strings.Contains(h.m.View(), pw) {
		t.Fatal("password visible while typing")
	}
	h.key(tea.KeyTab)
	h.typ("https://mail.example")
	h.key(tea.KeyTab)
	h.typ("#mail personal #mail")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	e := h.entry("Mail")
	if e == nil || e.Username != "me@mail.example" || e.Password != pw || len(e.URLs) != 1 || strings.Join(e.Tags, ",") != "mail,personal" {
		t.Fatalf("entry: %+v", e)
	}
	if h.saves != 1 || h.m.focus != focusList || h.m.current().ID != e.ID || !strings.Contains(h.m.View(), "saved Mail") {
		t.Fatalf("after save: saves %d, focus %v, selected %v", h.saves, h.m.focus, h.m.current().Title)
	}
}

func TestFormTakesCopyKeys(t *testing.T) {
	h := newHarness(t)
	h.typ("github")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.send(tea.KeyMsg{Type: tea.KeyCtrlU}) // deletes the title text; must not copy
	h.send(tea.KeyMsg{Type: tea.KeyCtrlO})
	if len(h.clip.calls) != 0 {
		t.Fatalf("copy keys copied inside the form: %+v", h.clip.calls)
	}
	if h.m.form.inputs[fTitle].Value() != "" {
		t.Fatalf("ctrl-u did not edit the title: %q", h.m.form.inputs[fTitle].Value())
	}
}

func TestEditPasswordKeepsHistory(t *testing.T) {
	h := newHarness(t)
	old := h.pw["GitHub"]
	h.typ("github")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	if !strings.Contains(h.m.View(), "Edit: GitHub") {
		t.Fatal("edit form not shown")
	}
	h.tabs(2)
	h.send(tea.KeyMsg{Type: tea.KeyCtrlG})
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	e := h.entry("GitHub")
	if e.Password != h.genPW || len(e.History) != 1 || e.History[0].Password != old || e.OTP != otpURI {
		t.Fatalf("after edit: %+v", e)
	}
	if len(e.Fields) != 1 || e.Notes != "line one\nline two" {
		t.Fatal("edit lost custom fields or notes")
	}
}

func TestFailedSaveKeepsFormAndRollsBack(t *testing.T) {
	h := newHarness(t)
	h.saveErr = errors.New("the vault changed on disk since it was unlocked")
	h.typ("grafana")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.typ(" renamed")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if h.m.focus != focusForm || h.m.form.inputs[fTitle].Value() != "Grafana prod renamed" {
		t.Fatal("form was closed or lost the edit")
	}
	if h.entry("Grafana prod") == nil || h.entry("Grafana prod renamed") != nil {
		t.Fatal("vault not rolled back after a failed save")
	}
	if !strings.Contains(h.m.View(), "not saved: the vault changed on disk") {
		t.Fatal("error not shown")
	}
	h.saveErr = nil
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if h.entry("Grafana prod renamed") == nil {
		t.Fatal("retry after the error did not save")
	}
}

func TestDeleteNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	h.typ("grafana")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlD})
	if h.m.focus != focusConfirm || !strings.Contains(h.m.View(), `Delete "Grafana prod"?`) {
		t.Fatal("no confirmation asked")
	}
	h.typ("n")
	if h.entry("Grafana prod") == nil || h.saves != 0 {
		t.Fatal("deleted without y")
	}
	h.send(tea.KeyMsg{Type: tea.KeyCtrlD})
	h.typ("y")
	if h.entry("Grafana prod") != nil || h.saves != 1 || len(h.m.opt.Vault.Tombstones) != 1 {
		t.Fatal("not deleted after y")
	}
	if !strings.Contains(h.m.View(), "deleted Grafana prod") {
		t.Fatal("no confirmation message")
	}
}

func TestEscDiscardNeedsTwoPresses(t *testing.T) {
	h := newHarness(t)
	h.typ("github")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.typ("X")
	h.key(tea.KeyEsc)
	if h.m.focus != focusForm || !strings.Contains(h.m.View(), "unsaved changes") {
		t.Fatal("first esc on a changed form should warn")
	}
	h.key(tea.KeyEsc)
	if h.m.focus == focusForm || h.entry("GitHub") == nil || h.saves != 0 {
		t.Fatal("second esc should discard without saving")
	}
	// an unchanged form closes on the first esc
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.key(tea.KeyEsc)
	if h.m.focus == focusForm {
		t.Fatal("unchanged form needed two esc")
	}
}

func TestOTPInForm(t *testing.T) {
	h := newHarness(t)
	h.typ("grafana")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.tabs(5)
	h.typ("jbsw y3dp ehpk 3pxp")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if e := h.entry("Grafana prod"); !strings.HasPrefix(e.OTP, "otpauth://totp/") {
		t.Fatalf("otp not set: %q", e.OTP)
	}
	// empty keeps, "-" removes
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if h.entry("Grafana prod").OTP == "" {
		t.Fatal("empty otp field removed the code")
	}
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.tabs(5)
	h.typ("-")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if h.entry("Grafana prod").OTP != "" {
		t.Fatal("- did not remove the code")
	}
	// a bad secret is refused and the form stays open
	h.send(tea.KeyMsg{Type: tea.KeyCtrlE})
	h.tabs(5)
	h.typ("not base32!")
	h.send(tea.KeyMsg{Type: tea.KeyCtrlS})
	if h.m.focus != focusForm || !strings.Contains(h.m.View(), "otp:") {
		t.Fatal("bad otp not refused")
	}
}

func TestReadOnlyWithoutSave(t *testing.T) {
	h := newHarness(t)
	h.m.opt.Save = nil
	h.send(tea.KeyMsg{Type: tea.KeyCtrlN})
	if h.m.focus == focusForm || !strings.Contains(h.m.View(), "read-only") {
		t.Fatal("form opened without a save function")
	}
	h.send(tea.KeyMsg{Type: tea.KeyCtrlD})
	if h.m.focus == focusConfirm {
		t.Fatal("delete offered without a save function")
	}
}

func TestFormInNarrowTerminal(t *testing.T) {
	h := newHarness(t)
	h.send(tea.WindowSizeMsg{Width: 60, Height: 20})
	h.send(tea.KeyMsg{Type: tea.KeyCtrlN})
	v := h.m.View()
	if !strings.Contains(v, "New entry") {
		t.Fatal("form not shown in narrow mode")
	}
	for _, line := range strings.Split(v, "\n") {
		if w := len([]rune(stripANSI(line))); w > 60 {
			t.Fatalf("line wider than terminal (%d): %q", w, stripANSI(line))
		}
	}
}
