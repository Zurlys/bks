// Package tui is the bks terminal UI: search on the left, the selected
// entry on the right. Typing always searches; Enter copies the password.
//
// The model never decrypts or unlocks anything. It locks by quitting with
// Result.Lock set; the caller then replaces the process (re-exec), which
// is the only reliable way to wipe the vault from a Go process's memory.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/Zurlys/bks/internal/clipboard"
	"github.com/Zurlys/bks/internal/otp"
	"github.com/Zurlys/bks/internal/search"
	"github.com/Zurlys/bks/internal/vault"
)

const (
	sleepGap   = 30 * time.Second // wall-clock jump between ticks ⇒ the Mac slept
	revealFor  = 10 * time.Second
	statusFor  = 4 * time.Second
	mask       = "••••••••••••" // fixed length: never hints at the real one
	narrow     = 72             // below this width only one pane is shown
	labelWidth = 9
)

// Options configure a Model.
type Options struct {
	Vault *vault.Vault
	// Name is the vault's name, shown in the header (empty: none).
	Name string
	// CanSwitch: there are other vaults; ctrl-v ends the UI to switch.
	CanSwitch bool
	// Version is shown at the bottom right (empty: none).
	Version    string
	Clipboard  clipboard.Clipboard
	UnlockedAt time.Time
	// Now returns wall-clock time without a monotonic reading, so a sleep of
	// the Mac shows up as a jump. Defaults to time.Now().Round(0).
	Now func() time.Time
	// Events carries screen-lock events from bks-mac watch (nil: none).
	// Any event, or the channel closing, locks.
	Events <-chan string
	// Concealed says copies stay on this Mac and out of clipboard history.
	Concealed bool
	// Save persists the vault after an edit; nil makes the UI read-only.
	Save func() error
	// Generate makes a new password for the form's ^g.
	Generate func() (string, error)
}

// Result says why the TUI ended.
type Result struct {
	Lock   bool
	Reason string
	// Switch: wiped to open another vault (ctrl-v), not locked.
	Switch bool
}

type focus int

const (
	focusList focus = iota
	focusDetail
	focusForm    // editing or creating an entry
	focusConfirm // confirming a delete
)

type tickMsg struct{}

// screenEventMsg is an event from bks-mac watch; watcherStoppedMsg means
// the watcher died, so screen locks would go unnoticed.
type screenEventMsg string
type watcherStoppedMsg struct{}

var eventReasons = map[string]string{
	"locked":        "the screen locked",
	"screensaver":   "the screensaver started",
	"sleep":         "the Mac went to sleep",
	"display-sleep": "the display went to sleep",
	"switch":        "the user session was switched",
}

func waitEvent(ch <-chan string) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return watcherStoppedMsg{}
		}
		return screenEventMsg(ev)
	}
}

// Model is the Bubble Tea model.
type Model struct {
	opt                     Options
	idle, maxOpen, clearing time.Duration

	query   textinput.Model
	matches []search.Match
	sel     int // selected match
	top     int // first visible match
	focus   focus
	row     int // selected detail row

	revealRow   int
	revealUntil time.Time
	status      string
	statusUntil time.Time
	copied      string
	clearAt     time.Time

	lastInput time.Time
	lastTick  time.Time
	width     int
	height    int
	result    Result
	done      bool // the model asked the program to quit

	form      form
	discardAt time.Time // first esc on a changed form arms discarding until then
	returnTo  focus     // where to go back to after the form or confirm
}

// New builds the model for an unlocked vault.
func New(opt Options) Model {
	if opt.Now == nil {
		opt.Now = func() time.Time { return time.Now().Round(0) }
	}
	now := opt.Now()
	if opt.UnlockedAt.IsZero() {
		opt.UnlockedAt = now
	}
	q := textinput.New()
	q.Prompt = "> "
	q.Placeholder = "type to search · #tag"
	q.Focus()
	m := Model{
		opt:       opt,
		idle:      duration(opt.Vault.Settings.IdleLock, 5*time.Minute),
		maxOpen:   duration(opt.Vault.Settings.MaxUnlocked, 8*time.Hour),
		clearing:  duration(opt.Vault.Settings.ClipboardClear, 30*time.Second),
		query:     q,
		lastInput: now,
		lastTick:  now,
		revealRow: -1,
		width:     100,
		height:    30,
	}
	m.refilter()
	return m
}

func duration(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// Result is how the TUI ended; valid after the program quit.
func (m Model) Result() Result { return m.result }

// Done reports whether the model has asked the program to quit.
func (m Model) Done() bool { return m.done }

func (m Model) quit() (tea.Model, tea.Cmd) {
	m.done = true
	return m, tea.Quit
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

// Init starts the cursor blink, the one-second tick and the screen-lock
// event listener.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textinput.Blink, tick()}
	if m.opt.Events != nil {
		cmds = append(cmds, waitEvent(m.opt.Events))
	}
	return tea.Batch(cmds...)
}

func (m Model) lock(reason string) (tea.Model, tea.Cmd) {
	m.result = Result{Lock: true, Reason: reason}
	return m.quit()
}

// Update handles keys, ticks and resizes.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.scroll()
		return m, nil

	case screenEventMsg:
		if reason, ok := eventReasons[string(msg)]; ok {
			return m.lock(reason)
		}
		return m, waitEvent(m.opt.Events)

	case watcherStoppedMsg:
		return m.lock("the screen-lock watcher stopped")

	case tickMsg:
		now := m.opt.Now()
		switch {
		case now.Sub(m.lastTick) > sleepGap:
			return m.lock("the Mac slept")
		case now.Sub(m.lastInput) >= m.idle:
			return m.lock("idle for " + short(m.idle))
		case now.Sub(m.opt.UnlockedAt) >= m.maxOpen:
			return m.lock("unlocked for " + short(m.maxOpen))
		}
		m.lastTick = now
		return m, tick()

	case tea.KeyMsg:
		m.lastInput = m.opt.Now()
		switch msg.String() {
		case "ctrl+c":
			return m.quit()
		case "ctrl+l":
			return m.lock("locked with ctrl-l")
		}
		// A form or confirm prompt takes every other key: ^u and ^o edit
		// text there instead of copying.
		switch m.focus {
		case focusForm:
			return m.updateForm(msg)
		case focusConfirm:
			return m.updateConfirm(msg)
		}
		switch msg.String() {
		case "ctrl+n":
			return m.openForm(nil)
		case "ctrl+e":
			return m.openForm(m.current())
		case "ctrl+d":
			if e := m.current(); e != nil && m.editable() {
				m.returnTo, m.focus = m.focus, focusConfirm
			}
			return m, nil
		case "ctrl+o":
			m.copyOTP()
			return m, nil
		case "ctrl+u":
			if e := m.current(); e != nil {
				m.copy("username", e.Username)
			}
			return m, nil
		case "ctrl+v":
			// Like a lock (the process restarts, nothing decrypted
			// survives), then the vault picker instead of the lock screen.
			// With one vault, ctrl-v stays paste in the search box.
			if m.opt.CanSwitch {
				m.result = Result{Lock: true, Switch: true, Reason: "switching vaults"}
				return m.quit()
			}
		}
		if m.focus == focusDetail {
			return m.updateDetail(msg)
		}
		return m.updateList(msg)
	}
	var cmd tea.Cmd
	m.query, cmd = m.query.Update(msg)
	return m, cmd
}

func (m Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "ctrl+k", "ctrl+p":
		m.move(-1)
	case "down", "ctrl+j":
		m.move(1)
	case "pgup":
		m.move(-m.visible())
	case "pgdown":
		m.move(m.visible())
	case "enter":
		if e := m.current(); e != nil {
			m.copy("password", e.Password)
		}
	case "tab":
		if m.current() != nil {
			m.focus, m.row = focusDetail, 0
		}
	case "esc":
		if m.query.Value() == "" {
			return m.quit()
		}
		m.query.SetValue("")
		m.refilter()
	default:
		before := m.query.Value()
		var cmd tea.Cmd
		m.query, cmd = m.query.Update(msg)
		if m.query.Value() != before {
			m.refilter()
		}
		return m, cmd
	}
	return m, nil
}

func (m Model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.rows()
	switch msg.String() {
	case "up", "k", "ctrl+k", "ctrl+p":
		if m.row > 0 {
			m.row--
		}
	case "down", "j", "ctrl+j":
		if m.row < len(rows)-1 {
			m.row++
		}
	case "enter":
		if m.row < len(rows) {
			r := rows[m.row]
			m.copy(r.label, r.copy())
		}
	case "r":
		if m.row < len(rows) && rows[m.row].secret {
			if m.revealRow == m.row && m.opt.Now().Before(m.revealUntil) {
				m.revealRow = -1
			} else {
				m.revealRow, m.revealUntil = m.row, m.opt.Now().Add(revealFor)
			}
		}
	case "e":
		return m.openForm(m.current())
	case "tab", "esc", "left", "h":
		m.focus, m.revealRow = focusList, -1
	}
	return m, nil
}

func (m *Model) editable() bool {
	if m.opt.Save == nil {
		m.say("read-only: this vault cannot be saved")
		return false
	}
	return true
}

func (m Model) openForm(e *vault.Entry) (tea.Model, tea.Cmd) {
	if m.opt.Save == nil {
		m.say("read-only: this vault cannot be saved")
		return m, nil
	}
	m.returnTo = m.focus
	m.form, m.focus, m.revealRow = newForm(e), focusForm, -1
	return m, textinput.Blink
}

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+s":
		return m.saveForm()
	case "esc":
		now := m.opt.Now()
		if m.form.dirty && now.After(m.discardAt) {
			m.discardAt = now.Add(3 * time.Second)
			m.say("unsaved changes: esc again to discard, ^s to save")
			return m, nil
		}
		m.focus, m.status = m.returnTo, ""
		return m, nil
	case "ctrl+g":
		if m.opt.Generate == nil {
			return m, nil
		}
		p, err := m.opt.Generate()
		if err != nil {
			m.say("generate: " + err.Error())
			return m, nil
		}
		m.form.setPassword(p)
		m.say(fmt.Sprintf("generated a %d-character password", len([]rune(p))))
		return m, nil
	case "ctrl+r":
		m.form.toggleShow()
		return m, nil
	}
	var cmd tea.Cmd
	m.form, cmd = m.form.update(msg)
	return m, cmd
}

// saveForm applies the form to the vault and saves. On any error the vault
// is put back as it was and the form stays open with everything typed.
func (m Model) saveForm() (tea.Model, tea.Cmd) {
	e, err := m.form.entry()
	if err != nil {
		m.say(err.Error())
		return m, nil
	}
	v := m.opt.Vault
	snapshot := append([]vault.Entry(nil), v.Entries...)
	now := m.opt.Now()
	var saved vault.Entry
	if m.form.id == "" {
		saved, err = v.Add(e, now)
	} else {
		saved, err = v.Update(m.form.id, e, now)
	}
	if err == nil {
		err = m.opt.Save()
	}
	if err != nil {
		v.Entries = snapshot
		m.say("not saved: " + firstLine(err.Error()))
		return m, nil
	}
	m.focus = m.returnTo
	m.refilterKeep(saved.ID)
	m.say("saved " + saved.Title)
	return m, nil
}

func (m Model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := m.current()
	m.focus = m.returnTo
	if e == nil || (msg.String() != "y" && msg.String() != "Y") {
		m.say("not deleted")
		return m, nil
	}
	v := m.opt.Vault
	snapshot := append([]vault.Entry(nil), v.Entries...)
	tombstones := append([]vault.Tombstone(nil), v.Tombstones...)
	title := e.Title
	err := v.Delete(e.ID, m.opt.Now())
	if err == nil {
		err = m.opt.Save()
	}
	if err != nil {
		v.Entries, v.Tombstones = snapshot, tombstones
		m.say("not deleted: " + firstLine(err.Error()))
		return m, nil
	}
	m.focus = focusList
	m.refilterKeep("")
	m.say("deleted " + title)
	return m, nil
}

// refilterKeep re-runs the search and selects the entry with id if it is
// still listed.
func (m *Model) refilterKeep(id string) {
	sel := m.sel
	m.refilter()
	for i, match := range m.matches {
		if match.Entry.ID == id {
			m.sel = i
			m.scroll()
			return
		}
	}
	if id == "" && len(m.matches) > 0 { // after a delete stay near the old position
		m.sel = min(sel, len(m.matches)-1)
		m.scroll()
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func (m *Model) refilter() {
	m.matches = search.Search(m.opt.Vault.Entries, m.query.Value())
	m.sel, m.top, m.row, m.revealRow = 0, 0, 0, -1
}

func (m *Model) move(d int) {
	if len(m.matches) == 0 {
		return
	}
	m.sel = max(0, min(len(m.matches)-1, m.sel+d))
	m.row, m.revealRow = 0, -1
	m.scroll()
}

func (m *Model) scroll() {
	v := m.visible()
	if m.sel < m.top {
		m.top = m.sel
	}
	if m.sel >= m.top+v {
		m.top = m.sel - v + 1
	}
}

func (m Model) current() *vault.Entry {
	if m.sel < len(m.matches) {
		return m.matches[m.sel].Entry
	}
	return nil
}

func (m *Model) say(s string) {
	m.status, m.statusUntil = s, m.opt.Now().Add(statusFor)
}

func (m *Model) copy(label, value string) {
	if value == "" {
		m.say("nothing to copy: " + label + " is empty")
		return
	}
	if err := m.opt.Clipboard.Copy(value, m.clearing); err != nil {
		m.say("copy failed: " + err.Error())
		return
	}
	m.copied, m.clearAt, m.status = label, m.opt.Now().Add(m.clearing), ""
}

func (m *Model) copyOTP() {
	e := m.current()
	if e == nil {
		return
	}
	if e.OTP == "" {
		m.say(e.Title + " has no one-time code")
		return
	}
	t, err := otp.Parse(e.OTP)
	if err != nil {
		m.say("one-time code: " + err.Error())
		return
	}
	m.copy("one-time code", t.Code(m.opt.Now()))
}

// row is one line of the detail pane.
type row struct {
	label  string
	value  string
	secret bool
	otp    *otp.TOTP
	copy   func() string
}

func (m Model) rows() []row {
	e := m.current()
	if e == nil {
		return nil
	}
	var rs []row
	plain := func(label, v string) {
		if v != "" {
			rs = append(rs, row{label: label, value: v, copy: func() string { return v }})
		}
	}
	plain("username", e.Username)
	if e.Password != "" {
		pw := e.Password
		rs = append(rs, row{label: "password", value: pw, secret: true, copy: func() string { return pw }})
	}
	if t, err := otp.Parse(e.OTP); err == nil {
		now := m.opt.Now
		rs = append(rs, row{label: "one-time", otp: &t, copy: func() string { return t.Code(now()) }})
	}
	for _, u := range e.URLs {
		plain("url", u)
	}
	for _, f := range e.Fields {
		v := f.Value
		rs = append(rs, row{label: f.Name, value: v, secret: f.Secret, copy: func() string { return v }})
	}
	plain("notes", e.Notes)
	return rs
}

var (
	accent   = lipgloss.AdaptiveColor{Light: "#5A56E0", Dark: "#9D98FF"}
	dim      = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#8A8A8A", Dark: "#6C6C6C"})
	bold     = lipgloss.NewStyle().Bold(true)
	selStyle = lipgloss.NewStyle().Foreground(accent).Bold(true)
	okStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#56D364"})
	warn     = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#E3B341"})
	pane     = lipgloss.NewStyle().Padding(0, 1).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.AdaptiveColor{Light: "#C8C8C8", Dark: "#444444"})
	header   = lipgloss.NewStyle().Foreground(accent).Bold(true)
)

// paneHeight is the inner height of the two panes.
func (m Model) paneHeight() int { return max(3, m.height-6) }

// visible is how many entries fit in the list (two lines each).
func (m Model) visible() int { return max(1, m.paneHeight()/2) }

// View renders the screen.
func (m Model) View() string {
	if m.result.Lock {
		return ""
	}
	now := m.opt.Now()
	w := max(40, m.width)

	left := fmt.Sprintf(" %s", header.Render("bks"))
	if m.opt.Name != "" {
		left += dim.Render(" · ") + header.Render(m.opt.Name)
	}
	idleLeft := m.idle - now.Sub(m.lastInput)
	watch := ""
	if m.opt.Events == nil {
		watch = " · no screen-lock watch"
	}
	right := dim.Render(fmt.Sprintf("🔓 unlocked · idle lock %s%s ", clock(idleLeft), watch))
	top := left + strings.Repeat(" ", max(1, w-lipgloss.Width(left)-lipgloss.Width(right))) + right

	count := dim.Render(fmt.Sprintf("%d/%d", len(m.matches), len(m.opt.Vault.Entries)))
	m.query.Width = max(10, w-lipgloss.Width(count)-6)
	searchLine := " " + m.query.View()
	searchLine += strings.Repeat(" ", max(1, w-lipgloss.Width(searchLine)-lipgloss.Width(count)-1)) + count

	h := m.paneHeight()
	var body string
	if w < narrow {
		if m.focus == focusForm {
			body = pane.Width(w - 2).Height(h).Render(m.form.view(w-4, h))
		} else if m.focus == focusDetail {
			body = pane.Width(w - 2).Height(h).Render(m.detailView(w-4, h))
		} else {
			body = pane.Width(w - 2).Height(h).Render(m.listView(w-4, h))
		}
	} else {
		lw := max(28, w*2/5)
		rw := w - lw - 4
		body = lipgloss.JoinHorizontal(lipgloss.Top,
			pane.Width(lw).Height(h).Render(m.listView(lw-2, h)),
			pane.Width(rw).Height(h).Render(m.rightView(rw-2, h)))
	}

	status := ""
	switch {
	case m.status != "" && now.Before(m.statusUntil):
		status = warn.Render(trunc(m.status, w-2))
	case m.copied != "" && now.Before(m.clearAt):
		where := " (this Mac only)"
		if !m.opt.Concealed {
			where = " (also reaches other Apple devices)"
		}
		status = okStyle.Render(trunc(fmt.Sprintf("✓ %s copied%s · clipboard clears in %ds", m.copied, where, int(m.clearAt.Sub(now).Seconds()+0.5)), w-2))
	}
	help := "enter copy password · ^o otp · ^u user · tab fields · ^n new · ^e edit · ^d delete · ^l lock · esc quit"
	if m.opt.CanSwitch {
		help = strings.Replace(help, "^l lock", "^v vault · ^l lock", 1)
	}
	switch m.focus {
	case focusDetail:
		help = "↑↓ field · enter copy · r reveal · e edit · ^o otp · tab/esc back · ^l lock"
	case focusForm:
		help = "^s save · tab/shift+tab field · ^g generate · ^r show secrets · esc cancel"
	case focusConfirm:
		if e := m.current(); e != nil {
			status = warn.Render(trunc(fmt.Sprintf("Delete %q? y to delete, any other key keeps it", e.Title), w-2))
		}
		help = "y delete · any other key cancels"
	}
	// The version stays at the bottom right; the key hints give way.
	ver := m.opt.Version
	helpW := w - 2
	if ver != "" {
		helpW -= lipgloss.Width(ver) + 2
	}
	footer := " " + dim.Render(trunc(help, max(10, helpW)))
	if ver != "" {
		footer += strings.Repeat(" ", max(1, w-lipgloss.Width(footer)-lipgloss.Width(ver)-1)) + dim.Render(ver)
	}
	return strings.Join([]string{top, searchLine, body, " " + status, footer}, "\n")
}

// rightView is the detail pane, or the form while editing.
func (m Model) rightView(width, height int) string {
	if m.focus == focusForm {
		return m.form.view(width, height)
	}
	return m.detailView(width, height)
}

func (m Model) listView(width, height int) string {
	if len(m.matches) == 0 {
		if len(m.opt.Vault.Entries) == 0 {
			return dim.Render("empty vault: add entries with\nbks add --title …")
		}
		return dim.Render("no matches")
	}
	var b strings.Builder
	end := min(len(m.matches), m.top+m.visible())
	for i := m.top; i < end; i++ {
		e := m.matches[i].Entry
		title := trunc(e.Title, width-2)
		user := trunc(e.Username, width-2)
		if i == m.sel {
			marker := "▌"
			if m.focus == focusDetail {
				marker = "│"
			}
			fmt.Fprintf(&b, "%s %s\n%s %s\n", selStyle.Render(marker), selStyle.Render(title), selStyle.Render(marker), dim.Render(user))
		} else {
			fmt.Fprintf(&b, "  %s\n  %s\n", title, dim.Render(user))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m Model) detailView(width, height int) string {
	e := m.current()
	if e == nil {
		return ""
	}
	now := m.opt.Now()
	var tags []string
	for _, t := range e.Tags {
		tags = append(tags, "#"+t)
	}
	tagStr := dim.Render(strings.Join(tags, " "))
	title := bold.Render(trunc(e.Title, max(10, width-lipgloss.Width(tagStr)-2)))
	lines := []string{title + strings.Repeat(" ", max(1, width-lipgloss.Width(title)-lipgloss.Width(tagStr))) + tagStr, ""}

	valueWidth := max(8, width-labelWidth-3)
	for i, r := range m.rows() {
		marker := " "
		if m.focus == focusDetail && i == m.row {
			marker = selStyle.Render("▌")
		}
		label := dim.Render(fmt.Sprintf("%-*s", labelWidth, trunc(r.label, labelWidth)))
		var value string
		switch {
		case r.otp != nil:
			value = otpLine(*r.otp, now)
		case r.secret && !(i == m.revealRow && now.Before(m.revealUntil)):
			value = mask
		case r.label == "notes":
			first, rest, more := strings.Cut(r.value, "\n")
			value = trunc(first, valueWidth)
			if more && rest != "" {
				value += dim.Render(" …")
			}
		default:
			value = trunc(r.value, valueWidth)
		}
		if r.secret && value != mask && runewidth.StringWidth(r.value) > valueWidth {
			// a revealed secret is shown whole, wrapped, never cut off
			chunks := wrap(r.value, valueWidth)
			lines = append(lines, fmt.Sprintf("%s %s %s", marker, label, chunks[0]))
			for _, c := range chunks[1:] {
				lines = append(lines, fmt.Sprintf("  %s %s", strings.Repeat(" ", labelWidth), c))
			}
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", marker, label, value))
	}
	if e.Notes != "" && strings.Contains(e.Notes, "\n") {
		lines = append(lines, "")
		for _, l := range strings.Split(e.Notes, "\n") {
			if len(lines) >= height {
				break
			}
			lines = append(lines, dim.Render("  "+trunc(l, width-2)))
		}
	}
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}

// otpLine renders "482 913  ▰▰▰▰▰▰▱▱▱▱ 19s" and the next code near the end.
func otpLine(t otp.TOTP, now time.Time) string {
	left := t.Remaining(now)
	filled := int(float64(left) / float64(time.Duration(t.Period)*time.Second) * 10)
	bar := strings.Repeat("▰", filled) + strings.Repeat("▱", 10-filled)
	s := fmt.Sprintf("%s  %s %2ds", group(t.Code(now)), dim.Render(bar), int(left.Seconds()+0.5))
	if left <= 5*time.Second {
		s += dim.Render("  next " + group(t.Code(now.Add(left))))
	}
	return s
}

// group splits a code in two halves for reading: "482913" → "482 913".
func group(code string) string {
	h := len(code) / 2
	return code[:h] + " " + code[h:]
}

// wrap splits s into pieces at most w columns wide.
func wrap(s string, w int) []string {
	var out []string
	var cur strings.Builder
	cw := 0
	for _, r := range s {
		rw := runewidth.RuneWidth(r)
		if cw+rw > w && cw > 0 {
			out = append(out, cur.String())
			cur.Reset()
			cw = 0
		}
		cur.WriteRune(r)
		cw += rw
	}
	return append(out, cur.String())
}

func trunc(s string, w int) string {
	if w <= 0 {
		return ""
	}
	return runewidth.Truncate(s, w, "…")
}

func clock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

func short(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "0m")
}
