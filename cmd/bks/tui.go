package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/Zurlys/bks/internal/clipboard"
	"github.com/Zurlys/bks/internal/gen"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/store"
	"github.com/Zurlys/bks/internal/tui"
	"github.com/Zurlys/bks/internal/vaults"
)

// lockedEnv carries the lock reason into the re-executed process.
const lockedEnv = "BKS_LOCKED"

// cmdTUI unlocks the vault and runs the UI. When the UI locks, the process
// replaces itself with a fresh one (syscall.Exec): nothing that was
// decrypted survives, which a garbage-collected Go process can't otherwise
// guarantee. The fresh process starts at the lock screen.
func cmdTUI(ctx context.Context, sel string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("the UI needs a terminal; the commands above work in scripts")
	}
	setGPGTTY()
	reason := os.Getenv(lockedEnv)
	os.Unsetenv(lockedEnv)

	// Which vault: -v / $BKS_VAULT, the only one, or ask. A relock carries
	// the vault's path in $BKS_VAULT, so it reopens the same vault and
	// skips the picker and the iCloud reminder.
	e, cfg, err := loadConfig()
	if err != nil {
		return err
	}
	v, err := cfg.Resolve(e, sel, os.Getenv("BKS_STATE_DIR"))
	if errors.Is(err, vaults.ErrChoose) {
		v, err = pickVault(os.Stdout, readKey, e, cfg)
	}
	if reason == "" && err == nil {
		v, err = remindICloud(os.Stdout, readKey, e, cfg, v)
	}
	if errors.Is(err, errQuit) {
		return nil
	}
	if err != nil {
		return err
	}
	if reason == "" && v.Name != "" && len(cfg.Vaults) > 1 && cfg.LastUsed != v.Name {
		cfg.LastUsed = v.Name
		_ = cfg.Save(e) // only the picker's preselection
	}
	s, err := newStore(v)
	if err != nil {
		return err
	}

	// Warnings from unlocking (e.g. a passphrase saved in the Keychain)
	// would vanish under the full-screen UI: collect them and make the
	// person acknowledge them first.
	var warnings []string
	warn := s.Warn
	s.Warn = func(m string) { warnings = append(warnings, m) }
	defer func() { s.Warn = warn }()

	var sess *store.Session
	for {
		choice := byte('u')
		if reason != "" {
			if choice = lockScreen(reason, v.Name, s.TouchIDEnrolled()); choice == 'q' {
				return nil
			}
		}
		warnings = nil // only the warnings of the attempt that succeeds
		var err error
		if choice == 'g' || !s.TouchIDEnrolled() {
			fmt.Fprintln(os.Stderr, "bks: unlocking with GPG (a passphrase window opens)…")
			sess, err = s.UnlockGPG(ctx)
		} else {
			fmt.Fprintln(os.Stderr, "bks: unlocking with Touch ID…")
			sess, err = unlock(ctx, s)
		}
		if err == nil {
			break
		}
		if reason == "" { // first start: report and exit
			return err
		}
		reason = "unlock failed: " + firstLine(err.Error())
	}

	// Screen-lock events and a this-Mac-only, concealed clipboard need the
	// helper; without it say so plainly before the UI starts.
	cb := clipboard.System{}
	var events <-chan string
	stopWatch := func() {}
	if h, err := macos.FindHelper(); err == nil {
		cb.Helper = &h
		if ch, stop, err := h.Watch(); err == nil {
			events, stopWatch = ch, stop
		} else {
			warnings = append(warnings, "the screen-lock watcher did not start ("+err.Error()+"): bks will NOT lock when the screen locks")
		}
	} else {
		warnings = append(warnings, "the bks-mac helper is missing (run make): bks will NOT lock when the screen locks, and copies reach other Apple devices and clipboard history")
	}
	defer stopWatch()

	if len(warnings) > 0 {
		for _, w := range warnings {
			fmt.Fprintln(os.Stderr, "bks: warning:", w)
		}
		fmt.Fprint(os.Stderr, "\nPress Enter to continue, q to quit. ")
		if !waitEnter() {
			return nil
		}
	}

	save := func() error { return s.Save(ctx, sess) }
	if sess.ReadOnly {
		save = nil // this Mac's last good copy: viewing and copying only
	}
	m := tui.New(tui.Options{
		Vault: sess.Vault, Name: v.Name, Clipboard: cb, Concealed: cb.Concealed(), Events: events,
		UnlockedAt: time.Now().Round(0),
		Save:       save,
		Generate:   func() (string, error) { return gen.Password(24, true) },
	})
	final, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	res := final.(tui.Model).Result()
	if !res.Lock {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	stopWatch() // defers do not run across exec
	env := withEnv(withEnv(os.Environ(), "BKS_VAULT", v.Path), lockedEnv, res.Reason)
	return syscall.Exec(exe, []string{exe}, env)
}

// lockScreen shows why bks locked and returns 'u' (unlock: Touch ID when
// enrolled, else GPG), 'g' (GPG passphrase) or 'q' (quit).
func lockScreen(reason, name string, touchID bool) byte {
	fmt.Print("\033[H\033[2J")
	if name != "" {
		name = " (" + name + ")"
	}
	fmt.Printf("\n   🔒 bks%s is locked: %s\n\n", name, reason)
	if touchID {
		fmt.Print("   enter  unlock with Touch ID\n   g      use the GPG passphrase\n")
	} else {
		fmt.Print("   enter  unlock with GPG\n")
	}
	fmt.Print("   q      quit\n\n")
	for {
		switch k := readKey(); k {
		case '\r', '\n':
			return 'u'
		case 'g', 'G':
			return 'g'
		case 'q', 'Q', 3, 4, 27, 0:
			return 'q'
		}
	}
}

// waitEnter reads keys until Enter (true) or q/ctrl-c/ctrl-d/esc (false).
func waitEnter() bool {
	for {
		switch readKey() {
		case '\r', '\n':
			return true
		case 'q', 'Q', 3, 4, 27, 0:
			return false
		}
	}
}

// readKey reads one key in raw mode; 0 on error.
func readKey() byte {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return 0
	}
	defer term.Restore(fd, old)
	buf := make([]byte, 1)
	if n, err := os.Stdin.Read(buf); err != nil || n == 0 {
		return 0
	}
	return buf[0]
}

// setGPGTTY tells gpg-agent which terminal a text-mode pinentry should use
// (e.g. over SSH). The GUI pinentry on macOS does not need it.
func setGPGTTY() {
	if os.Getenv("GPG_TTY") != "" {
		return
	}
	cmd := exec.Command("tty")
	cmd.Stdin = os.Stdin
	if out, err := cmd.Output(); err == nil {
		os.Setenv("GPG_TTY", strings.TrimSpace(string(out)))
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
