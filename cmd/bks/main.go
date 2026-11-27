// Command bks is a terminal password manager: a GPG-encrypted vault with
// fuzzy search, TOTP and (later) Touch ID unlock. See DESIGN.md.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/Zurlys/bks/internal/clipboard"
	"github.com/Zurlys/bks/internal/gen"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/otp"
	"github.com/Zurlys/bks/internal/search"
	"github.com/Zurlys/bks/internal/store"
	"github.com/Zurlys/bks/internal/vault"
)

const usage = `bks — terminal password manager

usage:
  bks                                               open the UI (type to search, enter copies)
  bks init                                          create the vault: pick or create a GPG key
  bks init --recipient <key> [--recipient <key>]   same, non-interactive (fingerprint or key ID)
  bks add --title <t> [--user <u>] [--url <url>]... [--tag <t>]... [--otp] [--notes <n>]
          [--generate <len> [--no-symbols] | --words <n> | --password-stdin] [--otp-stdin]
          --otp asks for the otpauth:// URI or base32 secret on the terminal (hidden);
          --otp-stdin reads it from stdin. Secrets are never taken as arguments.
  bks get [-f password|user|url|notes|otp|<field>] <query>   print one field of exactly one entry
  bks otp <query>                                   print the current one-time code
  bks ls [<query>]                                  list entries (no secrets)
  bks gen [-l <len>] [--no-symbols] | --words <n> [--sep <s>]   generate a password (no vault needed)
  bks recipients [list]                             show who can open the vault
  bks recipients add <key>                          add another GPG key (e.g. a backup)
  bks recipients remove <key|label>                 remove one; rotates the unlock secret
  bks rotate                                        new unlock secret (other Macs confirm once)
  bks import 1password <file.1pux> [--dry-run] [--archived]
                                                    import a 1Password export (try --dry-run first)
  bks touchid [status|enroll|remove]                Touch ID unlock on this Mac
  bks version

unlocking: Touch ID when enrolled (its dialog offers "Use GPG passphrase"), else GPG.
BKS_UNLOCK=gpg skips Touch ID.

search: every word must match (fuzzy, any order, accents ignored); #tag matches tags only

environment:
  BKS_VAULT      vault file   (default ~/.local/share/bks/vault.gpg)
  BKS_STATE_DIR  per-Mac state (default ~/.local/state/bks)
`

// exitError carries a specific exit code.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }

func main() {
	harden()
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bks:", err)
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "--help":
			fmt.Print(usage)
			return nil
		case "version", "--version":
			fmt.Println("bks", buildVersion())
			return nil
		case clipboard.ClearCommand: // detached clipboard clearer, see internal/clipboard
			return clipboard.RunClear(args[1:], os.Stdin)
		}
	}
	s, err := store.Default()
	if err != nil {
		return err
	}
	s.Confirm = confirm
	s.Warn = func(m string) { fmt.Fprintln(os.Stderr, "bks: warning:", m) }

	if len(args) == 0 {
		return cmdTUI(ctx, s)
	}
	switch args[0] {
	case "init":
		return cmdInit(ctx, s, args[1:])
	case "add":
		return cmdAdd(ctx, s, args[1:])
	case "get":
		return cmdGet(ctx, s, args[1:])
	case "otp":
		return cmdOTP(ctx, s, args[1:])
	case "gen":
		return cmdGen(args[1:])
	case "ls", "list":
		return cmdList(ctx, s, args[1:])
	case "recipients":
		return cmdRecipients(ctx, s, args[1:])
	case "touchid":
		return cmdTouchID(ctx, s, args[1:])
	case "rotate":
		return cmdRotate(ctx, s)
	case "import":
		return cmdImport(ctx, s, args[1:])
	}
	return fmt.Errorf("unknown command %q (see bks help)", args[0])
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("bks "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func cmdInit(ctx context.Context, s *store.Store, args []string) error {
	fs := flags("init")
	var recipients multi
	fs.Var(&recipients, "recipient", "GPG key (fingerprint or key ID) that can open the vault; repeatable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(recipients) == 0 {
		u, done, err := ttyUI()
		if err != nil {
			return err
		}
		defer done()
		return initInteractive(ctx, s, u)
	}
	sess, err := s.Init(ctx, recipients)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "created %s\n", s.VaultPath)
	return printRecipients(ctx, s, sess.Vault)
}

// unlock opens the vault: with Touch ID when it is enrolled on this Mac
// (its dialog offers "Use GPG passphrase"), otherwise with GPG via
// pinentry. BKS_UNLOCK=gpg skips Touch ID.
func unlock(ctx context.Context, s *store.Store) (*store.Session, error) {
	if !s.TouchIDEnrolled() || os.Getenv("BKS_UNLOCK") == "gpg" {
		return s.UnlockGPG(ctx)
	}
	h, err := macos.FindHelper()
	if err != nil {
		warn(s, "Touch ID is enrolled but %v; using GPG", err)
		return s.UnlockGPG(ctx)
	}
	sess, err := s.UnlockTouchID(ctx, h)
	switch {
	case err == nil:
		return sess, nil
	case errors.Is(err, macos.ErrTouchIDCancelled):
		return nil, errors.New("unlock cancelled")
	case errors.Is(err, store.ErrForged):
		return nil, err
	case errors.Is(err, macos.ErrTouchIDFallback):
		// the person chose the GPG passphrase
	case errors.Is(err, macos.ErrTouchIDUnavailable):
		warn(s, "%v. Using GPG; after a fingerprint change run: bks touchid enroll", err)
	default:
		warn(s, "Touch ID unlock failed (%v); using GPG", err)
	}
	return s.UnlockGPG(ctx)
}

func warn(s *store.Store, format string, a ...any) {
	if s.Warn != nil {
		s.Warn(fmt.Sprintf(format, a...))
	}
}

func cmdTouchID(ctx context.Context, s *store.Store, args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		if s.TouchIDEnrolled() {
			fmt.Println("Touch ID: enrolled on this Mac")
		} else {
			fmt.Println("Touch ID: not enrolled on this Mac (bks touchid enroll)")
		}
		if h, err := macos.FindHelper(); err != nil {
			fmt.Println("helper:   missing (run make): no Touch ID, no screen-lock watch, copies reach other devices")
		} else {
			fmt.Println("helper:  ", h.Path)
		}
		return nil
	case "enroll":
		h, err := macos.FindHelper()
		if err != nil {
			return err
		}
		sess, err := unlock(ctx, s)
		if err != nil {
			return err
		}
		if err := s.EnrollTouchID(ctx, sess, h); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Touch ID enrolled on this Mac. Adding or removing a fingerprint disables it")
		fmt.Fprintln(os.Stderr, "(re-run bks touchid enroll then); the GPG passphrase always works.")
		return nil
	case "remove":
		if err := s.RemoveTouchID(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Touch ID removed on this Mac; unlocking now uses GPG.")
		return nil
	}
	return errors.New("usage: bks touchid [status|enroll|remove]")
}

func cmdAdd(ctx context.Context, s *store.Store, args []string) error {
	fs := flags("add")
	var e vault.Entry
	var urls, tags multi
	fs.StringVar(&e.Title, "title", "", "entry title (required)")
	fs.StringVar(&e.Username, "user", "", "username")
	fs.Var(&urls, "url", "URL; repeatable")
	fs.Var(&tags, "tag", "tag; repeatable")
	askOTP := fs.Bool("otp", false, "ask for an otpauth:// URI on the terminal (hidden)")
	fs.StringVar(&e.Notes, "notes", "", "notes")
	genLen := fs.Int("generate", 0, "generate a password of this length")
	noSymbols := fs.Bool("no-symbols", false, "with --generate: letters and digits only")
	words := fs.Int("words", 0, "generate a passphrase of this many EFF words")
	fromStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	otpStdin := fs.Bool("otp-stdin", false, "read the otpauth:// URI or base32 secret from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(e.Title) == "" {
		return errors.New("add: --title is required")
	}
	e.URLs, e.Tags = urls, tags
	for i, t := range e.Tags {
		e.Tags[i] = strings.TrimPrefix(t, "#")
	}

	var err error
	switch {
	case (*genLen > 0) && (*words > 0) || (*genLen > 0 || *words > 0) && *fromStdin:
		return errors.New("add: use one of --generate, --words or --password-stdin")
	case *fromStdin && *otpStdin:
		return errors.New("add: --password-stdin and --otp-stdin both read stdin; use --otp for a hidden prompt")
	case *genLen > 0:
		e.Password, err = gen.Password(*genLen, !*noSymbols)
	case *words > 0:
		e.Password, err = gen.Passphrase(*words, "-")
	case *fromStdin:
		e.Password, err = readStdinPassword()
	default:
		e.Password, err = promptPassword()
	}
	if err != nil {
		return err
	}
	if *askOTP || *otpStdin {
		var in string
		if *otpStdin {
			in, err = readStdinPassword()
		} else {
			in, err = promptHidden("otpauth:// URI or base32 secret: ")
		}
		if err != nil {
			return err
		}
		if e.OTP, err = otp.Normalize(in, e.Title); err != nil {
			return err
		}
	}

	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	added, err := sess.Vault.Add(e, time.Now())
	if err != nil {
		return err
	}
	if err := s.Save(ctx, sess); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "added %q (%s)\n", added.Title, added.ID)
	return nil
}

func cmdGet(ctx context.Context, s *store.Store, args []string) error {
	fs := flags("get")
	field := fs.String("f", "password", "field: password, user, url, notes, title or a custom field name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(query) == "" {
		return errors.New("get: a query is required")
	}
	if strings.EqualFold(*field, "otp") {
		return printOTP(ctx, s, query)
	}
	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	e, err := pickOne(sess.Vault, query, nil)
	if err != nil {
		return err
	}
	val, ok := e.Field(*field)
	if !ok {
		return exitError{2, fmt.Errorf("%q has no field %q", e.Title, *field)}
	}
	fmt.Println(val)
	return nil
}

// pickOne returns the single entry matching query (and keep, when set); an
// exact title match (ignoring case and accents) wins over fuzzy matches. It
// never guesses between several fuzzy matches: get prints secrets.
func pickOne(v *vault.Vault, query string, keep func(*vault.Entry) bool) (*vault.Entry, error) {
	all := search.Find(v, query)
	var matches []*vault.Entry
	for _, m := range all {
		if keep == nil || keep(m) {
			matches = append(matches, m)
		}
	}
	if len(matches) == 0 && len(all) == 1 {
		return nil, exitError{2, fmt.Errorf("%q has no one-time code", all[0].Title)}
	}
	if len(matches) == 0 && len(all) > 1 {
		return nil, exitError{2, fmt.Errorf("%d entries match %q, none has a one-time code", len(all), query)}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	var exact []*vault.Entry
	for _, m := range matches {
		if search.Normalize(m.Title) == search.Normalize(strings.TrimSpace(query)) {
			exact = append(exact, m)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(matches) == 0 {
		return nil, exitError{2, fmt.Errorf("no entry matches %q", query)}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d entries match %q, be more specific:", len(matches), query)
	for i, m := range matches {
		if i == 10 {
			fmt.Fprintf(&b, "\n  … and %d more", len(matches)-10)
			break
		}
		fmt.Fprintf(&b, "\n  %s  %s", m.Title, m.Username)
	}
	return nil, exitError{2, errors.New(b.String())}
}

func cmdOTP(ctx context.Context, s *store.Store, args []string) error {
	query := strings.Join(args, " ")
	if strings.TrimSpace(query) == "" {
		return errors.New("otp: a query is required")
	}
	return printOTP(ctx, s, query)
}

// printOTP prints the current code of the one matching entry that has OTP;
// validity (and the next code when it is about to change) go to stderr.
func printOTP(ctx context.Context, s *store.Store, query string) error {
	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	e, err := pickOne(sess.Vault, query, func(e *vault.Entry) bool { return e.OTP != "" })
	if err != nil {
		return err
	}
	t, err := otp.Parse(e.OTP)
	if err != nil {
		return fmt.Errorf("%q: %w", e.Title, err)
	}
	now := time.Now()
	left := t.Remaining(now)
	fmt.Println(t.Code(now))
	msg := fmt.Sprintf("%s: valid %ds more", e.Title, int(left.Seconds()+0.5))
	if left <= 5*time.Second {
		msg += ", next: " + t.Code(now.Add(left))
	}
	fmt.Fprintln(os.Stderr, msg)
	return nil
}

func cmdGen(args []string) error {
	fs := flags("gen")
	n := fs.Int("l", 24, "password length")
	noSymbols := fs.Bool("no-symbols", false, "letters and digits only")
	words := fs.Int("words", 0, "generate a passphrase of this many EFF words instead")
	sep := fs.String("sep", "-", "passphrase word separator")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var p string
	var bits float64
	var err error
	if *words > 0 {
		p, err = gen.Passphrase(*words, *sep)
		bits = gen.PassphraseBits(*words)
	} else {
		p, err = gen.Password(*n, !*noSymbols)
		bits = gen.PasswordBits(*n, !*noSymbols)
	}
	if err != nil {
		return err
	}
	fmt.Println(p)
	fmt.Fprintf(os.Stderr, "≈%.0f bits of entropy\n", bits)
	return nil
}

func cmdList(ctx context.Context, s *store.Store, args []string) error {
	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for _, e := range search.Find(sess.Vault, strings.Join(args, " ")) {
		tags := ""
		for _, t := range e.Tags {
			tags += "#" + t + " "
		}
		otp := ""
		if e.OTP != "" {
			otp = "otp"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Title, e.Username, strings.TrimSpace(tags), otp)
	}
	return tw.Flush()
}

func cmdRecipients(ctx context.Context, s *store.Store, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		sess, err := unlock(ctx, s)
		if err != nil {
			return err
		}
		return printRecipients(ctx, s, sess.Vault)
	}
	if args[0] == "add" && len(args) == 2 {
		sess, err := unlock(ctx, s)
		if err != nil {
			return err
		}
		r, err := s.AddRecipient(ctx, sess, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "added recipient %s (subkey %s)\n", r.Label, r.Subkey)
		return printRecipients(ctx, s, sess.Vault)
	}
	if args[0] == "remove" && len(args) == 2 {
		sess, err := unlock(ctx, s)
		if err != nil {
			return err
		}
		r, touch, err := s.RemoveRecipient(ctx, sess, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "removed recipient %s (subkey %s) and rotated the unlock secret\n", r.Label, r.Subkey)
		fmt.Fprintln(os.Stderr, "other Macs will ask once to accept the rotation; old copies (backups, git history) still open with the removed key")
		reenrollTouchID(ctx, s, sess, touch)
		return printRecipients(ctx, s, sess.Vault)
	}
	return errors.New("usage: bks recipients [list] | add <key> | remove <key|label>")
}

func cmdRotate(ctx context.Context, s *store.Store) error {
	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	touch, err := s.Rotate(ctx, sess)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "rotated the vault's unlock secret; other Macs will ask once to accept it")
	reenrollTouchID(ctx, s, sess, touch)
	return nil
}

// reenrollTouchID seals the new unlock secret after a rotation, when Touch
// ID was enrolled before. Sealing needs no prompt.
func reenrollTouchID(ctx context.Context, s *store.Store, sess *store.Session, wasEnrolled bool) {
	if !wasEnrolled {
		return
	}
	h, err := macos.FindHelper()
	if err == nil {
		err = s.EnrollTouchID(ctx, sess, h)
	}
	if err != nil {
		warn(s, "Touch ID is off after the rotation (%v): run bks touchid enroll", err)
		return
	}
	fmt.Fprintln(os.Stderr, "Touch ID re-enrolled for the new secret")
}

func printRecipients(ctx context.Context, s *store.Store, v *vault.Vault) error {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RECIPIENT\tSUBKEY\tEXPIRES\t")
	for _, r := range v.Recipients {
		expires, note := "?", ""
		if k, err := s.RecipientKey(ctx, r); err == nil {
			expires = "never"
			if !k.Expires.IsZero() {
				expires = k.Expires.Format("2006-01-02")
			}
			if macos.GnuPGPassphraseSaved(k.Keygrip) {
				note = "passphrase saved in macOS Keychain: GPG unlock will not ask"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Label, r.Subkey, expires, note)
	}
	return tw.Flush()
}

// confirm asks a yes/no question on the terminal, never on stdin/stdout.
func confirm(question string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s [y/N] ", question)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

// promptHidden reads one line from the terminal without echo. Secrets are
// never taken as arguments: those end up in shell history and ps.
func promptHidden(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no terminal to ask on")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return strings.TrimSpace(string(b)), err
}

// promptPassword asks twice; an empty answer generates a password.
func promptPassword() (string, error) {
	p, err := promptHidden("Password (empty = generate 24 chars): ")
	if err != nil {
		return "", fmt.Errorf("%w: use --generate or --password-stdin", err)
	}
	if p == "" {
		return gen.Password(24, true)
	}
	again, err := promptHidden("Repeat: ")
	if err != nil {
		return "", err
	}
	if again != p {
		return "", errors.New("passwords do not match")
	}
	return p, nil
}

func readStdinPassword() (string, error) {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return "", err
	}
	p := strings.TrimRight(string(b), "\r\n")
	if p == "" {
		return "", errors.New("empty password on stdin")
	}
	return p, nil
}
