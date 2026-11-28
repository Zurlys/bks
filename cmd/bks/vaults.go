package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/store"
	"github.com/Zurlys/bks/internal/vaults"
)

// errQuit: the person quit at a prompt before unlocking.
var errQuit = errors.New("quit")

// timeMachine is swapped out in tests.
var timeMachine = macos.TimeMachine

// takeVaultFlag removes "-v <vault>" / "--vault <vault>" / "--vault=<vault>"
// from the front of args or right after the command.
func takeVaultFlag(args []string) ([]string, string, error) {
	for _, i := range []int{0, 1} {
		if i >= len(args) {
			break
		}
		a := args[i]
		var val string
		n := 0
		switch {
		case a == "-v" || a == "--vault" || a == "-vault":
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, "", fmt.Errorf("%s needs a vault name or path", a)
			}
			val, n = args[i+1], 2
		case strings.HasPrefix(a, "--vault="):
			val, n = strings.TrimPrefix(a, "--vault="), 1
		default:
			continue
		}
		rest := append(append([]string{}, args[:i]...), args[i+n:]...)
		return rest, val, nil
	}
	return args, "", nil
}

func loadConfig() (vaults.Env, *vaults.Config, error) {
	e, err := vaults.DefaultEnv()
	if err != nil {
		return e, nil, err
	}
	cfg, err := vaults.Load(e)
	return e, cfg, err
}

// openStore is the vault a command line works on: sel (-v or $BKS_VAULT),
// else the only one, else the default. It never guesses: several vaults
// and no default is exit code 2.
func openStore(sel string) (*store.Store, error) {
	e, cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	v, err := cfg.Resolve(e, sel, os.Getenv("BKS_STATE_DIR"))
	if errors.Is(err, vaults.ErrChoose) {
		d := cfg.Find(cfg.Default)
		if d == nil {
			return nil, exitError{2, err}
		}
		v, err = *d, nil
	}
	if err != nil {
		return nil, err
	}
	return newStore(v)
}

func newStore(v vaults.Vault) (*store.Store, error) {
	s, err := store.Open(v.Path, v.State)
	if err != nil {
		return nil, err
	}
	s.Confirm = confirm
	s.Warn = func(m string) { fmt.Fprintln(os.Stderr, "bks: warning:", m) }
	return s, nil
}

// stateFor picks a new vault's state directory and refuses one that still
// holds an earlier vault's pin (it would call the new vault forged).
func stateFor(e vaults.Env, v vaults.Vault, override string) (string, error) {
	st := e.StateFor(v.Name)
	switch {
	case override != "":
		return override, nil
	case v.Path == e.LegacyVault():
		st = e.LegacyState()
	}
	if _, err := os.Stat(filepath.Join(st, "device.json")); err == nil {
		return "", fmt.Errorf("the state directory %s belongs to an earlier vault; remove it, or choose another name", st)
	}
	return st, nil
}

// initArgs parses "bks init [<name>] [--name <name>] [--recipient <key>]...".
func initArgs(args []string) (name string, recipients []string, err error) {
	fs := flags("init")
	var rs multi
	fs.Var(&rs, "recipient", "GPG key (fingerprint or key ID) that can open the vault; repeatable")
	fs.StringVar(&name, "name", "", "name of the new vault")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	if fs.NArg() > 0 { // a name first, flags after it
		pos := fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return "", nil, err
		}
		if fs.NArg() > 0 || (name != "" && name != pos) {
			return "", nil, errors.New("usage: bks init [<name>] [--recipient <key>]...")
		}
		name = pos
	}
	return name, rs, nil
}

func cmdInit(ctx context.Context, sel string, args []string) error {
	name, recipients, err := initArgs(args)
	if err != nil {
		return err
	}
	if sel == "" {
		sel = os.Getenv("BKS_VAULT")
	}
	e, cfg, err := loadConfig()
	if err != nil {
		return err
	}
	want := vaults.Vault{Name: name}
	override := ""
	if sel != "" && vaults.IsPath(sel) {
		if want.Path, err = e.Expand(sel); err != nil {
			return err
		}
		override = os.Getenv("BKS_STATE_DIR")
	} else if sel != "" && want.Name == "" {
		want.Name = sel
	}
	if want.Name != "" {
		if err := vaults.ValidName(want.Name); err != nil {
			return err
		}
		if cfg.Find(want.Name) != nil {
			return fmt.Errorf("a vault named %q already exists (bks vault list)", want.Name)
		}
	}
	if o := cfg.FindPath(want.Path); want.Path != "" && o != nil {
		return fmt.Errorf("%s is already the vault %q", e.Display(want.Path), o.Name)
	}

	if len(recipients) == 0 {
		u, done, err := ttyUI()
		if err != nil {
			return err
		}
		defer done()
		v, existing, err := chooseLocation(u, e, cfg, want, override)
		if err != nil {
			return err
		}
		s, err := newStore(v)
		if err != nil {
			return err
		}
		if existing {
			return addExisting(ctx, u, e, cfg, v, s)
		}
		err = initInteractive(ctx, s, u)
		if rerr := remember(u.out, e, cfg, v); err == nil {
			err = rerr
		}
		return err
	}

	if want.Name == "" {
		if len(cfg.Vaults) > 0 {
			return errors.New("name the new vault: bks init --name <name> --recipient …")
		}
		want.Name = "personal"
	}
	if want.Path == "" {
		want.Path = e.LocalPath(want.Name)
		if e.ICloudAvailable() {
			want.Path = e.ICloudPath(want.Name)
		}
	}
	if want.State, err = stateFor(e, want, override); err != nil {
		return err
	}
	s, err := newStore(want)
	if err != nil {
		return err
	}
	sess, err := s.Init(ctx, recipients)
	if err != nil {
		return err
	}
	if err := remember(os.Stderr, e, cfg, want); err != nil {
		return err
	}
	return printRecipients(ctx, s, sess.Vault)
}

// remember adds a vault that now exists on disk to the config.
func remember(out io.Writer, e vaults.Env, cfg *vaults.Config, v vaults.Vault) error {
	if _, err := os.Stat(v.Path); err != nil || cfg.FindPath(v.Path) != nil {
		return nil
	}
	if err := cfg.Add(v); err != nil {
		return err
	}
	if err := cfg.Save(e); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nThe vault %q is at %s; bks remembers it in %s.\n", v.Name, e.Display(v.Path), e.Display(e.Config))
	if len(cfg.Vaults) > 1 {
		fmt.Fprintf(out, "Open it with: bks -v %s   (scripts: bks -v %s get …, or export BKS_VAULT=%s)\n", v.Name, v.Name, v.Name)
	}
	return nil
}

// chooseLocation asks for a new vault's name and place. existing: a vault
// file is already there (another Mac's, synced) and should be added.
func chooseLocation(u *ui, e vaults.Env, cfg *vaults.Config, v vaults.Vault, override string) (vaults.Vault, bool, error) {
	for v.Name == "" {
		def, prompt := "", "Name for the new vault (e.g. work): "
		if len(cfg.Vaults) == 0 {
			def, prompt = "personal", "Name for this vault [personal]: "
		}
		n, err := u.ask(prompt, def)
		if err != nil {
			return v, false, err
		}
		if err := vaults.ValidName(n); err != nil {
			u.say("%v\n", err)
		} else if cfg.Find(n) != nil {
			u.say("There is already a vault named %q.\n", n)
		} else {
			v.Name = n
		}
	}
	if v.Path == "" {
		p, err := askLocation(u, e, cfg, v.Name)
		if err != nil {
			return v, false, err
		}
		v.Path = p
	}

	existing := false
	inICloud := macos.ICloudSyncedUnder(v.Path, e.Home)
	dir, base := filepath.Split(v.Path)
	if _, err := os.Stat(v.Path); err == nil {
		u.say("\nThere is already a vault file at %s (from another Mac, or made earlier).\n", e.Display(v.Path))
		ok, err := u.yes("Add it to this Mac?", true)
		if err != nil {
			return v, false, err
		}
		if !ok {
			return v, false, errors.New("init cancelled; the file stays as it is")
		}
		existing = true
	} else if _, err := os.Stat(filepath.Join(dir, "."+base+".icloud")); err == nil {
		return v, false, fmt.Errorf("iCloud has %s but has not downloaded it to this Mac yet: open that folder in Finder, wait for the download, then run bks init again", e.Display(v.Path))
	} else if fi, err := os.Stat(dir); inICloud && err == nil && fi.IsDir() {
		u.say("\nThe folder %s exists but holds no vault yet. If another Mac already has this vault, iCloud may still be bringing it here.\n", e.Display(dir))
		ok, err := u.yes("Create a new, empty vault there anyway?", false)
		if err != nil {
			return v, false, err
		}
		if !ok {
			return v, false, errors.New("init cancelled: once iCloud Drive shows the vault here, run bks init again to add it")
		}
	} else if inICloud {
		u.say("\nIf this vault already exists on another Mac, stop here (Ctrl-C) and wait until iCloud Drive shows %s; then run bks init again to add it.\n", e.Display(v.Path))
	}
	if !existing {
		st, err := stateFor(e, v, override)
		v.State = st
		return v, false, err
	}
	switch {
	case override != "":
		v.State = override
	case v.Path == e.LegacyVault():
		v.State = e.LegacyState()
	default:
		v.State = e.StateFor(v.Name)
	}
	return v, true, nil
}

// askLocation offers iCloud Drive (when on), this Mac only, or a path.
func askLocation(u *ui, e vaults.Env, cfg *vaults.Config, name string) (string, error) {
	icloud := e.ICloudAvailable()
	local := e.LocalPath(name)
	u.say("\nWhere should the vault %q live?\n", name)
	choices := []string{}
	if icloud {
		u.say("  1) %s   synced to your Macs, kept by iCloud (recommended)\n", e.Display(e.ICloudPath(name)))
		choices = append(choices, "icloud")
	} else {
		u.say("  (iCloud Drive is off on this Mac. With it on, bks can keep the vault in iCloud Drive, synced to your other Macs.)\n")
	}
	u.say("  %d) %s   this Mac only\n", len(choices)+1, e.Display(local))
	choices = append(choices, "local")
	u.say("  %d) another folder (you type the path)\n", len(choices)+1)
	choices = append(choices, "other")

	for {
		a, err := u.ask("Choose [1]: ", "1")
		if err != nil {
			return "", err
		}
		i := 0
		if _, err := fmt.Sscanf(a, "%d", &i); err != nil || i < 1 || i > len(choices) {
			continue
		}
		switch choices[i-1] {
		case "icloud":
			return e.ICloudPath(name), nil
		case "local":
			u.say("%s\n", backupNote(e, local))
			return local, nil
		}
		p, err := u.ask("Path (a folder or a .gpg file): ", "")
		if err != nil {
			return "", err
		}
		if p == "" {
			continue
		}
		if p, err = e.Expand(p); err != nil {
			return "", err
		}
		if fi, err := os.Stat(p); (err == nil && fi.IsDir()) || !strings.HasSuffix(p, ".gpg") {
			p = filepath.Join(p, "vault.gpg")
		}
		if o := cfg.FindPath(p); o != nil {
			u.say("That is already the vault %q.\n", o.Name)
			continue
		}
		storage := filepath.Join(e.Home, "Library", "CloudStorage")
		switch {
		case strings.HasPrefix(p, storage+string(os.PathSeparator)) && !strings.HasPrefix(p, filepath.Join(storage, "Dropbox")):
			u.say("Note: bks merges the conflict copies of iCloud Drive, Dropbox and Syncthing only; with this service, edits made on two Macs at once can be lost.\n")
		case macos.ICloudSyncedUnder(p, e.Home) && !strings.HasPrefix(p, e.ICloudDrive()):
			u.say("Note: this folder is synced through Desktop & Documents; if that is turned off later, the file may move away from this path. %s is steadier.\n", e.Display(filepath.Join(e.ICloudDrive(), "bks")))
		case !macos.ICloudSyncedUnder(p, e.Home):
			u.say("%s\n", backupNote(e, p))
		}
		return p, nil
	}
}

// backupNote is what bks can say about backups of a vault outside iCloud.
func backupNote(e vaults.Env, path string) string {
	probe := path
	for probe != e.Home && probe != "/" {
		if _, err := os.Stat(probe); err == nil {
			break
		}
		probe = filepath.Dir(probe)
	}
	switch timeMachine(probe) {
	case macos.BackupNone:
		return "Only on this Mac, and bks sees no Time Machine backup: keep a copy of the vault file somewhere safe."
	case macos.BackupExcluded:
		return "Only on this Mac, and Time Machine skips this folder: keep a copy of the vault file somewhere safe."
	case macos.BackupIncluded:
		return "Only on this Mac; Time Machine backs it up."
	}
	return "Only on this Mac: make sure something backs up the vault file."
}

// addExisting adds a vault file that is already there: one unlock with the
// GPG key checks it and pins it to this Mac.
func addExisting(ctx context.Context, u *ui, e vaults.Env, cfg *vaults.Config, v vaults.Vault, s *store.Store) error {
	u.say("Unlocking it once with your GPG key, to check it and pin it to this Mac…\n")
	sess, err := s.UnlockGPG(ctx)
	if err != nil {
		return err
	}
	if err := cfg.Add(v); err != nil {
		return err
	}
	if err := cfg.Save(e); err != nil {
		return err
	}
	u.say("Added the vault %q (%d entries) at %s.\n", v.Name, len(sess.Vault.Entries), e.Display(v.Path))
	return offerTouchID(ctx, s, u, sess)
}

func cmdVault(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	e, cfg, err := loadConfig()
	if err != nil {
		return err
	}
	need := func(n int, use string) error {
		if len(args) != n {
			return fmt.Errorf("usage: bks vault %s", use)
		}
		return nil
	}
	find := func(name string) (*vaults.Vault, error) {
		if v := cfg.Find(name); v != nil {
			return v, nil
		}
		return nil, fmt.Errorf("no vault named %q (bks vault list)", name)
	}
	switch sub {
	case "list", "ls":
		printVaults(os.Stdout, e, cfg)
		return nil
	case "add":
		if err := need(2, "add <name> <path>"); err != nil {
			return err
		}
		p, err := e.Expand(args[1])
		if err != nil {
			return err
		}
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			p = filepath.Join(p, "vault.gpg")
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("no vault file at %s (to create a vault: bks init)", e.Display(p))
		}
		v := vaults.Vault{Name: args[0], Path: p}
		if err := vaults.ValidName(v.Name); err != nil {
			return err
		}
		v.State = e.StateFor(v.Name)
		if p == e.LegacyVault() {
			v.State = e.LegacyState()
		}
		if err := cfg.Add(v); err != nil {
			return err
		}
		if err := cfg.Save(e); err != nil {
			return err
		}
		fmt.Printf("Added the vault %q at %s. Its first unlock on this Mac asks you to trust (pin) it.\n", v.Name, e.Display(p))
		return nil
	case "move", "mv":
		if len(args) != 1 && len(args) != 2 {
			return errors.New("usage: bks vault move <name> [<path>]   (default: iCloud Drive/bks/<name>/vault.gpg)")
		}
		v, err := find(args[0])
		if err != nil {
			return err
		}
		dest := e.ICloudPath(v.Name)
		if len(args) == 2 {
			if dest, err = e.Expand(args[1]); err != nil {
				return err
			}
			if fi, err := os.Stat(dest); (err == nil && fi.IsDir()) || !strings.HasSuffix(dest, ".gpg") {
				dest = filepath.Join(dest, "vault.gpg")
			}
		} else if !e.ICloudAvailable() {
			return errors.New("iCloud Drive is off on this Mac: give a path, bks vault move <name> <path>")
		}
		_, err = moveVault(os.Stdout, e, cfg, v.Name, dest)
		return err
	case "rename":
		if err := need(2, "rename <name> <new-name>"); err != nil {
			return err
		}
		if err := cfg.Rename(args[0], args[1]); err != nil {
			return err
		}
		return cfg.Save(e)
	case "default":
		if err := need(1, "default <name>"); err != nil {
			return err
		}
		if _, err := find(args[0]); err != nil {
			return err
		}
		cfg.Default = args[0]
		return cfg.Save(e)
	case "remove", "rm":
		if err := need(1, "remove <name>"); err != nil {
			return err
		}
		v, err := find(args[0])
		if err != nil {
			return err
		}
		gone := *v
		if err := cfg.Remove(gone.Name); err != nil {
			return err
		}
		if err := cfg.Save(e); err != nil {
			return err
		}
		fmt.Printf("bks no longer lists %q. Nothing was deleted: the vault file stays at %s and this Mac's state for it at %s.\n",
			gone.Name, e.Display(gone.Path), e.Display(gone.State))
		return nil
	}
	return fmt.Errorf("unknown: bks vault %s (list, add, move, rename, default, remove)", sub)
}

func printVaults(out io.Writer, e vaults.Env, cfg *vaults.Config) {
	if len(cfg.Vaults) == 0 {
		fmt.Fprintln(out, "No vaults yet: bks init")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\tNAME\tWHERE\tPATH")
	for _, v := range cfg.Vaults {
		mark := ""
		if v.Name == cfg.Default {
			mark = "*"
		}
		where := "this Mac"
		switch _, err := os.Stat(v.Path); {
		case err != nil:
			where = "missing"
		case macos.ICloudSyncedUnder(v.Path, e.Home):
			where = "iCloud"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", mark, v.Name, where, e.Display(v.Path))
	}
	tw.Flush()
	if len(cfg.Vaults) > 1 {
		fmt.Fprintln(out, "\n* default for commands run without -v")
	}
}

// moveVault copies a vault to dest, checks the copy, points the config at
// it and renames the old file aside, so nothing opens the stale copy later.
func moveVault(out io.Writer, e vaults.Env, cfg *vaults.Config, name, dest string) (vaults.Vault, error) {
	v := cfg.Find(name)
	if v == nil {
		return vaults.Vault{}, fmt.Errorf("no vault named %q", name)
	}
	if dest == v.Path {
		return *v, fmt.Errorf("the vault %q is already at %s", name, e.Display(dest))
	}
	if o := cfg.FindPath(dest); o != nil {
		return *v, fmt.Errorf("%s is the vault %q", e.Display(dest), o.Name)
	}
	s, err := newStore(*v)
	if err != nil {
		return *v, err
	}
	if err := s.CopyTo(dest); err != nil {
		return *v, err
	}
	old := v.Path
	v.Path = dest
	if err := cfg.Save(e); err != nil {
		v.Path = old
		return *v, fmt.Errorf("could not save the list of vaults (%w); bks still uses %s, and the copy at %s can be deleted",
			err, e.Display(old), e.Display(dest))
	}
	fmt.Fprintf(out, "Moved the vault %q to %s (the copy was checked byte for byte).\n", name, e.Display(dest))
	aside, err := renameAside(old, ".moved-"+time.Now().Format("20060102-150405"))
	if err != nil {
		fmt.Fprintf(out, "Could not rename the old copy %s (%v): delete it once the new location works.\n", e.Display(old), err)
	} else {
		fmt.Fprintf(out, "The old copy is now %s; delete it (and %s, if there) once the new location works:\n  rm -f %q %q\n",
			e.Display(aside), e.Display(old+".bak"), aside, old+".bak")
	}
	fmt.Fprintf(out, "To move it back: bks vault move %s %q\n", name, old)
	return *v, nil
}

// renameAside renames a file within its own folder (os.Root: only the
// name changes, the folder cannot) and returns the new path.
func renameAside(path, suffix string) (string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.Rename(base, base+suffix); err != nil {
		return "", err
	}
	return filepath.Join(dir, base+suffix), nil
}

// pickVault asks which vault to open: the last used one is preselected,
// or, when switching away from the vault "from", another one.
func pickVault(out io.Writer, key func() byte, e vaults.Env, cfg *vaults.Config, from string) (vaults.Vault, error) {
	list := cfg.Vaults
	if len(list) > 9 {
		list = list[:9]
	}
	pre := 0
	for i, v := range list {
		if v.Name == cfg.LastUsed || (cfg.LastUsed == "" && v.Name == cfg.Default) {
			pre = i
		}
	}
	if list[pre].Name == from {
		for i, v := range list {
			if v.Name != from {
				pre = i
				break
			}
		}
	}
	fmt.Fprint(out, "\n   bks: which vault?\n\n")
	for i, v := range list {
		mark := ""
		if i == pre {
			mark = "  ←"
		}
		fmt.Fprintf(out, "   %d  %-16s %s%s\n", i+1, v.Name, e.Display(v.Path), mark)
	}
	fmt.Fprintf(out, "\n   enter  open %s   1–%d  choose   q  quit\n", list[pre].Name, len(list))
	for {
		switch k := key(); {
		case k == '\r' || k == '\n':
			return list[pre], nil
		case k >= '1' && int(k-'0') <= len(list):
			return list[k-'1'], nil
		case k == 'q' || k == 'Q' || k == 3 || k == 4 || k == 27 || k == 0:
			return vaults.Vault{}, errQuit
		}
	}
}

// remindICloud proposes moving a vault that lives only on this Mac into
// iCloud Drive, unless the person said not to remind them.
func remindICloud(out io.Writer, key func() byte, e vaults.Env, cfg *vaults.Config, v vaults.Vault) (vaults.Vault, error) {
	if v.Name == "" || v.NoICloudReminder || !e.ICloudAvailable() || macos.ICloudSyncedUnder(v.Path, e.Home) {
		return v, nil
	}
	dest := e.ICloudPath(v.Name)
	fmt.Fprintf(out, "\n   bks: the vault %q is not in iCloud Drive: %s\n   %s\n\n", v.Name, e.Display(v.Path), backupNote(e, v.Path))
	fmt.Fprintf(out, "   m      move it to %s (synced to your Macs, kept by iCloud)\n", e.Display(dest))
	fmt.Fprint(out, "   enter  not now\n   n      don't remind me again for this vault\n   q      quit\n")
	for {
		switch k := key(); k {
		case 'm', 'M':
			moved, err := moveVault(out, e, cfg, v.Name, dest)
			if err != nil {
				fmt.Fprintf(out, "   Not moved: %v\n", err)
				return v, nil
			}
			return moved, nil
		case 'n', 'N':
			if c := cfg.Find(v.Name); c != nil {
				c.NoICloudReminder = true
				if err := cfg.Save(e); err != nil {
					return v, err
				}
			}
			fmt.Fprintf(out, "   OK. To move it later: bks vault move %s\n", v.Name)
			v.NoICloudReminder = true
			return v, nil
		case '\r', '\n':
			return v, nil
		case 'q', 'Q', 3, 4, 27, 0:
			return v, errQuit
		}
	}
}

// withEnv returns env with key set to val (replacing any earlier value).
func withEnv(env []string, key, val string) []string {
	return append(withoutEnv(env, key), key+"="+val)
}

// withoutEnv returns env without key.
func withoutEnv(env []string, key string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}
