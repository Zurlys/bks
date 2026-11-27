package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Zurlys/bks/internal/importer"
	"github.com/Zurlys/bks/internal/macos"
	"github.com/Zurlys/bks/internal/store"
	"github.com/Zurlys/bks/internal/vault"
)

// cmdImport: bks import 1password <file.1pux> [--dry-run] [--archived]
func cmdImport(ctx context.Context, s *store.Store, args []string) error {
	if len(args) == 0 || args[0] != "1password" {
		return errors.New("usage: bks import 1password <file.1pux> [--dry-run] [--archived]")
	}
	fs := flags("import 1password")
	dry := fs.Bool("dry-run", false, "show what would be imported (no secrets), change nothing")
	archived := fs.Bool("archived", false, "also import archived items")
	var path string
	rest := args[1:]
	for len(rest) > 0 { // flags may come before or after the file
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if rest = fs.Args(); len(rest) > 0 {
			if path != "" {
				return errors.New("import: one export file at a time")
			}
			path, rest = rest[0], rest[1:]
		}
	}
	if path == "" {
		return errors.New("import: which .1pux file?")
	}
	path = expandHome(path)
	if macos.ICloudSynced(path) {
		fmt.Fprintln(os.Stderr, "bks: warning: this export holds every secret in plain text and sits in a folder")
		fmt.Fprintln(os.Stderr, "bks: warning: macOS syncs to iCloud, so it is being uploaded. Move it out, e.g. to ~/")
	}
	r, err := importer.Parse1PUX(path, *archived)
	if err != nil {
		return err
	}
	printPlan(os.Stdout, r, *dry)
	if *dry {
		return nil
	}
	if len(r.Entries) == 0 {
		return nil
	}
	if !confirm(fmt.Sprintf("Import up to %d entries into %s?", len(r.Entries), s.VaultPath)) {
		return errors.New("import cancelled")
	}
	sess, err := unlock(ctx, s)
	if err != nil {
		return err
	}
	added, dup, err := importInto(ctx, s, sess, r)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "imported %d entries", added)
	if dup > 0 {
		fmt.Fprintf(os.Stderr, " (%d were already imported)", dup)
	}
	fmt.Fprintln(os.Stderr)
	if added > 0 && confirm("Delete the export file now? It holds every password in plain text.") {
		if err := os.Remove(path); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "deleted. Also empty the Trash, and check that no copy is in iCloud Drive, Downloads or a backup.")
	}
	return nil
}

// importInto adds the entries not imported before (by Source) and saves
// once. Original creation times are kept; `updated` is the import time.
func importInto(ctx context.Context, s *store.Store, sess *store.Session, r *importer.Result) (added, dup int, err error) {
	have := map[string]bool{}
	for _, e := range sess.Vault.Entries {
		if e.Source != "" {
			have[e.Source] = true
		}
	}
	snapshot := append([]vault.Entry(nil), sess.Vault.Entries...)
	now := time.Now()
	for _, e := range r.Entries {
		if e.Source != "" && have[e.Source] {
			dup++
			continue
		}
		created := e.Created
		a, err := sess.Vault.Add(e, now)
		if err != nil {
			sess.Vault.Entries = snapshot
			return 0, 0, fmt.Errorf("%q: %w", e.Title, err)
		}
		if !created.IsZero() && created.Before(now) {
			sess.Vault.Get(a.ID).Created = created
		}
		added++
	}
	if added == 0 {
		return 0, dup, nil
	}
	if err := s.Save(ctx, sess); err != nil {
		sess.Vault.Entries = snapshot
		return 0, 0, err
	}
	return added, dup, nil
}

// printPlan summarises an import without printing any secret value.
func printPlan(w io.Writer, r *importer.Result, detailed bool) {
	var cats []string
	for c := range r.Counts {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Fprintf(w, "1Password export: %d entries to import", len(r.Entries))
	if len(cats) > 0 {
		var parts []string
		for _, c := range cats {
			parts = append(parts, fmt.Sprintf("%d %s", r.Counts[c], c))
		}
		fmt.Fprintf(w, " (%s)", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	if detailed {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "\nTITLE\tUSERNAME\tURLS\tOTP\tHISTORY\tFIELDS\tTAGS")
		for _, e := range r.Entries {
			otp := ""
			if e.OTP != "" {
				otp = "yes"
			}
			var fields []string
			for _, f := range e.Fields {
				name := f.Name
				if f.Secret {
					name += "*"
				}
				fields = append(fields, name)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\t%s\n", e.Title, e.Username, len(e.URLs), otp, len(e.History),
				strings.Join(fields, ", "), strings.Join(e.Tags, " "))
		}
		tw.Flush()
		fmt.Fprintln(w, "(* = secret field; values are never shown here)")
	}
	if len(r.Partial) > 0 {
		fmt.Fprintf(w, "\nimported, but without (%d):\n", len(r.Partial))
		for _, sk := range r.Partial {
			fmt.Fprintf(w, "  %s — %s\n", sk.Title, sk.Reason)
		}
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "\nnot imported (%d):\n", len(r.Skipped))
		for _, sk := range r.Skipped {
			fmt.Fprintf(w, "  %s — %s\n", sk.Title, sk.Reason)
		}
	}
}
