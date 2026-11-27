// Package clipboard copies secrets and clears them again.
//
// With the bks-mac helper a copy stays on this Mac (no Universal
// Clipboard), is marked concealed/transient so clipboard-history tools skip
// it, and is cleared by pasteboard change count, so nothing ever reads the
// clipboard back. Without the helper it falls back to pbcopy/pbpaste and a
// hash comparison.
package clipboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zurlys/bks/internal/macos"
)

// ClearCommand is the hidden bks subcommand that runs ClearLater's work.
const ClearCommand = "_clipclear"

// maxPaste bounds how much clipboard content the clearer reads.
const maxPaste = 1 << 20

// Clipboard copies a value and arranges for it to be cleared.
type Clipboard interface {
	Copy(value string, clearAfter time.Duration) error
}

// System is the macOS clipboard, cleared by a detached bks process so the
// clearing survives the TUI quitting or locking.
type System struct {
	// Exe is the bks binary that runs ClearCommand; os.Executable when empty.
	Exe string
	// Helper is bks-mac; nil falls back to pbcopy.
	Helper *macos.Helper
}

// Concealed reports whether copies stay on this Mac and out of clipboard
// history (the helper is in use).
func (s System) Concealed() bool { return s.Helper != nil }

// Copy puts value on the clipboard and starts the delayed clear.
func (s System) Copy(value string, clearAfter time.Duration) error {
	if s.Helper != nil {
		n, err := s.Helper.Copy(context.Background(), value)
		if err != nil {
			return err
		}
		if clearAfter <= 0 {
			return nil
		}
		return s.clearLater("cc:"+strconv.Itoa(n), clearAfter)
	}
	if err := write(value); err != nil {
		return err
	}
	if clearAfter <= 0 {
		return nil
	}
	sum := sha256.Sum256([]byte(value))
	return s.clearLater(hex.EncodeToString(sum[:]), clearAfter)
}

// clearLater starts `bks _clipclear <seconds>` in its own session. Its
// token on stdin is either "cc:<pasteboard change count>" (helper) or the
// SHA-256 of the value (pbcopy): never the value itself, and nothing in
// argv that ps could show.
func (s System) clearLater(token string, after time.Duration) error {
	exe := s.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	// Write the token into a pipe before starting the clearer: it is in the
	// pipe buffer even if this process re-execs (locks) right away.
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	_, werr := w.WriteString(token)
	w.Close()
	if werr != nil {
		return werr
	}
	cmd := exec.Command(exe, ClearCommand, strconv.Itoa(int(after.Seconds()+0.5)))
	cmd.Stdin = r
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting clipboard clearer: %w", err)
	}
	go cmd.Wait() // reap it if we are still running when it finishes
	return nil
}

// RunClear is ClearCommand: read the token from stdin, wait, and clear the
// clipboard only if it still holds the copied value.
func RunClear(args []string, stdin io.Reader) error {
	if len(args) != 1 {
		return errors.New("usage: bks _clipclear <seconds>")
	}
	secs, err := strconv.Atoi(args[0])
	if err != nil || secs < 1 || secs > 3600 {
		return errors.New("bad delay")
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 128))
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(b))
	if cc, ok := strings.CutPrefix(token, "cc:"); ok {
		n, err := strconv.Atoi(cc)
		if err != nil || n < 0 {
			return errors.New("bad change count")
		}
		h, err := macos.FindHelper()
		if err != nil {
			return err
		}
		time.Sleep(time.Duration(secs) * time.Second)
		return h.ClearIf(context.Background(), n)
	}
	want, err := hex.DecodeString(token)
	if err != nil || len(want) != sha256.Size {
		return errors.New("bad hash")
	}
	time.Sleep(time.Duration(secs) * time.Second)
	return ClearIfUnchanged(want)
}

// ClearIfUnchanged empties the clipboard if its content hashes to want.
func ClearIfUnchanged(want []byte) error {
	cur, err := read()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(cur)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return nil // the person copied something else since: leave it
	}
	return write("")
}

// utf8Env makes pbcopy/pbpaste treat text as UTF-8 even when the caller's
// locale is unset (otherwise "č" can come out mangled).
func utf8Env() []string { return append(os.Environ(), "LANG=en_US.UTF-8", "LC_CTYPE=UTF-8") }

func write(value string) error {
	cmd := exec.Command("pbcopy")
	cmd.Env = utf8Env()
	cmd.Stdin = strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pbcopy: %v %s", err, bytes.TrimSpace(out))
	}
	return nil
}

func read() ([]byte, error) {
	cmd := exec.Command("pbpaste")
	cmd.Env = utf8Env()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(out, maxPaste))
	io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return b, rerr
}
