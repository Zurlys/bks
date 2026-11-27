package macos

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// HelperName is the Swift helper binary, built next to bks.
const HelperName = "bks-mac"

var (
	ErrHelperMissing      = errors.New("bks-mac helper not found (build it with make)")
	ErrTouchIDCancelled   = errors.New("cancelled at the Touch ID prompt")
	ErrTouchIDFallback    = errors.New("GPG passphrase chosen instead of Touch ID")
	ErrTouchIDUnavailable = errors.New("this Mac cannot use Touch ID right now")
)

// Helper runs bks-mac.
type Helper struct{ Path string }

// FindHelper uses $BKS_HELPER, else the bks-mac built next to the
// (symlink-resolved) bks executable. It never searches PATH: the helper is
// handed the unlock secret and every copied password, so only the sibling
// binary from the same build is trusted.
func FindHelper() (Helper, error) {
	if p := os.Getenv("BKS_HELPER"); p != "" { // explicit: no other lookups
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return Helper{}, fmt.Errorf("%w at BKS_HELPER=%s", ErrHelperMissing, p)
		}
		return Helper{p}, nil
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			p := filepath.Join(filepath.Dir(real), HelperName)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return Helper{p}, nil
			}
		}
	}
	return Helper{}, ErrHelperMissing
}

// run executes the helper with stdin; exit codes map to Touch ID errors.
func (h Helper) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, h.Path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(stderr.String()), "bks-mac: "))
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		switch ee.ExitCode() {
		case 2:
			return nil, ErrTouchIDCancelled
		case 3:
			return nil, ErrTouchIDFallback
		case 4:
			return nil, fmt.Errorf("%w: %s", ErrTouchIDUnavailable, msg)
		}
		return nil, fmt.Errorf("bks-mac %s: %s", args[0], msg)
	}
	if err != nil {
		return nil, fmt.Errorf("bks-mac %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

type blob struct {
	Key    string `json:"key"`
	Sealed string `json:"sealed"`
}

// Enroll creates a Touch ID-protected Secure Enclave key and seals secret
// to it. No prompt: sealing only needs the public key.
func (h Helper) Enroll(ctx context.Context, secret []byte) (key, sealed string, err error) {
	out, err := h.run(ctx, []byte(hex.EncodeToString(secret)), "enroll")
	if err != nil {
		return "", "", err
	}
	var b blob
	if err := json.Unmarshal(out, &b); err != nil || b.Key == "" || b.Sealed == "" {
		return "", "", fmt.Errorf("bks-mac enroll: unexpected output")
	}
	return b.Key, b.Sealed, nil
}

// Unseal asks for Touch ID and returns the sealed secret.
func (h Helper) Unseal(ctx context.Context, key, sealed string) ([]byte, error) {
	in, _ := json.Marshal(blob{Key: key, Sealed: sealed})
	out, err := h.run(ctx, in, "unseal")
	if err != nil {
		return nil, err
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(secret) == 0 {
		return nil, errors.New("bks-mac unseal: unexpected output")
	}
	return secret, nil
}

// Copy puts text on this Mac's pasteboard only (no Universal Clipboard),
// marked concealed/transient for clipboard-history tools, and returns the
// pasteboard change count that identifies this copy.
func (h Helper) Copy(ctx context.Context, text string) (int, error) {
	out, err := h.run(ctx, []byte(text), "copy")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// ClearIf empties the pasteboard if nothing was copied since changeCount.
func (h Helper) ClearIf(ctx context.Context, changeCount int) error {
	_, err := h.run(ctx, nil, "clear-if", strconv.Itoa(changeCount))
	return err
}

// Watch starts `bks-mac watch` and returns its events (locked,
// screensaver, sleep, display-sleep, switch). The channel closes when the
// watcher dies; stop ends it. It returns once the watcher is listening.
func (h Helper) Watch() (<-chan string, func(), error) {
	cmd := exec.Command(h.Path, "watch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	stop := func() {
		stdin.Close()
		_ = cmd.Wait()
	}
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "ready" {
		stop()
		return nil, nil, errors.New("bks-mac watch did not start")
	}
	events := make(chan string, 8)
	go func() {
		defer close(events)
		for lines.Scan() {
			events <- lines.Text()
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	return events, stop, nil
}
