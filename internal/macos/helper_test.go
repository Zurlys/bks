package macos

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// helper returns the built bks-mac, or skips. These tests never trigger a
// Touch ID prompt and never touch the clipboard.
func helper(t *testing.T) Helper {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	p, _ := filepath.Abs("../../bin/bks-mac")
	if _, err := os.Stat(p); err != nil {
		t.Skip("bin/bks-mac not built (run make)")
	}
	return Helper{p}
}

func TestEnrollNeedsNoPrompt(t *testing.T) {
	h := helper(t)
	secret := make([]byte, 32)
	rand.Read(secret)
	key, sealed, err := h.Enroll(context.Background(), secret)
	if errors.Is(err, ErrTouchIDUnavailable) {
		t.Skipf("no Secure Enclave here: %v", err) // e.g. CI virtual machines
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(key) < 100 || len(sealed) < 100 {
		t.Fatalf("short blobs: %d %d", len(key), len(sealed))
	}
	// a second enrolment makes a different key and box
	key2, sealed2, _ := h.Enroll(context.Background(), secret)
	if key2 == key || sealed2 == sealed {
		t.Fatal("enrolment is not randomized")
	}
}

func TestUnsealRejectsGarbageWithoutPrompt(t *testing.T) {
	h := helper(t)
	_, err := h.Unseal(context.Background(), "bm90IGEga2V5", "bm90IHNlYWxlZA==")
	if err == nil || errors.Is(err, ErrTouchIDCancelled) {
		t.Fatalf("got %v", err)
	}
}

func TestWatchStartsAndStops(t *testing.T) {
	h := helper(t)
	events, stop, err := h.Watch()
	if err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("events channel not closed after stop")
	}
}

func TestExitCodesMapToErrors(t *testing.T) {
	dir := t.TempDir()
	for code, want := range map[int]error{2: ErrTouchIDCancelled, 3: ErrTouchIDFallback, 4: ErrTouchIDUnavailable} {
		script := filepath.Join(dir, "fake")
		body := "#!/bin/sh\necho 'bks-mac: nope' >&2\nexit " + string(rune('0'+code)) + "\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := Helper{script}.Unseal(context.Background(), "a", "b")
		if !errors.Is(err, want) {
			t.Errorf("exit %d: got %v, want %v", code, err, want)
		}
	}
}

// Copy and ClearIf run against a private pasteboard (BKS_PASTEBOARD): the
// real clipboard is never touched.
func TestCopyMarksAndClearIf(t *testing.T) {
	h := helper(t)
	t.Setenv("BKS_PASTEBOARD", "bks-go-test")
	ctx := context.Background()
	types := func() string {
		out, err := h.run(ctx, nil, "types")
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	n, err := h.Copy(ctx, "value-"+time.Now().String())
	if err != nil && os.Getenv("CI") != "" {
		t.Skipf("no pasteboard server on this CI runner: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"public.utf8-plain-text", "org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"} {
		if !strings.Contains(types(), want) {
			t.Fatalf("type %s missing after copy:\n%s", want, types())
		}
	}
	if err := h.ClearIf(ctx, n-1); err != nil || !strings.Contains(types(), "utf8") {
		t.Fatalf("stale change count cleared the pasteboard: %v", err)
	}
	if err := h.ClearIf(ctx, n); err != nil || strings.Contains(types(), "utf8") {
		t.Fatalf("matching change count did not clear: %v\n%s", err, types())
	}
}
