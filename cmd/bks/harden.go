//go:build unix

package main

import "golang.org/x/sys/unix"

// harden limits where secrets can leak from this process: files are private
// to the user, no core dumps, and (macOS) no debugger can attach.
func harden() {
	unix.Umask(0o077)
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	denyDebugger()
}
