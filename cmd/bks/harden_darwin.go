package main

import "golang.org/x/sys/unix"

// denyDebugger sets PT_DENY_ATTACH: a speed bump against same-user
// debuggers reading the unlocked vault from memory.
func denyDebugger() { _ = unix.PtraceDenyAttach() }
