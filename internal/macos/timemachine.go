package macos

import (
	"os/exec"
	"runtime"
	"strings"
)

// Backup says what bks can see of Time Machine for a file.
type Backup int

const (
	BackupUnknown  Backup = iota // tmutil missing or not answering
	BackupNone                   // no Time Machine destination
	BackupExcluded               // Time Machine runs but skips this file
	BackupIncluded               // Time Machine backs this file up
)

// TimeMachine reports whether Time Machine backs up path. It only sees
// Time Machine: other backup tools are invisible to it.
func TimeMachine(path string) Backup {
	if runtime.GOOS != "darwin" {
		return BackupUnknown
	}
	out, err := exec.Command("tmutil", "destinationinfo").CombinedOutput()
	b := parseDestinations(string(out), err)
	if b != BackupIncluded {
		return b
	}
	out, err = exec.Command("tmutil", "isexcluded", path).CombinedOutput()
	return parseExcluded(string(out), err)
}

func parseDestinations(out string, err error) Backup {
	switch {
	case strings.Contains(out, "No destinations configured"):
		return BackupNone
	case err == nil && strings.Contains(out, "Name"):
		return BackupIncluded
	}
	return BackupUnknown
}

func parseExcluded(out string, err error) Backup {
	switch {
	case err != nil:
		return BackupUnknown
	case strings.Contains(out, "[Excluded]"):
		return BackupExcluded
	case strings.Contains(out, "[Included]"):
		return BackupIncluded
	}
	return BackupUnknown
}
