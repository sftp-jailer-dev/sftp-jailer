package main

import (
	"fmt"
	"strings"
)

// rootCheckMessage is the SAFE-01 pure gate: given the invocation args and
// the effective UID, returns the stderr message to print and whether the
// process should exit non-zero. Kept pure so it is testable without
// actually exercising os.Exit.
func rootCheckMessage(args []string, euid int) (stderr string, shouldExit bool) {
	if euid == 0 {
		return "", false
	}
	rest := strings.Join(args, " ")
	msg := fmt.Sprintf("sftp-jailer: must run as root.\n  re-invoke: sudo sftp-jailer %s\n", rest)
	return msg, true
}
