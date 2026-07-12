package collect

import (
	"os/exec"
	"strconv"
	"strings"
)

// ParseExecPaths turns `ps -axo pid=,comm=` output into the set of real
// executable paths of running processes. Each line is "<pid> <path>"; the path
// may contain spaces, so we split once on the first space after the numeric pid.
// This is the trustworthy exec path (unlike argv0), enabling persistence↔process
// correlation for liveness (ticket T-4).
func ParseExecPaths(b []byte) map[string]bool {
	paths := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimLeft(line, " ")
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		if _, err := strconv.Atoi(line[:sp]); err != nil {
			continue // not a "<pid> <path>" line
		}
		if p := strings.TrimSpace(line[sp+1:]); p != "" {
			paths[p] = true
		}
	}
	return paths
}

// CollectExecPaths resolves running processes' real exec paths. Best-effort:
// callers treat an error as "no running-path knowledge" (persistence then reads
// as vestigial rather than crashing).
func CollectExecPaths() (map[string]bool, error) {
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	return ParseExecPaths(out), nil
}
