package collect

import (
	"os/exec"
	"strconv"
	"strings"
)

// ParseRunningPaths extracts, from `ps -axo pid=,args= -ww` output, the set of
// filesystem paths currently referenced by a running process: its executable AND
// every argv token that looks like an absolute path. Correlating a persistence
// target against THIS set (not just the exec path) makes the #23 active/vestigial
// mark correct for two cases `comm=` gets wrong (ESC-1):
//   - bare-argv0 processes (e.g. `node` invoked via PATH): the target still
//     appears if it is an argv path token;
//   - interpreter-wrapped persistence (`/usr/bin/python3 /path/payload.py`): the
//     script is an argv token, so the T-7 payload correlates even though the
//     process's executable is the interpreter.
//
// Ticket T-4. Liveness is DISPLAY-ONLY, so imprecision here only mislabels a
// glyph; it never suppresses a finding or changes a score. Two known limits
// (accepted at ESC-1): (1) a path passed as a plain ARGUMENT to an unrelated
// process (e.g. `grep /etc/x`, `tar -C /tmp/x`) is collected too, so a dormant
// target that merely appears in someone's argv can read false-active; (2) a path
// containing spaces is whitespace-split by ps and won't match as a single token.
func ParseRunningPaths(b []byte) map[string]bool {
	paths := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line) // tolerant of tabs / repeated spaces
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue // not a "<pid> <args...>" line
		}
		for _, tok := range fields[1:] {
			if strings.HasPrefix(tok, "/") { // absolute-path token (exec or script arg)
				paths[tok] = true
			}
		}
	}
	return paths
}

// CollectRunningPaths resolves the paths referenced by running processes.
// Best-effort: callers treat an error as "nothing known running" (persistence
// then reads as vestigial rather than crashing).
func CollectRunningPaths() (map[string]bool, error) {
	out, err := exec.Command(psBin, "-axo", "pid=,args=", "-ww").Output()
	if err != nil {
		return nil, err
	}
	return ParseRunningPaths(out), nil
}
