package collect

import "testing"

func TestParseRunningPaths(t *testing.T) {
	// `ps -axo pid=,args= -ww` — pid then the full argv. We collect every
	// absolute-path token so correlation works for a direct binary, a bare-argv0
	// interpreter running a script (the path is an ARG), and avoids comm=' bare-name miss.
	out := []byte(
		"    1 /sbin/launchd\n" +
			"  777 /usr/local/bin/live --flag\n" +
			"  888 node /Users/j/.tools/agent.js --port 3000\n" + // bare argv0 'node'; script path is an arg
			"  999 /usr/bin/python3 /Library/Scripts/payload.py\n", // interpreter-wrapper (T-7)
	)
	got := ParseRunningPaths(out)

	want := []string{
		"/sbin/launchd",
		"/usr/local/bin/live",
		"/Users/j/.tools/agent.js", // interpreter-run script, correlates even though argv0 is bare 'node'
		"/usr/bin/python3",
		"/Library/Scripts/payload.py", // the T-7 payload, present as an arg
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("missing path token %q in %v", p, got)
		}
	}
	// non-path tokens (flags, bare names) are excluded
	for _, bad := range []string{"node", "--flag", "--port", "3000"} {
		if got[bad] {
			t.Errorf("non-path token %q should not be collected", bad)
		}
	}
}

func TestParseRunningPaths_SkipsMalformed(t *testing.T) {
	out := []byte("\n" + "notapid /x\n" + "  42 \n" + "\t99 /ok\n")
	got := ParseRunningPaths(out)
	if !got["/ok"] {
		t.Errorf("want /ok collected (leading/tab whitespace tolerated), got %v", got)
	}
	if got["/x"] {
		t.Errorf("non-pid line must be skipped, got %v", got)
	}
}

// Documents the ACCEPTED display-only limitation (cp-T4 review F-1, ESC-1): a
// path passed as an argument to an unrelated process is collected, so a dormant
// target that merely appears in someone's argv reads active. Intended, not a bug.
func TestParseRunningPaths_ArgPathIsCollected(t *testing.T) {
	got := ParseRunningPaths([]byte("321 grep -r foo /var/db/dormant.plist\n"))
	if !got["/var/db/dormant.plist"] {
		t.Errorf("known limitation: an argv path token is collected — got %v", got)
	}
}
