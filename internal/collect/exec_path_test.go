package collect

import "testing"

func TestParseExecPaths(t *testing.T) {
	// `ps -axo pid=,comm=` — leading spaces, pid, then the full exec path (may
	// contain spaces). We only need the set of paths.
	out := []byte(
		"  1 /sbin/launchd\n" +
			"777 /usr/local/bin/live\n" +
			"888 /Applications/Some App.app/Contents/MacOS/Some App\n")
	got := ParseExecPaths(out)
	for _, p := range []string{"/sbin/launchd", "/usr/local/bin/live", "/Applications/Some App.app/Contents/MacOS/Some App"} {
		if !got[p] {
			t.Errorf("missing path %q in %v", p, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d paths, want 3: %v", len(got), got)
	}
}

func TestParseExecPaths_SkipsMalformed(t *testing.T) {
	out := []byte("\n" + "notapid /x\n" + "  42 \n" + "   \n" + "99 /ok\n")
	got := ParseExecPaths(out)
	if len(got) != 1 || !got["/ok"] {
		t.Errorf("want only {/ok}, got %v", got)
	}
}
