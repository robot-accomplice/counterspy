package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// --- Part C: direct tests for pure helpers ---

func TestExtractAuthority_FirstLineWins(t *testing.T) {
	s := "Executable=/bin/x\nAuthority=Developer ID Application: Foo\nAuthority=Apple Root CA\n"
	if got := extractAuthority(s); got != "Developer ID Application: Foo" {
		t.Errorf("extractAuthority = %q, want first Authority= line", got)
	}
}

func TestExtractAuthority_NoneReturnsEmpty(t *testing.T) {
	if got := extractAuthority("no authority lines here\n"); got != "" {
		t.Errorf("extractAuthority = %q, want empty", got)
	}
}

func TestExpand_TildeExpandsToHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir available")
	}
	got := expand("~/Library/LaunchAgents")
	want := filepath.Join(home, "Library/LaunchAgents")
	if got != want {
		t.Errorf("expand(~/...) = %q, want %q", got, want)
	}
}

func TestExpand_AbsolutePathUnchanged(t *testing.T) {
	if got := expand("/Library/LaunchAgents"); got != "/Library/LaunchAgents" {
		t.Errorf("expand(absolute) = %q, want unchanged", got)
	}
}

func TestPickTarget_LastAbsolutePathWins(t *testing.T) {
	got := pickTarget([]string{"/usr/bin/env", "-x", "/Users/me/payload"})
	if got != "/Users/me/payload" {
		t.Errorf("pickTarget = %q, want last absolute path", got)
	}
}

func TestPickTarget_NoAbsolutePathFallsBackToFirst(t *testing.T) {
	got := pickTarget([]string{"relative", "args"})
	if got != "relative" {
		t.Errorf("pickTarget = %q, want first arg fallback", got)
	}
}

func TestPickTarget_EmptyReturnsEmpty(t *testing.T) {
	if got := pickTarget(nil); got != "" {
		t.Errorf("pickTarget(nil) = %q, want empty", got)
	}
}

func TestStatExists_EmptyPathIsFalse(t *testing.T) {
	if statExists("") {
		t.Error("statExists(\"\") should be false")
	}
}

func TestStatExists_MissingPathIsFalse(t *testing.T) {
	if statExists("/definitely/does/not/exist/xyz123") {
		t.Error("statExists on missing path should be false")
	}
}

func TestStatExists_ExistingPathIsTrue(t *testing.T) {
	tmp := t.TempDir()
	if !statExists(tmp) {
		t.Error("statExists on an existing dir should be true")
	}
}

func TestFirstField_Empty(t *testing.T) {
	if got := firstField(""); got != "" {
		t.Errorf("firstField(\"\") = %q, want empty", got)
	}
}

func TestFirstField_SingleToken(t *testing.T) {
	if got := firstField("/bin/ls"); got != "/bin/ls" {
		t.Errorf("firstField = %q, want /bin/ls", got)
	}
}

func TestFirstField_MultiToken(t *testing.T) {
	if got := firstField("/usr/bin/python3 beacon.py --flag"); got != "/usr/bin/python3" {
		t.Errorf("firstField = %q, want first token", got)
	}
}
