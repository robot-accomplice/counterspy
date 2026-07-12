//go:build darwin

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativeSig_RealBinaries exercises the Security.framework backend against real files:
// an Apple-signed system binary and a non-code file. It runs on the macOS CI runner (cgo),
// so it needs no sudo and no external tools.
func TestNativeSig_RealBinaries(t *testing.T) {
	// /bin/ls is Apple-signed and valid.
	verifyErr, accepted, authority, _ := nativeSig("/bin/ls")
	if verifyErr != "" || !accepted {
		t.Fatalf("/bin/ls should be signed+accepted, got verifyErr=%q accepted=%v", verifyErr, accepted)
	}
	if authority == "" || !(strings.Contains(authority, "Software Signing") || strings.Contains(authority, "Apple")) {
		t.Fatalf("/bin/ls authority should be an Apple leaf CN, got %q", authority)
	}

	// A plain text file is not a code object → unsigned.
	txt := filepath.Join(t.TempDir(), "notcode.txt")
	if err := os.WriteFile(txt, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, acc, _, _ := nativeSig(txt)
	if !strings.Contains(v, "not signed") || acc {
		t.Fatalf("a non-code file should read unsigned, got verifyErr=%q accepted=%v", v, acc)
	}

	// End-to-end: CollectCodesign(/bin/ls) yields signed=true with the authority fact.
	ev := CollectCodesign("/bin/ls")
	if len(ev) != 1 || ev[0].Facts["signed"] != "true" || ev[0].Facts["authority"] == "" {
		t.Fatalf("CollectCodesign(/bin/ls) should be signed with an authority, got %+v", ev)
	}
}
