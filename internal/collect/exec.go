package collect

import (
	"context"
	"os/exec"
	"time"
)

// cmdTimeout bounds every native-tool invocation so a pathological input (a plist
// bomb, a huge app bundle, a corrupt TCC db) cannot hang the scan indefinitely
// (ABORT C1).
const cmdTimeout = 15 * time.Second

// The native tools are invoked by absolute path, never resolved through PATH. counterspy is meant
// to be run under sudo for full visibility, so a writable directory anywhere on PATH would let any
// of these be substituted and executed with the scan's privileges (go:S4036).
const (
	psBin      = "/bin/ps"
	lsofBin    = "/usr/sbin/lsof"
	plutilBin  = "/usr/bin/plutil"
	sqlite3Bin = "/usr/bin/sqlite3"
)

// execOutput is a package var (not a func) so tests can override it with a fake keyed on
// command name — no shelling out in tests. Code-signature checks no longer shell out (they
// use Security.framework, see codesign_darwin.go); the remaining collectors still exec.
var execOutput = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
