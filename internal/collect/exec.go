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

// execOutput is a package var (not a func) so tests can override it with a fake keyed on
// command name — no shelling out in tests. Code-signature checks no longer shell out (they
// use Security.framework, see codesign_darwin.go); the remaining collectors still exec.
var execOutput = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}
