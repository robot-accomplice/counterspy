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

func execOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func execCombined(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func execAccepts(name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run() == nil
}
