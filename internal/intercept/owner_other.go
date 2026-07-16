//go:build !darwin

package intercept

// portOwner is macOS-only (the lsof attribution sweep). Off darwin a flow is simply unattributed —
// shown without an app rather than dropped.
func portOwner(int) (int, string, bool) { return 0, "", false }
