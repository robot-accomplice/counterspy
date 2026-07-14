//go:build darwin && !cgo

package collect

// Building CounterSpy for darwin without cgo SILENTLY drops codesign_darwin.go — the
// Security.framework code-signature probe carries `import "C"`, and Go excludes every cgo file
// when CGO_ENABLED=0. The result is a binary that does NO code-signature checks at all: trust
// glyphs, notarization, revocation, and unsigned detection all vanish, with no error.
//
// codesign is a core signal and darwin is the only supported platform, so a no-cgo build is always
// a misconfiguration (it bit the goreleaser release once). Fail LOUD at compile time — referencing
// an undefined identifier forces a build error — instead of shipping a crippled binary.
var _ = counterspy_requires_CGO_ENABLED_1_on_darwin_for_codesign
