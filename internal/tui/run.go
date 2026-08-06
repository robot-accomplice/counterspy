package tui

import (
	"counterspy/internal/model"
)

// Actor performs the effects the pure loop requests (satisfied by internal/act +
// internal/feedback via a main adapter). Label records a shareable TP/FP judgement; Ack/Unack
// record a LOCAL, revisitable "reviewed / leave it" decision (issue #4), kept distinct so the
// TUI never imports internal/ack (the model-only decoupling invariant).
type Actor interface {
	Quarantine(a model.Assessment) (string, error)
	// RestoreItem reverses ONE quarantined finding (per-item undo, #8). Whole-session restore lives
	// in the `counterspy restore <manifest>` CLI command, not the interactive UI.
	RestoreItem(manifest string, a model.Assessment) error
	Label(a model.Assessment, falsePositive bool) error
	Ack(a model.Assessment) error
	Unack(a model.Assessment) error
}

// withKey returns a NEW map with key set: clone-on-write so Model value-copies stay independent
// snapshots rather than sharing one map header (cp-tui-1 Audit F-1).
func withKey(m map[string]bool, key string) map[string]bool {
	nm := make(map[string]bool, len(m)+1)
	for k, v := range m {
		nm[k] = v
	}
	nm[key] = true
	return nm
}

// withoutKey returns a NEW map with key removed (clone-on-write, mirrors withKey).
func withoutKey(m map[string]bool, key string) map[string]bool {
	nm := make(map[string]bool, len(m))
	for k, v := range m {
		if k != key {
			nm[k] = v
		}
	}
	return nm
}

// withDone is withKey under its original name (quarantine-completion set).
func withDone(done map[string]bool, key string) map[string]bool { return withKey(done, key) }
