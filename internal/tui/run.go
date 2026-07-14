package tui

import (
	"counterspy/internal/model"
)

// Actor performs the effects the pure loop requests (satisfied by internal/act +
// internal/feedback via a main adapter). Label records a TP/FP judgement locally.
type Actor interface {
	Quarantine(a model.Assessment) (string, error)
	Restore(manifest string) error
	Label(a model.Assessment, falsePositive bool) error
}

// withDone returns a NEW map with key added — clone-on-write so Model value-copies
// stay independent snapshots rather than sharing one map header (cp-tui-1 Audit F-1).
func withDone(done map[string]bool, key string) map[string]bool {
	nd := make(map[string]bool, len(done)+1)
	for k, v := range done {
		nd[k] = v
	}
	nd[key] = true
	return nd
}
