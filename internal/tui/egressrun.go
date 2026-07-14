// internal/tui/egressrun.go
package tui

import (
	"counterspy/internal/model"
)

// Sampler yields the current aggregated egress groups (satisfied by internal/egress.Monitor
// via a main adapter). The live loop that consumes it lives in RunConsole (console.go).
type Sampler interface {
	Sample() []model.EgressGroup
}
