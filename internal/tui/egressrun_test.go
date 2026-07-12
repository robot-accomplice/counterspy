// internal/tui/egressrun_test.go
package tui

import (
	"strings"
	"sync/atomic"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// simContains reports whether the SimulationScreen's rendered contents include want.
func simContains(s tcell.SimulationScreen, want string) bool {
	cells, w, h := s.GetContents()
	var b []rune
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			b = append(b, cells[y*w+x].Runes...)
		}
	}
	return len(b) > 0 && strings.Contains(string(b), want)
}

type fakeSampler struct{ groups []model.EgressGroup }

func (f fakeSampler) Sample() []model.EgressGroup { return f.groups }

// countingSampler tracks how many times Sample was called, so tests can tell a tick actually
// triggered a resample. Sample() runs on a dedicated background goroutine (see console.go), so
// the counter is atomic to be read race-free from the test goroutine.
type countingSampler struct {
	groups []model.EgressGroup
	calls  atomic.Int64
}

func (c *countingSampler) Sample() []model.EgressGroup {
	c.calls.Add(1)
	return c.groups
}
