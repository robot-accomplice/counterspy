// Package tui is an interactive tcell triage face over []model.Assessment. It performs
// no analysis — it renders findings and acts through the Actor interface (§12 invariant).
package tui

import (
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type focusMode int

const (
	focusList focusMode = iota
	focusModal
	focusHelp
	focusFilter
)

// palette mirrors the report tier scheme as tcell colors.
var (
	colAccent      = tcell.NewRGBColor(90, 208, 168)  // mint
	colDim         = tcell.NewRGBColor(102, 120, 138) // slate
	colQuarantine  = tcell.NewRGBColor(255, 107, 107) // red
	colInvestigate = tcell.NewRGBColor(255, 180, 84)  // amber
	colMonitor     = tcell.NewRGBColor(124, 142, 160) // gray
	colText        = tcell.NewRGBColor(196, 208, 220)
)

// Model is the pure UI state. No I/O touches it.
type Model struct {
	Assessments []model.Assessment
	Gaps        []string
	Selected    int // index into visible()
	Filter      string
	SortByRec   bool // false = sort by score desc
	ShowMonitor bool
	Focus       focusMode
	Pending     model.Assessment // the item shown in the confirm modal
	Done        map[string]bool  // Subject.Key() of quarantined items
	Toast       string
}

func New(assessments []model.Assessment, gaps []string) Model {
	return Model{Assessments: assessments, Gaps: gaps, Done: map[string]bool{}}
}

func recRank(r model.Recommendation) int {
	switch r {
	case model.RecQuarantine:
		return 0
	case model.RecInvestigate:
		return 1
	default:
		return 2
	}
}

// visible applies filter + monitor-collapse + sort. Pure.
func (m Model) visible() []model.Assessment {
	out := make([]model.Assessment, 0, len(m.Assessments))
	for _, a := range m.Assessments {
		if !m.ShowMonitor && a.Recommendation == model.RecMonitor {
			continue
		}
		if m.Filter != "" && !strings.Contains(strings.ToLower(a.Subject.Display()), strings.ToLower(m.Filter)) {
			continue
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if m.SortByRec {
			if recRank(out[i].Recommendation) != recRank(out[j].Recommendation) {
				return recRank(out[i].Recommendation) < recRank(out[j].Recommendation)
			}
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func (m Model) counts() (q, inv, mon int) {
	for _, a := range m.Assessments {
		switch a.Recommendation {
		case model.RecQuarantine:
			q++
		case model.RecInvestigate:
			inv++
		default:
			mon++
		}
	}
	return
}
