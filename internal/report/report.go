// Package report formats assessments for humans and machines. It does no analysis —
// all synthesis lives in interpret; report only presents (spec §8.1, §12 invariant).
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"counterspy/internal/model"
)

// RenderJSON emits the machine-readable form fed to CI / the ABORT gate / future UIs.
// It emits ALL assessments, including Monitor-tier. Consumers MUST gate on
// Recommendation before surfacing Category/Verdict prominently — a Monitor-tier
// item's category (e.g. "permission-grant") is low-signal and must not be shown as an
// alert (cp-9 Audit F-2; spec §8.1 "present, don't scare").
func RenderJSON(assessments []model.Assessment) ([]byte, error) {
	return json.MarshalIndent(assessments, "", "  ")
}

// ANSI style codes. Applied only when color is on (a real terminal, NO_COLOR unset).
const (
	sReset = "\x1b[0m"
	sBold  = "\x1b[1m"
	sDim   = "\x1b[38;5;244m"
	sMint  = "\x1b[38;5;79m"  // accent / CounterSpy chrome + evidence labels
	sRed   = "\x1b[38;5;203m" // Quarantine
	sAmber = "\x1b[38;5;215m" // Investigate
	sGray  = "\x1b[38;5;246m" // Monitor
	sTrip  = "\x1b[1;97;48;5;52m"
)

type pen struct{ on bool }

func (p pen) s(code, text string) string {
	if !p.on || text == "" {
		return text
	}
	return code + text + sReset
}

func recStyle(r model.Recommendation) string {
	switch r {
	case model.RecQuarantine:
		return sRed
	case model.RecInvestigate:
		return sAmber
	default:
		return sGray
	}
}

func glyph(r model.Recommendation) string {
	switch r {
	case model.RecQuarantine:
		return "⚑"
	case model.RecInvestigate:
		return "▲"
	default:
		return "·"
	}
}

// Render produces the human report: a styled executive summary (counts per tier and
// any collector gaps) followed by the actionable findings (Quarantine + Investigate)
// as verdict + recommendation + a deduplicated evidence story. Monitor-tier noise is
// counted, not detailed. Color is applied only when `color` is true.
func Render(assessments []model.Assessment, gaps []string, color bool) string {
	p := pen{color}
	var q, inv, mon int
	for _, a := range assessments {
		switch a.Recommendation {
		case model.RecQuarantine:
			q++
		case model.RecInvestigate:
			inv++
		default:
			mon++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s  %s\n",
		p.s(sBold+sMint, "CounterSpy"),
		p.s(sDim, fmt.Sprintf("%d actionable of %d scanned", q+inv, len(assessments))))
	fmt.Fprintf(&b, "  %s   %s   %s\n",
		p.s(sRed, fmt.Sprintf("● %d Quarantine", q)),
		p.s(sAmber, fmt.Sprintf("▲ %d Investigate", inv)),
		p.s(sGray, fmt.Sprintf("· %d Monitor", mon)))
	for _, g := range gaps {
		fmt.Fprintf(&b, "  %s\n", p.s(sAmber, "⚠ "+g))
	}

	if q+inv == 0 {
		fmt.Fprintf(&b, "\n  %s\n\n", p.s(sDim, "Nothing actionable. Low-signal items are counted above only."))
		return b.String()
	}

	n := 0
	for _, a := range assessments {
		if a.Recommendation == model.RecMonitor {
			continue
		}
		n++
		rc := recStyle(a.Recommendation)
		fmt.Fprintf(&b, "\n  %s %s  %s\n",
			p.s(rc, glyph(a.Recommendation)+" "+strings.ToUpper(string(a.Recommendation))),
			p.s(sBold, Clean(a.Subject.Display())),
			p.s(sDim, a.Category+" · score "+itoa(a.Score)))
		fmt.Fprintf(&b, "     %s\n", Clean(a.Verdict))
		if a.Tripwire != "" {
			fmt.Fprintf(&b, "     %s\n", p.s(sTrip, " ⚠ tripwire: "+a.Tripwire+" "))
		}
		for _, e := range dedupe(a.Evidence) {
			suffix := ""
			if e.count > 1 {
				suffix = p.s(sDim, fmt.Sprintf("  ×%d", e.count))
			}
			fmt.Fprintf(&b, "       %s %s%s\n", p.s(sMint, pad(e.kind, 12)), Clean(e.summary), suffix)
			if e.ancestry != "" {
				fmt.Fprintf(&b, "         %s %s\n", p.s(sDim, "↳"), p.s(sAmber, Clean(e.ancestry)))
			}
			if e.argv != "" {
				fmt.Fprintf(&b, "         %s %s\n", p.s(sDim, "↳"), p.s(sDim, Clean(e.argv)))
			}
		}
	}
	fmt.Fprintf(&b, "\n  %s\n", p.s(sDim,
		"Quarantine = act now · Investigate = review (may be legitimate) · undo anything with: counterspy restore"))
	return b.String()
}

type evLine struct {
	kind, summary, ancestry, argv string
	count                         int
}

// dedupe collapses identical (kind, summary) evidence into one line with a count —
// a subject with two LaunchAgents no longer repeats "user-level LaunchAgent" twice.
func dedupe(ev []model.Evidence) []evLine {
	order := []string{}
	seen := map[string]*evLine{}
	for _, e := range ev {
		key := string(e.Kind) + "|" + e.Summary
		l, ok := seen[key]
		if !ok {
			l = &evLine{kind: string(e.Kind), summary: e.Summary, ancestry: e.Facts["ancestry"], argv: e.Facts["argv"]}
			seen[key] = l
			order = append(order, key)
		}
		l.count++
	}
	// Stable, kind-grouped order.
	sort.SliceStable(order, func(i, j int) bool { return seen[order[i]].kind < seen[order[j]].kind })
	out := make([]evLine, 0, len(order))
	for _, k := range order {
		out = append(out, *seen[k])
	}
	return out
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// Clean strips control/escape characters from attacker-influenced strings before they
// reach the terminal (ABORT C1). Delegates to model.Clean so the CLI and TUI share it.
func Clean(s string) string { return model.Clean(s) }
