package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"counterspy/internal/model"
)

// RenderEgressJSON emits the machine-readable per-app egress form.
func RenderEgressJSON(groups []model.EgressGroup) ([]byte, error) {
	return json.MarshalIndent(groups, "", "  ")
}

// RenderEgress prints a per-app egress report: one block per app with rate, trust,
// destinations, cadence, capabilities, and the inferred exfil risk + candidates.
func RenderEgress(groups []model.EgressGroup, color bool) string {
	p := pen{color}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s  %s\n", p.s(sBold+sMint, "CounterSpy"), p.s(sDim, "egress observation"))
	for _, g := range groups {
		style := sGray
		switch g.Concern {
		case model.Elevated:
			style = sRed
		case model.Notable:
			style = sAmber
		}
		fmt.Fprintf(&b, "\n  %s  %s  %s\n",
			p.s(style, g.Concern.String()+" "+Clean(g.App)),
			p.s(sDim, fmt.Sprintf("%s · %s · out %s/s", g.Trust, backgroundLabel(g.Background), humanBytes(g.OutRate))),
			p.s(sDim, fmt.Sprintf("%d instance(s) · %s", g.Instances, g.Cadence)))
		if len(g.Destinations) > 0 {
			fmt.Fprintf(&b, "     %s %s\n", p.s(sDim, "→"), Clean(destList(g.Destinations)))
		}
		if len(g.Capabilities) > 0 {
			fmt.Fprintf(&b, "     %s %s — %s %s %s\n", p.s(sDim, "can access"), strings.Join(g.Capabilities, ", "),
				p.s(style, "exfil "+g.ExfilRisk.String()), p.s(sDim, "candidate:"), strings.Join(g.Candidate, ", "))
		}
	}
	return b.String()
}

func backgroundLabel(bg bool) string {
	if bg {
		return "background"
	}
	return "foreground"
}

func destList(dests []model.Endpoint) string {
	parts := make([]string, 0, len(dests))
	for i, d := range dests {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d", len(dests)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", d.IP, d.Port))
	}
	return strings.Join(parts, "  ")
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
