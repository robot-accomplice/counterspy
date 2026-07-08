// Package report formats assessments for humans and machines. It does no analysis —
// all synthesis lives in interpret; report only presents (spec §8.1, §12 invariant).
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"counterspy/internal/model"
)

// RenderJSON emits the machine-readable form fed to CI / the ABORT gate / future UIs.
func RenderJSON(assessments []model.Assessment) ([]byte, error) {
	return json.MarshalIndent(assessments, "", "  ")
}

// Render produces the human report: an executive summary (counts per recommendation)
// followed by the actionable findings (Quarantine + Investigate) as verdict +
// recommendation + evidence story. Monitor-tier noise is counted, not detailed.
func Render(assessments []model.Assessment) string {
	var q, inv, mon int
	for _, a := range assessments {
		switch a.Recommendation {
		case model.RecQuarantine:
			q++
		case model.RecInvestigate:
			inv++
		case model.RecMonitor:
			mon++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "CounterSpy — %d finding(s): %d Quarantine, %d Investigate, %d Monitor\n",
		len(assessments), q, inv, mon)
	if q+inv == 0 {
		fmt.Fprint(&b, "\nNothing actionable. Low-signal items are counted above only.\n")
		return b.String()
	}

	n := 0
	for _, a := range assessments {
		if a.Recommendation == model.RecMonitor {
			continue // summarized above, not detailed
		}
		n++
		id := a.Subject.Label
		if id == "" {
			id = a.Subject.Key()
		}
		fmt.Fprintf(&b, "\n[%d] %s  —  %s  (%s, score %d)\n", n, id, a.Recommendation, a.Category, a.Score)
		fmt.Fprintf(&b, "    %s\n", a.Verdict)
		if a.Tripwire != "" {
			fmt.Fprintf(&b, "    ⚠ TRIPWIRE: %s\n", a.Tripwire)
		}
		for _, e := range a.Evidence {
			fmt.Fprintf(&b, "      - %s: %s\n", e.Kind, e.Summary)
			if v := e.Facts["ancestry"]; v != "" {
				fmt.Fprintf(&b, "          ancestry: %s\n", v)
			}
			if v := e.Facts["argv"]; v != "" {
				fmt.Fprintf(&b, "          argv:     %s\n", v)
			}
		}
	}
	return b.String()
}
