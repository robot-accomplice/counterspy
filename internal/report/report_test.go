package report

import (
	"encoding/json"
	"strings"
	"testing"

	"counterspy/internal/model"
)

func sample() []model.Assessment {
	return []model.Assessment{
		{
			Finding: model.Finding{
				Subject:  model.Subject{Path: "/tmp/x", PID: 777, Label: "com.evil"},
				Score:    12,
				Tripwire: "unsigned + persistence + listener",
				Evidence: []model.Evidence{{Kind: model.KindProcess, Summary: "listener",
					Facts: map[string]string{"ancestry": "launchd -> python3", "argv": "python3 beacon.py"}}},
			},
			Verdict:        "com.evil is an unsigned binary listening for inbound connections.",
			Category:       "backdoor",
			Recommendation: model.RecQuarantine,
		},
		{
			Finding:        model.Finding{Subject: model.Subject{PID: 42}, Score: 2},
			Verdict:        "pid:42 shows weak, isolated signals.",
			Category:       "unknown",
			Recommendation: model.RecMonitor,
		},
	}
}

func TestRender_LeadsWithSummaryAndVerdict(t *testing.T) {
	out := Render(sample(), nil, false)
	// Executive summary counts by recommendation.
	for _, want := range []string{"1 Quarantine", "1 Monitor"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n%s", want, out)
		}
	}
	// The top finding shows its verdict + recommendation + evidence story.
	for _, want := range []string{"com.evil", "QUARANTINE", "backdoor", "launchd -> python3", "tripwire"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

// C1: a malicious plist Label with ANSI/control chars must be neutralized in output.
func TestRender_SanitizesAttackerControlledStrings(t *testing.T) {
	as := []model.Assessment{{
		Finding:        model.Finding{Subject: model.Subject{Label: "evil\x1b[2K\x1b[1Afake"}, Score: 12},
		Recommendation: model.RecQuarantine, Category: "backdoor",
		Verdict: "line1\nline2\x1b[31m",
	}}
	out := Render(as, nil, false)
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\x1b[2K") {
		t.Errorf("ANSI escape leaked into output:\n%q", out)
	}
}

// A collector gap is surfaced in the summary (fail loud).
func TestRender_SurfacesGaps(t *testing.T) {
	out := Render(sample(), []string{"TCC privacy-grant signal unavailable"}, false)
	if !strings.Contains(out, "TCC privacy-grant signal unavailable") {
		t.Errorf("gap not surfaced:\n%s", out)
	}
}

// The low-signal Monitor item is summarized, not front-paged with full evidence.
func TestRender_OmitsMonitorNoiseFromDetail(t *testing.T) {
	out := Render(sample(), nil, false)
	if strings.Contains(out, "pid:42 shows weak") {
		t.Error("Monitor-tier items should be counted in the summary, not detailed")
	}
}

func TestRenderJSON_RoundTrips(t *testing.T) {
	b, err := RenderJSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var back []model.Assessment
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back[0].Recommendation != model.RecQuarantine || back[0].Subject.Label != "com.evil" {
		t.Errorf("json round-trip lost data: %+v", back[0])
	}
}
