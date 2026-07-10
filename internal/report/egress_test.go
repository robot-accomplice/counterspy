// internal/report/egress_test.go
package report

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestRenderEgress_ShowsConcernAndExfil(t *testing.T) {
	groups := []model.EgressGroup{{
		App: "backuptool", Trust: "unsigned", Instances: 2, OutRate: 840_000, Background: true,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}},
		Capabilities: []string{"screen", "keystrokes"},
		Concern:      model.Elevated, ExfilRisk: model.Elevated, Candidate: []string{"screen", "keystrokes"},
	}}
	out := RenderEgress(groups, false)
	for _, want := range []string{"backuptool", "unsigned", "elevated", "screen", "keystrokes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestRenderEgressJSON(t *testing.T) {
	b, err := RenderEgressJSON([]model.EgressGroup{{App: "x", Concern: model.Low}})
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		t.Fatalf("json: %v %s", err, b)
	}
}

func TestRenderEgressJSON_EmptyIsArray(t *testing.T) {
	b, err := RenderEgressJSON(nil)
	if err != nil || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("empty json: %v %s", err, b)
	}
}
