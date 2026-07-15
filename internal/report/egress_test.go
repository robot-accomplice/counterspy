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

// #3 (Audit cp-p1a F-2): the additive Endpoint.Name must not change the egress JSON contract for
// unresolved endpoints — it is omitted when empty, and present only when a name was observed.
func TestRenderEgressJSON_EndpointNameOmitEmpty(t *testing.T) {
	groups := []model.EgressGroup{{App: "x", Destinations: []model.Endpoint{{IP: "1.2.3.4", Port: 443}}}}
	b, err := RenderEgressJSON(groups)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\"Name\"") {
		t.Fatalf("unresolved endpoint must omit Name from JSON:\n%s", b)
	}
	groups[0].Destinations[0].Name = "api.example.com"
	b, _ = RenderEgressJSON(groups)
	if !strings.Contains(string(b), "\"Name\": \"api.example.com\"") {
		t.Fatalf("resolved endpoint must include Name in JSON:\n%s", b)
	}
}
