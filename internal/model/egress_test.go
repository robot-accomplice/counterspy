package model

import "testing"

func TestConcernLevelString(t *testing.T) {
	for _, c := range []struct {
		l    ConcernLevel
		want string
	}{{Minimal, "minimal"}, {Low, "low"}, {Notable, "notable"}, {Elevated, "elevated"}} {
		if got := c.l.String(); got != c.want {
			t.Fatalf("ConcernLevel(%d).String() = %q, want %q", c.l, got, c.want)
		}
	}
}

func TestEgressGroupCarriesConnsAndExfil(t *testing.T) {
	g := EgressGroup{
		App: "backuptool", Trust: "unsigned", Instances: 2,
		Conns:        []Conn{{PID: 4821, Endpoint: Endpoint{IP: "198.51.100.7", Port: 443}, Proto: "tcp", OutRate: 620}},
		Capabilities: []string{"screen", "keystrokes"},
		Concern:      Elevated, ExfilRisk: Elevated, Candidate: []string{"screen", "keystrokes"},
	}
	if g.Conns[0].Endpoint.Port != 443 || g.ExfilRisk != Elevated || len(g.Candidate) != 2 {
		t.Fatalf("EgressGroup fields wrong: %+v", g)
	}
}
