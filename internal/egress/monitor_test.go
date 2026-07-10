package egress

import (
	"testing"

	"counterspy/internal/collect"
	"counterspy/internal/model"
)

func TestMonitor_SampleAggregatesAndScores(t *testing.T) {
	m := New(2)
	// Inject fake tool output + joins (no real network / sudo).
	m.runNettop = func() []byte { return []byte("time,,bytes_in,bytes_out\n15:04:05.0,daemon.4821,0,200000\n") }
	m.runLsof = func() []byte {
		return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
			"daemon 4821 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->198.51.100.7:443 (ESTABLISHED)\n")
	}
	m.procs = func() map[int]*collect.Proc {
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/Users/jon/.hidden/daemon"}}
	}
	m.trustOf = func(path string) string { return "unsigned" }
	m.capsOf = func(path string) []string { return []string{"screen", "keystrokes"} }

	m.Sample()           // first tick: establishes the baseline, rate 0
	groups := m.Sample() // second tick: cur==prev cumulative here, so rate 0 — assert structure
	if len(groups) != 1 || groups[0].App == "" {
		t.Fatalf("expected one group, got %+v", groups)
	}
	g := groups[0]
	if g.Trust != "unsigned" || !g.Background {
		t.Fatalf("trust/background wrong: %+v", g)
	}
	if len(g.Capabilities) != 2 {
		t.Fatalf("capabilities not joined: %+v", g.Capabilities)
	}
	if len(g.Conns) != 1 || g.Conns[0].Endpoint.Port != 443 {
		t.Fatalf("conns wrong: %+v", g.Conns)
	}
	if g.ExfilRisk < model.Low {
		t.Fatalf("exfil risk should be set from capabilities: %s", g.ExfilRisk)
	}
}
