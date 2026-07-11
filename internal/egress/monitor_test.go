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
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/Users/jon/.hidden/daemon serve"}}
	}
	// exePaths resolves the REAL executable path (spaces intact) — the fix for the
	// "Application" mislabel. A spaced path must yield its true base name, not "Application".
	m.exePaths = func() map[int]string {
		return map[int]string{4821: "/Users/jon/Library/Application Support/Foo/foo"}
	}
	m.trustOf = func(path string) string { return "unsigned" }
	m.capsOf = func(path string) []string { return []string{"screen", "keystrokes"} }

	m.Sample()           // first tick: establishes the baseline, rate 0
	groups := m.Sample() // second tick: cur==prev cumulative here, so rate 0 — assert structure
	if len(groups) != 1 || groups[0].App != "foo" {
		t.Fatalf("expected one group named 'foo' (spaced path resolved), got %+v", groups)
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

// Two concurrent pids: output order must be stable across identical calls (determinism),
// and a pid's FIRST sighting must report rate 0 even with a large cumulative counter (the
// process's history must not be attributed to one tick). Guards both review findings.
func TestMonitor_DeterministicOrderAndFirstSightRateZero(t *testing.T) {
	newM := func() *Monitor {
		m := New(2)
		m.runNettop = func() []byte {
			return []byte("time,,bytes_in,bytes_out\n15:04:05.0,a.100,0,500000\n15:04:05.0,b.200,0,900000\n")
		}
		m.runLsof = func() []byte {
			return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
				"a 100 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->1.1.1.1:443 (ESTABLISHED)\n" +
				"b 200 root 11u IPv4 0x2 0t0 TCP 10.0.0.3:6->2.2.2.2:443 (ESTABLISHED)\n")
		}
		m.procs = func() map[int]*collect.Proc {
			return map[int]*collect.Proc{100: {PID: 100, Cmd: "/x/a"}, 200: {PID: 200, Cmd: "/x/b"}}
		}
		m.exePaths = func() map[int]string { return map[int]string{100: "/x/a", 200: "/x/b"} }
		m.trustOf = func(string) string { return "unsigned" }
		m.capsOf = func(string) []string { return nil }
		return m
	}
	m := newM()
	first := m.Sample()
	for _, g := range first {
		if g.OutRate != 0 {
			t.Fatalf("first-sight rate must be 0 (cumulative not attributed to one tick), got %d for %s", g.OutRate, g.App)
		}
	}
	// Stable order across identical subsequent calls.
	a, b := m.Sample(), m.Sample()
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("want 2 groups, got %d/%d", len(a), len(b))
	}
	for i := range a {
		if a[i].App != b[i].App {
			t.Fatalf("nondeterministic order at %d: %q vs %q", i, a[i].App, b[i].App)
		}
	}
}
