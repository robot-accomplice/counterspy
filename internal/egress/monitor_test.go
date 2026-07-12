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

// Every instance row gets its OWN sparkline: per-PID out-rate history must accumulate across
// ticks and attach to each group member (not just the app-level Spark). Guards the "sparklines
// on every line" behavior.
func TestMonitor_PerPIDSparkAttachedToMembers(t *testing.T) {
	m := New(1) // interval 1s → rate == byte delta
	tick := 0
	m.runNettop = func() []byte {
		tick++
		out := 100000 * tick // cumulative climbs 100000/tick → per-tick rate 100000
		return []byte("time,,bytes_in,bytes_out\n15:04:0" + itoa(tick) + ".0,daemon." + itoa(4821) +
			",0," + itoa(out) + "\n")
	}
	m.runLsof = func() []byte {
		return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
			"daemon 4821 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->198.51.100.7:443 (ESTABLISHED)\n")
	}
	m.procs = func() map[int]*collect.Proc {
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/x/daemon"}}
	}
	m.exePaths = func() map[int]string { return map[int]string{4821: "/x/daemon"} }
	m.trustOf = func(string) string { return "unsigned" }
	m.capsOf = func(string) []string { return nil }

	m.Sample()           // tick 1: first sighting → rate 0, one sample recorded
	groups := m.Sample() // tick 2: rate 100000, second sample recorded
	if len(groups) != 1 || len(groups[0].Members) != 1 {
		t.Fatalf("expected one group with one member, got %+v", groups)
	}
	sp := groups[0].Members[0].Spark
	if len(sp) != 2 {
		t.Fatalf("member Spark should hold 2 ticks of history, got %v", sp)
	}
	if sp[0] != 0 {
		t.Fatalf("first-sight sample should be rate 0, got %d", sp[0])
	}
	if sp[1] == 0 {
		t.Fatalf("second sample should be the non-zero out-rate, got %d", sp[1])
	}
}

// A PID that vanishes (no established connections next tick) must be pruned from the per-PID
// history so the map stays bounded over a long session.
func TestMonitor_PerPIDSparkPrunesDeadPIDs(t *testing.T) {
	m := New(1)
	present := true
	m.runNettop = func() []byte {
		if !present {
			return []byte("time,,bytes_in,bytes_out\n")
		}
		return []byte("time,,bytes_in,bytes_out\n15:04:05.0,daemon.4821,0,200000\n")
	}
	m.runLsof = func() []byte {
		if !present {
			return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n")
		}
		return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
			"daemon 4821 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->198.51.100.7:443 (ESTABLISHED)\n")
	}
	m.procs = func() map[int]*collect.Proc {
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/x/daemon"}}
	}
	m.exePaths = func() map[int]string { return map[int]string{4821: "/x/daemon"} }
	m.trustOf = func(string) string { return "unsigned" }
	m.capsOf = func(string) []string { return nil }

	m.Sample()
	if len(m.sparkPID) != 1 {
		t.Fatalf("expected 1 tracked PID after first tick, got %d", len(m.sparkPID))
	}
	present = false
	m.Sample()
	if len(m.sparkPID) != 0 {
		t.Fatalf("dead PID should be pruned from per-PID history, still have %d", len(m.sparkPID))
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

// Every connection leaf row gets its OWN sparkline + rate: nettop's per-connection byte rows
// are correlated with the lsof-discovered connection and accumulate across ticks.
func TestMonitor_PerConnRateAndSpark(t *testing.T) {
	m := New(1) // interval 1s → rate == byte delta
	tick := 0
	m.runNettop = func() []byte {
		tick++
		out := 50000 * tick // cumulative climbs 50000/tick → per-tick rate 50000
		return []byte("time,,bytes_in,bytes_out\n" +
			"15:04:0" + itoa(tick) + ".0,daemon.4821,0," + itoa(out) + "\n" +
			"15:04:0" + itoa(tick) + ".0,tcp4 10.0.0.2:5<->198.51.100.7:443,0," + itoa(out) + "\n")
	}
	m.runLsof = func() []byte {
		return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
			"daemon 4821 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->198.51.100.7:443 (ESTABLISHED)\n")
	}
	m.procs = func() map[int]*collect.Proc {
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/x/daemon"}}
	}
	m.exePaths = func() map[int]string { return map[int]string{4821: "/x/daemon"} }
	m.trustOf = func(string) string { return "unsigned" }
	m.capsOf = func(string) []string { return nil }

	m.Sample()           // tick 1: first sighting → conn rate 0
	groups := m.Sample() // tick 2: conn rate 50000
	conns := groups[0].Members[0].Conns
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].OutRate != 50000 {
		t.Fatalf("per-connection OutRate: got %d want 50000", conns[0].OutRate)
	}
	if len(conns[0].Spark) != 2 || conns[0].Spark[1] == 0 {
		t.Fatalf("per-connection Spark should hold 2 samples ending non-zero, got %v", conns[0].Spark)
	}
}

// Two connections to the SAME remote endpoint share a connKey; the spark ring must advance
// once per tick, not once per FD (else duplicate rows desync and the ring grows too fast).
func TestMonitor_PerConnSparkDedupsSharedKey(t *testing.T) {
	m := New(1)
	tick := 0
	m.runNettop = func() []byte {
		tick++
		out := 1000 * tick
		return []byte(",bytes_in,bytes_out,\n" +
			"daemon.4821,0," + itoa(out) + ",\n" +
			"tcp4 10.0.0.2:5<->9.9.9.9:443,0," + itoa(out) + ",\n")
	}
	m.runLsof = func() []byte {
		// two FDs from the same PID to the same remote endpoint
		return []byte("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n" +
			"daemon 4821 root 10u IPv4 0x1 0t0 TCP 10.0.0.2:5->9.9.9.9:443 (ESTABLISHED)\n" +
			"daemon 4821 root 11u IPv4 0x2 0t0 TCP 10.0.0.3:6->9.9.9.9:443 (ESTABLISHED)\n")
	}
	m.procs = func() map[int]*collect.Proc {
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/x/daemon"}}
	}
	m.exePaths = func() map[int]string { return map[int]string{4821: "/x/daemon"} }
	m.trustOf = func(string) string { return "unsigned" }
	m.capsOf = func(string) []string { return nil }

	m.Sample()
	m.Sample()
	if got := len(m.sparkConn[connKey(4821, "9.9.9.9", 443)]); got != 2 {
		t.Fatalf("shared connKey ring should advance once/tick (2 ticks → 2 samples), got %d", got)
	}
}
