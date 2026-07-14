package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// TestGenerateScreens renders the console views through the REAL draw code with representative
// fixture data and writes each as a trimmed text "screenshot" for the README. It is gated on
// COUNTERSPY_SCREENS_DIR so it never runs in CI (it writes files); the point is authentic renders
// (real layout, invented numbers) rather than hand-drawn ASCII that can drift.
func TestGenerateScreens(t *testing.T) {
	dir := os.Getenv("COUNTERSPY_SCREENS_DIR")
	if dir == "" {
		t.Skip("set COUNTERSPY_SCREENS_DIR to regenerate README screenshots")
	}
	write := func(name string, w, h int, draw func(s tcell.SimulationScreen)) {
		s := tcell.NewSimulationScreen("")
		if err := s.Init(); err != nil {
			t.Fatal(err)
		}
		s.SetSize(w, h)
		draw(s)
		s.Show()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(trimScreen(s)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// --- Exfiltration tree ---
	write("exfil-tree.txt", 92, 20, func(s tcell.SimulationScreen) {
		egressView(NewEgress().withGroups(demoGroups()), s)
	})

	// --- Zoom dashboard, by PID ---
	write("zoom-pid.txt", 104, 26, func(s tcell.SimulationScreen) {
		m := NewEgress().withGroups([]model.EgressGroup{demoZoomGroup()})
		m.Zoom = &zoomState{app: "claude", sel: 0, mode: trendOut}
		drawEgressZoom(s, m)
	})

	// --- Zoom dashboard, by destination (destinations box focused) ---
	write("zoom-dest.txt", 104, 26, func(s tcell.SimulationScreen) {
		m := NewEgress().withGroups([]model.EgressGroup{demoZoomGroup()})
		m.Zoom = &zoomState{app: "claude", selDest: 0, mode: trendOut, byDest: true}
		drawEgressZoom(s, m)
	})

	// --- Inspect (encrypted flow) ---
	write("inspect.txt", 92, 12, func(s tcell.SimulationScreen) {
		insp := &inspection{
			target: inspectTarget{app: "claude", pid: 1802, trust: "notarized",
				conn: model.Conn{Endpoint: model.Endpoint{IP: "2607:6bc0::10", Port: 443}, Proto: "tcp"}},
			view: model.InspectView{Verdict: "ENCRYPTED · not decrypted (metadata only)",
				Coverage: model.InspectMetadata, SentBytes: 9216, RecvBytes: 354},
		}
		drawInspect(s, insp, false)
	})
}

// trimScreen dumps a SimulationScreen to text with trailing blank rows/cols removed.
func trimScreen(s tcell.SimulationScreen) string {
	cells, w, h := s.GetContents()
	rows := make([]string, h)
	maxCol := 0
	for y := 0; y < h; y++ {
		var b strings.Builder
		for x := 0; x < w; x++ {
			r := cells[y*w+x].Runes
			if len(r) > 0 && r[0] != 0 {
				b.WriteRune(r[0])
			} else {
				b.WriteByte(' ')
			}
		}
		rows[y] = strings.TrimRight(b.String(), " ")
		if len(rows[y]) > maxCol {
			maxCol = len(rows[y])
		}
	}
	// drop trailing all-blank rows
	end := h
	for end > 0 && rows[end-1] == "" {
		end--
	}
	return strings.Join(rows[:end], "\n") + "\n"
}

// wave builds an n-sample rate history: a base level plus a triangle oscillation, so the graph
// renders a readable line rather than flat or random noise.
func wave(n int, base, amp uint64, period, phase int) []uint64 {
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		p := (i + phase) % period
		tri := p
		if p > period/2 {
			tri = period - p
		}
		out[i] = base + amp*uint64(tri)/uint64(period/2)
	}
	return out
}

func demoZoomGroup() model.EgressGroup {
	return model.EgressGroup{App: "claude", Trust: "notarized", Instances: 3, Cadence: "periodic",
		Background: false, Capabilities: []string{"screen", "keystrokes"},
		OutRate: 1_500_000, InRate: 120_000,
		Conns: []model.Conn{
			{PID: 1802, Endpoint: model.Endpoint{IP: "2607:6bc0::10", Port: 443}, Proto: "tcp", OutRate: 1_400_000, Spark: wave(48, 200_000, 1_200_000, 16, 0)},
			{PID: 1990, Endpoint: model.Endpoint{IP: "140.82.113.26", Port: 443}, Proto: "tcp", OutRate: 80_000, Spark: wave(48, 40_000, 120_000, 12, 5)},
			{PID: 2044, Endpoint: model.Endpoint{IP: "17.253.7.7", Port: 443}, Proto: "tcp", OutRate: 20_000, Spark: wave(48, 5_000, 60_000, 20, 9)},
		},
		Members: []model.EgressInstance{
			{PID: 1802, Path: "/Applications/Claude.app/…/Claude Helper (GPU)", Trust: "notarized",
				OutRate: 1_400_000, InRate: 120_000,
				Spark: wave(48, 200_000, 1_200_000, 16, 0), InSpark: wave(48, 20_000, 100_000, 16, 3),
				Conns: []model.Conn{{PID: 1802, Endpoint: model.Endpoint{IP: "2607:6bc0::10", Port: 443}, Proto: "tcp", OutRate: 1_400_000}}},
			{PID: 1990, Path: "/Applications/Claude.app/…/Claude Helper", Trust: "notarized",
				OutRate: 80_000, InRate: 2_000,
				Spark: wave(48, 40_000, 120_000, 12, 5), InSpark: wave(48, 1_000, 4_000, 12, 2),
				Conns: []model.Conn{{PID: 1990, Endpoint: model.Endpoint{IP: "140.82.113.26", Port: 443}, Proto: "tcp", OutRate: 80_000}}},
			{PID: 2044, Path: "/Applications/Claude.app/…/Claude Helper (Renderer)", Trust: "notarized",
				OutRate: 20_000, InRate: 0,
				Spark: wave(48, 5_000, 60_000, 20, 9), InSpark: wave(48, 0, 0, 20, 0),
				Conns: []model.Conn{{PID: 2044, Endpoint: model.Endpoint{IP: "17.253.7.7", Port: 443}, Proto: "tcp", OutRate: 20_000}}},
		}}
}

func demoGroups() []model.EgressGroup {
	g := func(app, trust string, out uint64, ip string, port int, concern model.ConcernLevel, spark []uint64) model.EgressGroup {
		return model.EgressGroup{App: app, Trust: trust, Instances: 1, OutRate: out, Concern: concern,
			Spark: spark, Cadence: "steady",
			Conns:        []model.Conn{{Endpoint: model.Endpoint{IP: ip, Port: port}, Proto: "tcp", OutRate: out}},
			Destinations: []model.Endpoint{{IP: ip, Port: port}},
		}
	}
	return []model.EgressGroup{
		g("claude", "notarized", 1_200_000, "2607:6bc0::10", 443, model.Minimal, wave(24, 3, 9, 8, 0)),
		g("backuptool", "unsigned", 315_000, "185.70.42.39", 443, model.Elevated, wave(24, 5, 8, 6, 2)),
		g("Notion Calendar Helper", "notarized", 65_000, "2606:50c0::1", 443, model.Minimal, wave(24, 2, 6, 10, 1)),
		g("legacy-sync", "signed", 41_000, "192.0.2.9", 80, model.Notable, wave(24, 1, 7, 5, 3)),
		g("adb", "unknown", 800, "127.0.0.1", 5037, model.Low, wave(24, 0, 3, 7, 0)),
		g("firefox", "notarized", 0, "140.82.113.25", 443, model.Minimal, wave(24, 0, 2, 9, 4)),
	}
}
