// internal/tui/egresstreearmed_test.go
package tui

import (
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Part-A honesty (v0.7.0 ABORT re-review): while the intercept proxy is armed, a proxy-honoring app's
// egress destination as seen by nettop IS the loopback proxy, not the real remote. The tree must not
// let the user read 127.0.0.1 as the app's destination.

func TestExfilTitle_StatesArmedOnlyWhenArmed(t *testing.T) {
	if got := exfilTitle(false); strings.Contains(got, "armed") {
		t.Fatalf("unarmed title must not claim armed: %q", got)
	}
	if got := exfilTitle(true); !strings.Contains(got, "armed") {
		t.Fatalf("armed title must state intercept armed: %q", got)
	}
}

func TestDestCell_RelabelsProxyButNotRealRemote(t *testing.T) {
	label, isProxy := destCell("127.0.0.1:62443", "127.0.0.1:62443", "127.0.0.1:62443")
	if !isProxy || strings.Contains(label, "127.0.0.1") || !strings.Contains(label, "proxy") {
		t.Fatalf("a proxy endpoint must be relabeled off its raw loopback IP, got %q (isProxy=%v)", label, isProxy)
	}
	label, isProxy = destCell("api.example.com:443", "198.51.100.7:443", "127.0.0.1:62443")
	if isProxy || label != "api.example.com:443" {
		t.Fatalf("a real remote must be shown verbatim, got %q (isProxy=%v)", label, isProxy)
	}
	if _, isProxy := destCell("127.0.0.1:62443", "127.0.0.1:62443", ""); isProxy {
		t.Fatal("not armed: nothing is the proxy")
	}
}

// The armed relabel must keep the "+N" more-destinations hint (topDest emits "ip:port +N"), so the
// collapsed row still tells the user the app has other destinations (ABORT re-review low-sev residual).
func TestDestCell_PreservesMoreDestinationsHint(t *testing.T) {
	label, isProxy := destCell("127.0.0.1:62443 +2", "127.0.0.1:62443", "127.0.0.1:62443")
	if !isProxy || !strings.Contains(label, "proxy") || !strings.Contains(label, "+2") {
		t.Fatalf("armed relabel must keep the +N more-destinations hint, got %q", label)
	}
	if strings.Contains(label, "127.0.0.1") {
		t.Fatalf("armed relabel must not show the raw loopback IP, got %q", label)
	}
}

func renderEgress(t *testing.T, m EgressModel, w, h int) string {
	t.Helper()
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	defer s.Fini()
	s.SetSize(w, h)
	egressView(m, s)
	s.Show()
	cells, cw, ch := s.GetContents()
	var b strings.Builder
	for y := 0; y < ch; y++ {
		for x := 0; x < cw; x++ {
			r := cells[y*cw+x].Runes
			if len(r) == 0 || r[0] == 0 {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r[0])
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestEgressView_ArmedTreeRelabelsProxyDestination(t *testing.T) {
	conn := model.Conn{PID: 500, Endpoint: model.Endpoint{IP: "127.0.0.1", Port: 62443}, Proto: "tcp", OutRate: 1000}
	g := model.EgressGroup{
		App: "Slack", Path: "/Applications/Slack.app/Contents/MacOS/Slack", Trust: "notarized", OutRate: 1000,
		Destinations: []model.Endpoint{{IP: "127.0.0.1", Port: 62443}},
		Conns:        []model.Conn{conn},
		Members:      []model.EgressInstance{{PID: 500, Path: "/Applications/Slack.app/Contents/MacOS/Slack", OutRate: 1000, Conns: []model.Conn{conn}}},
	}
	m := NewEgress()
	m.ProxyAddr = "127.0.0.1:62443"
	m.Groups = []model.EgressGroup{g}
	m.sampled = true

	screen := renderEgress(t, m, 120, 16)
	if !strings.Contains(screen, "intercept proxy") {
		t.Fatalf("armed tree must relabel the loopback proxy destination as the intercept proxy:\n%s", screen)
	}
	if !strings.Contains(screen, "armed") {
		t.Fatalf("armed tree must show an armed indicator so 127.0.0.1 is not read as the real remote:\n%s", screen)
	}
}

// Unarmed, the tree shows real destinations verbatim (no relabel, no armed indicator).
func TestEgressView_UnarmedTreeShowsRealDestination(t *testing.T) {
	conn := model.Conn{PID: 500, Endpoint: model.Endpoint{IP: "198.51.100.7", Port: 443}, Proto: "tcp", OutRate: 1000}
	g := model.EgressGroup{
		App: "curl", Path: "/usr/bin/curl", Trust: "apple", OutRate: 1000,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}},
		Conns:        []model.Conn{conn},
		Members:      []model.EgressInstance{{PID: 500, Path: "/usr/bin/curl", OutRate: 1000, Conns: []model.Conn{conn}}},
	}
	m := NewEgress()
	m.Groups = []model.EgressGroup{g}
	m.sampled = true

	screen := renderEgress(t, m, 120, 16)
	if !strings.Contains(screen, "198.51.100.7") {
		t.Fatalf("unarmed tree must show the real destination IP:\n%s", screen)
	}
	if strings.Contains(screen, "armed") || strings.Contains(screen, "intercept proxy") {
		t.Fatalf("unarmed tree must not show intercept-armed decorations:\n%s", screen)
	}
}
