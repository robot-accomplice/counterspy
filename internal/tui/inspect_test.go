package tui

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// fakeInspector records how many captures were requested and returns a canned view.
type fakeInspector struct {
	calls atomic.Int64
	view  model.InspectView
}

func (f *fakeInspector) Inspect(model.Conn) model.InspectView {
	f.calls.Add(1)
	return f.view
}

func simInit(t *testing.T) tcell.SimulationScreen {
	t.Helper()
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 40)
	return s
}

// `i` on a resolvable row requests the capture directly — there is no consent gate (the user is
// inspecting their own machine's own traffic; the own-machine-only boundary is architectural).
func TestEgressInspect_RequestsDirectly(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("backuptool", model.Elevated, 900)})
	m, _ = egressUpdate(m, tcell.KeyRight, 0) // expand app → reveals the instance row
	m.Selected = 1                            // select the instance row

	m, _ = egressUpdate(m, tcell.KeyRune, 'i')
	if m.InspectReq == nil {
		t.Fatal("`i` on a resolvable row must queue the capture request directly")
	}
}

// The target resolves from the selected row: an app header is ambiguous (a hint, no flow); an
// instance row uses its busiest connection; a connection row is that exact flow.
func TestResolveInspectTarget(t *testing.T) {
	g := eg("backuptool", model.Elevated, 900)
	g.Members[0].Conns = append(g.Members[0].Conns,
		model.Conn{PID: 100, Endpoint: model.Endpoint{IP: "9.9.9.9", Port: 8443}, Proto: "tcp", OutRate: 5000})
	m := NewEgress().withGroups([]model.EgressGroup{g})

	// App header selected, collapsed → ambiguous.
	if tgt, hint := resolveInspectTarget(m.visibleRows(), 0); tgt != nil || hint == "" {
		t.Fatalf("app header must yield a hint, not a flow (got %v)", tgt)
	}

	m, _ = egressUpdate(m, tcell.KeyRight, 0) // expand app
	rows := m.visibleRows()
	tgt, _ := resolveInspectTarget(rows, 1) // instance row
	if tgt == nil || tgt.pid != 100 || tgt.conn.Endpoint.Port != 8443 {
		t.Fatalf("instance row must resolve to its busiest connection, got %+v", tgt)
	}

	m.Selected = 1
	m, _ = egressUpdate(m, tcell.KeyRight, 0) // expand the instance → conn rows
	rows = m.visibleRows()
	// The first conn row (index 2) is the exact flow it points at.
	ctgt, _ := resolveInspectTarget(rows, 2)
	if ctgt == nil || ctgt.conn.Endpoint.Port != 443 {
		t.Fatalf("connection row must resolve to that exact flow, got %+v", ctgt)
	}
}

// The result overlay is modal: `r` toggles secret masking, esc closes back to the tree.
func TestEgressInspect_RevealAndClose(t *testing.T) {
	m := NewEgress()
	m.Inspection = &inspection{view: model.InspectView{Verdict: "plaintext — readable (not encrypted)"}}

	m, _ = egressUpdate(m, tcell.KeyRune, 'r')
	if !m.Reveal {
		t.Fatal("`r` should reveal")
	}
	m, _ = egressUpdate(m, tcell.KeyRune, 'r')
	if m.Reveal {
		t.Fatal("`r` should toggle back to masked")
	}
	m, _ = egressUpdate(m, tcell.KeyEscape, 0)
	if m.Inspection != nil {
		t.Fatal("esc must close the inspection overlay")
	}
}

// The inspection pane renders the honest verdict + SNI, and masks a secret in the content pane
// until revealed (§6).
func TestDrawInspect_MasksSecretUntilRevealed(t *testing.T) {
	s := simInit(t)
	insp := &inspection{
		target: inspectTarget{app: "badapp", pid: 100, trust: "signed",
			conn: model.Conn{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp"}},
		view: model.InspectView{
			SNI:      "api.evil.example.com",
			Verdict:  "ENCRYPTED · SNI api.evil.example.com · not decrypted (metadata only)",
			Coverage: model.InspectMetadata,
			Content:  "GET /x HTTP/1.1\nAuthorization: Bearer ya29.SECRETTOKENvalue\n",
		},
	}
	drawInspect(s, insp, false)
	s.Show()
	if !simContains(s, "api.evil.example.com") || !simContains(s, "badapp") {
		t.Fatal("pane must show the SNI and the app header")
	}
	if simContains(s, "ya29.SECRETTOKENvalue") {
		t.Fatal("a bearer token must be masked by default (§6)")
	}
	if !simContains(s, "[redacted]") {
		t.Fatal("masked content should show the redaction marker")
	}

	drawInspect(s, insp, true)
	s.Show()
	if !simContains(s, "ya29.SECRETTOKENvalue") {
		t.Fatal("reveal must show the real bytes")
	}
}

// End-to-end through RunConsole: `i` captures directly (no consent gate); the verdict renders;
// the secret is masked until `r`; esc returns to the tree.
func TestRunConsole_InspectEndToEnd(t *testing.T) {
	s := simInit(t)
	fi := &fakeInspector{view: model.InspectView{
		Verdict:  "plaintext — readable (not encrypted)",
		Coverage: model.InspectPlaintext,
		Content:  "POST /steal\nAuthorization: Bearer tok_hunter2exfil_SECRET",
	}}
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	tick := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- RunConsole(s, New(nil, nil), &fakeActor{}, sampler, fi, tick, nil) }()

	step := func() { time.Sleep(35 * time.Millisecond) }
	s.InjectKey(tcell.KeyTab, 0, tcell.ModNone) // → Exfiltration (warm sample)
	step()
	s.InjectKey(tcell.KeyRight, 0, tcell.ModNone) // expand app
	step()
	s.InjectKey(tcell.KeyDown, 0, tcell.ModNone) // select the instance row
	step()
	s.InjectKey(tcell.KeyRune, 'i', tcell.ModNone) // request inspection → captures immediately
	step()
	if fi.calls.Load() != 1 {
		t.Fatalf("`i` must trigger exactly one capture (no consent gate), got %d", fi.calls.Load())
	}
	if !simContains(s, "plaintext") {
		t.Fatal("the coverage verdict should render")
	}
	if simContains(s, "tok_hunter2exfil_SECRET") {
		t.Fatal("a bearer token must be masked by default (§6)")
	}

	s.InjectKey(tcell.KeyRune, 'r', tcell.ModNone) // reveal
	step()
	if !simContains(s, "tok_hunter2exfil_SECRET") {
		t.Fatal("reveal should expose the content")
	}

	s.InjectKey(tcell.KeyEscape, 0, tcell.ModNone) // back to the tree
	step()
	if !simContains(s, "Exfiltration") {
		t.Fatal("esc should return to the exfil view")
	}

	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunConsole did not exit")
	}
}

func TestWrapText(t *testing.T) {
	// word-wrap on spaces, no line over width
	got := wrapText("the quick brown fox jumps", 10)
	for _, ln := range got {
		if len([]rune(ln)) > 10 {
			t.Fatalf("line exceeds width: %q", ln)
		}
	}
	if strings.Join(got, " ") != "the quick brown fox jumps" {
		t.Fatalf("words must be preserved, got %q", got)
	}
	// a token longer than width is hard-broken, never dropped
	long := wrapText("buf0=deadbeefdeadbeefdeadbeef", 8)
	if strings.Join(long, "") != "buf0=deadbeefdeadbeefdeadbeef" {
		t.Fatalf("hard-break must preserve all runes, got %q", long)
	}
	for _, ln := range long {
		if len([]rune(ln)) > 8 {
			t.Fatalf("hard-break line exceeds width: %q", ln)
		}
	}
	// existing newlines start new lines
	if got := wrapText("a\nb", 80); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("newlines must split, got %q", got)
	}
}
