package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/feedback"
	"counterspy/internal/model"
	"counterspy/internal/tui"
)

// The usual ways a user asks for help must all work and exit 0 (help is success), and the
// help must actually advertise the tool, its version, and every command — including how to
// reach the interactive UI (tui) vs the plain CLI (scan).
func TestRun_HelpFlags(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help", "-?"} {
		var buf bytes.Buffer
		if code := run([]string{arg}, &buf); code != 0 {
			t.Fatalf("%q: exit %d, want 0", arg, code)
		}
		out := buf.String()
		for _, want := range []string{"CounterSpy", model.Version, "scan", "tui", "feedback", "restore"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%q help missing %q in:\n%s", arg, want, out)
			}
		}
	}
}

// No command given is a usage error (exit 2) but must still print the full usage, not an
// anemic one-liner.
func TestRun_NoArgsShowsUsage(t *testing.T) {
	var buf bytes.Buffer
	if code := run(nil, &buf); code != 2 {
		t.Fatalf("no-args exit %d, want 2", code)
	}
	out := buf.String()
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "tui") || !strings.Contains(out, model.Version) {
		t.Fatalf("no-args usage is anemic:\n%s", out)
	}
}

// The version must be discoverable without reading the banner.
func TestRun_Version(t *testing.T) {
	for _, arg := range []string{"version", "--version"} {
		var buf bytes.Buffer
		if code := run([]string{arg}, &buf); code != 0 {
			t.Fatalf("%q exit %d, want 0", arg, code)
		}
		if !strings.Contains(buf.String(), model.Version) {
			t.Fatalf("%q missing version:\n%s", arg, buf.String())
		}
	}
}

// An unknown command fails (exit 2) AND shows usage so the user can recover.
func TestRun_UnknownCommandShowsUsage(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"bogus"}, &buf); code != 2 {
		t.Fatalf("unknown exit %d, want 2", code)
	}
	out := buf.String()
	if !strings.Contains(out, "unknown command") || !strings.Contains(out, "Usage:") {
		t.Fatalf("unknown-command output missing usage:\n%s", out)
	}
}

func TestRun_ScanJSONDryEmitsArray(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"scan", "--json", "--dry"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Fatalf("expected JSON array, got: %s", buf.String())
	}
}

// A PID-only process finding has no on-disk artifact — no quarantine action (matches
// the actor: nothing to move, and we never offer an irreversible kill).
// fakeEgressSampler stands in for egress.Monitor in tests so the report/JSON path never
// shells out to nettop/lsof (those require sudo and aren't present in CI).
type fakeEgressSampler struct{ calls int }

func (f *fakeEgressSampler) Sample() []model.EgressGroup {
	f.calls++
	return []model.EgressGroup{{App: "backuptool", Trust: "unsigned", Concern: model.Elevated,
		ExfilRisk: model.Elevated, Candidate: []string{"screen"}, OutRate: 840_000, Background: true}}
}

// withFakeEgress swaps newEgressMonitor for a fake sampler for the duration of the test.
func withFakeEgress(t *testing.T) {
	t.Helper()
	orig := newEgressMonitor
	newEgressMonitor = func(float64) tui.Sampler { return &fakeEgressSampler{} }
	t.Cleanup(func() { newEgressMonitor = orig })
}

func TestRunEgress_JSONReport(t *testing.T) {
	// Non-TTY (test) → report path; --json emits an array. --once avoids the live loop.
	withFakeEgress(t)
	var buf bytes.Buffer
	if code := runEgress([]string{"--json", "--once"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "[") || !strings.Contains(out, "backuptool") {
		t.Fatalf("expected JSON array with content, got: %s", out)
	}
}

func TestRunEgress_TextReport(t *testing.T) {
	withFakeEgress(t)
	var buf bytes.Buffer
	if code := runEgress([]string{"--once"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(buf.String(), "backuptool") {
		t.Fatalf("text report missing content: %s", buf.String())
	}
}

func TestPlannedActions_ProcessOnlyHasNone(t *testing.T) {
	f := model.Finding{Subject: model.Subject{PID: 8821}}
	if got := plannedActions(f); len(got) != 0 {
		t.Fatalf("process-only finding should have no actions, got %+v", got)
	}
}

func TestLoadSnapshot(t *testing.T) {
	as, err := loadSnapshot("testdata/tui_snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 || as[0].Subject.Label != "com.evil.updater" || as[0].Recommendation != model.RecQuarantine {
		t.Fatalf("snapshot decode wrong: %+v", as)
	}
}

func TestCliActor_Quarantine(t *testing.T) {
	tmp := t.TempDir()
	orig := filepath.Join(tmp, "beacon")
	os.WriteFile(orig, []byte("x"), 0o644)
	real, _ := filepath.EvalSymlinks(orig) // actor requires a canonical path (macOS /var symlink)
	a := model.Assessment{Finding: model.Finding{
		Subject:  model.Subject{Path: real, Label: "com.evil"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"plist": real}}},
	}}
	realRoot, _ := filepath.EvalSymlinks(tmp)
	ca := &cliActor{root: filepath.Join(realRoot, "q"), ts: "t"}
	mp, err := ca.Quarantine(a)
	if err != nil {
		t.Fatalf("cliActor.Quarantine: %v", err)
	}
	if _, err := os.Stat(real); !os.IsNotExist(err) {
		t.Fatal("file should have moved to quarantine")
	}
	if mp == "" {
		t.Fatal("expected a manifest path")
	}
}

// ABORT-TUI Attacker/Domain #2: the actor boundary refuses a read-only (snapshot) actor,
// so read-only isn't a single UI conditional.
func TestCliActor_ReadOnlyRefuses(t *testing.T) {
	ca := &cliActor{root: t.TempDir(), ts: "t", readOnly: true}
	a := model.Assessment{Finding: model.Finding{
		Subject: model.Subject{Path: "/tmp/x", Label: "l"},
		Actions: []model.Action{{Kind: model.ActionMove, From: "/tmp/x"}},
	}}
	if _, err := ca.Quarantine(a); err == nil {
		t.Fatal("a read-only actor must refuse to quarantine")
	}
}

// The user allowlist suppresses a vetted known-good subject by label or path.
func TestFilterAllowed_SuppressesVetted(t *testing.T) {
	as := []model.Assessment{
		{Finding: model.Finding{Subject: model.Subject{Label: "com.jon.roboticus"}}},
		{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/evil"}}},
	}
	out := filterAllowed(as, map[string]bool{"com.jon.roboticus": true})
	if len(out) != 1 || out[0].Subject.Path != "/tmp/evil" {
		t.Fatalf("allowlist should drop only the vetted subject, got %+v", out)
	}
}

// A persistence finding plans a bootout (by label) plus a move of the plist and target.
func TestPlannedActions_PersistenceBootoutAndMoves(t *testing.T) {
	f := model.Finding{
		Subject:  model.Subject{Path: "/Users/me/Library/.hidden/beacon", Label: "com.evil"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"plist": "/Users/me/Library/LaunchAgents/com.evil.plist"}}},
	}
	a := plannedActions(f)
	var boot, moves int
	for _, x := range a {
		if x.Kind == model.ActionBootout {
			boot++
		}
		if x.Kind == model.ActionMove {
			moves++
		}
	}
	if boot != 1 || moves != 2 {
		t.Fatalf("want 1 bootout + 2 moves, got %d/%d (%+v)", boot, moves, a)
	}
}

func TestInvokingUserHome_PrefersSudoUser(t *testing.T) {
	// Fallback: SUDO_USER unset → non-empty home.
	t.Setenv("SUDO_USER", "")
	if invokingUserHome() == "" {
		t.Fatal("expected a non-empty home fallback")
	}
	// Preference: SUDO_USER set to a real, lookup-able user → that user's home wins over root's.
	cur, err := user.Current()
	if err != nil {
		t.Skip("cannot resolve current user")
	}
	t.Setenv("SUDO_USER", cur.Username)
	if got := invokingUserHome(); got != cur.HomeDir {
		t.Fatalf("SUDO_USER=%q should resolve to %q, got %q", cur.Username, cur.HomeDir, got)
	}
}

func TestCliActor_LabelWritesStore(t *testing.T) {
	dir := t.TempDir()
	st := feedback.NewStore(filepath.Join(dir, "feedback.json"))
	ca := &cliActor{store: st, detail: feedback.DetailPublic}
	a := model.Assessment{Finding: model.Finding{Subject: model.Subject{Label: "com.apple.x", Path: "/x"}}, Recommendation: model.RecInvestigate}
	if err := ca.Label(a, true); err != nil {
		t.Fatal(err)
	}
	p, _ := st.Pending()
	if len(p) != 1 || p[0].Label != model.LabelFalsePositive {
		t.Fatalf("label not persisted: %+v", p)
	}
}

type fakeTx struct {
	sent  int
	calls int
}

func (f *fakeTx) Send(_ context.Context, rs []model.FeedbackRecord) error {
	f.calls++
	f.sent += len(rs)
	return nil
}

func seedStore(t *testing.T) (*feedback.Store, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "store.json")
	st := feedback.NewStore(p)
	if err := st.Add(feedback.Capture(model.Assessment{
		Finding: model.Finding{Subject: model.Subject{Label: "com.apple.x"}}, Recommendation: model.RecInvestigate,
	}, model.LabelFalsePositive, feedback.DetailPublic, "n1")); err != nil {
		t.Fatal(err)
	}
	return st, p
}

func TestSubmit_OffNeverSends(t *testing.T) {
	st, _ := seedStore(t)
	tx := &fakeTx{}
	err := submitFeedback(feedback.Config{Share: feedback.ShareOff}, st, tx, false, strings.NewReader(""), io.Discard)
	if err != nil || tx.calls != 0 {
		t.Fatalf("off must never send: calls=%d err=%v", tx.calls, err)
	}
}

func TestSubmit_AlwaysSendsAndMarksSent(t *testing.T) {
	st, _ := seedStore(t)
	tx := &fakeTx{}
	if err := submitFeedback(feedback.Config{Share: feedback.ShareAlways}, st, tx, false, strings.NewReader(""), io.Discard); err != nil {
		t.Fatal(err)
	}
	if tx.sent != 1 {
		t.Fatalf("always must send pending, sent=%d", tx.sent)
	}
	if p, _ := st.Pending(); len(p) != 0 {
		t.Fatalf("sent records must be marked, pending=%d", len(p))
	}
}

func TestSubmit_AskRequiresYes(t *testing.T) {
	st, _ := seedStore(t)
	txNo := &fakeTx{}
	_ = submitFeedback(feedback.Config{Share: feedback.ShareAsk}, st, txNo, true, strings.NewReader("n\n"), io.Discard)
	if txNo.calls != 0 {
		t.Fatal("ask + 'n' must not send")
	}
	st2, _ := seedStore(t)
	txYes := &fakeTx{}
	_ = submitFeedback(feedback.Config{Share: feedback.ShareAsk}, st2, txYes, true, strings.NewReader("y\n"), io.Discard)
	if txYes.sent != 1 {
		t.Fatal("ask + 'y' must send")
	}
}
