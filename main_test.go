package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/feedback"
	"counterspy/internal/interpret"
	"counterspy/internal/mark"
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
		for _, want := range []string{"CounterSpy", model.Version, "scan", "console", "feedback", "restore"} {
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
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "console") || !strings.Contains(out, model.Version) {
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
	if code := runConsole([]string{"--json", "--once"}, &buf); code != 0 {
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
	if code := runConsole([]string{"--once"}, &buf); code != 0 {
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

// --- flagValue -------------------------------------------------------------

func TestFlagValue(t *testing.T) {
	if got := flagValue([]string{"--from", "path.json"}, "--from"); got != "path.json" {
		t.Fatalf("space form: got %q", got)
	}
	if got := flagValue([]string{"--from=path.json"}, "--from"); got != "path.json" {
		t.Fatalf("= form: got %q", got)
	}
	if got := flagValue([]string{"--other"}, "--from"); got != "" {
		t.Fatalf("absent: got %q, want empty", got)
	}
	if got := flagValue([]string{"--from"}, "--from"); got != "" {
		t.Fatalf("trailing flag with no value: got %q, want empty", got)
	}
}

// --- colorEnabled / dim (isTerminal seam) -----------------------------------

func TestColorEnabled(t *testing.T) {
	origIsTerminal := isTerminal
	t.Cleanup(func() { isTerminal = origIsTerminal })

	isTerminal = func(*os.File) bool { return true }
	t.Setenv("NO_COLOR", "")
	if !colorEnabled() {
		t.Fatal("want color enabled on a tty with NO_COLOR unset")
	}

	t.Setenv("NO_COLOR", "1")
	if colorEnabled() {
		t.Fatal("NO_COLOR must disable color even on a tty")
	}

	t.Setenv("NO_COLOR", "")
	isTerminal = func(*os.File) bool { return false }
	if colorEnabled() {
		t.Fatal("non-tty must disable color")
	}
}

func TestDim(t *testing.T) {
	origIsTerminal := isTerminal
	t.Cleanup(func() { isTerminal = origIsTerminal })
	t.Setenv("NO_COLOR", "")

	isTerminal = func(*os.File) bool { return true }
	if got := dim("x"); got == "x" || !strings.Contains(got, "x") {
		t.Fatalf("expected ANSI-wrapped string, got %q", got)
	}

	isTerminal = func(*os.File) bool { return false }
	if got := dim("x"); got != "x" {
		t.Fatalf("expected plain string when color disabled, got %q", got)
	}
}

// --- userAllowlist -----------------------------------------------------------

func TestUserAllowlist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgDir := filepath.Join(dir, ".config", "counterspy")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "com.jon.roboticus\n# a comment\n\n/tmp/evil\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "allowlist.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := userAllowlist()
	if !got["com.jon.roboticus"] || !got["/tmp/evil"] || got["# a comment"] || len(got) != 2 {
		t.Fatalf("allowlist parse wrong: %+v", got)
	}
}

func TestUserAllowlist_MissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if got := userAllowlist(); len(got) != 0 {
		t.Fatalf("missing file should yield empty allowlist, got %+v", got)
	}
}

// --- loadSnapshot: missing + oversize cap -----------------------------------

func TestLoadSnapshot_Missing(t *testing.T) {
	if _, err := loadSnapshot(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestLoadSnapshot_OversizeCap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.json")
	big := make([]byte, maxSnapshotBytes+1)
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadSnapshot(p)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

// --- feedbackPaths / chooseTransmitter ---------------------------------------

func TestFeedbackPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	cfgPath, storePath := feedbackPaths()
	wantBase := filepath.Join(dir, ".config", "counterspy")
	if cfgPath != filepath.Join(wantBase, "feedback.json") {
		t.Fatalf("cfgPath = %q", cfgPath)
	}
	if storePath != filepath.Join(wantBase, "feedback-store.json") {
		t.Fatalf("storePath = %q", storePath)
	}
}

func TestChooseTransmitter(t *testing.T) {
	tx := chooseTransmitter(feedback.Config{Endpoint: "http://example.com"}, "/tmp")
	if _, ok := tx.(*feedback.HTTPTransmitter); !ok {
		t.Fatalf("endpoint set should choose HTTPTransmitter, got %T", tx)
	}
	tx2 := chooseTransmitter(feedback.Config{}, "/tmp")
	if _, ok := tx2.(*feedback.FileTransmitter); !ok {
		t.Fatalf("no endpoint should choose FileTransmitter, got %T", tx2)
	}
}

// --- collectAll: fan-out + fail-loud gap note (evidenceCollectors seam) -----

func TestCollectAll_FanOutAndGapNote(t *testing.T) {
	orig := evidenceCollectors
	t.Cleanup(func() { evidenceCollectors = orig })
	evidenceCollectors = []collectorSpec{
		{"gap A", func() ([]model.Evidence, error) {
			return []model.Evidence{{Subject: model.Subject{Label: "com.a"}}}, nil
		}},
		{"gap B", func() ([]model.Evidence, error) {
			return nil, errors.New("boom")
		}},
	}
	ev, gaps := collectAll()
	if len(ev) != 1 || ev[0].Subject.Label != "com.a" {
		t.Fatalf("expected 1 evidence item from the succeeding collector, got %+v", ev)
	}
	if len(gaps) != 1 || gaps[0] != "gap B" {
		t.Fatalf("expected exactly the failing collector's gap note, got %+v", gaps)
	}
}

// --- quarantineLoop: y/N/q branches + error reporting (quarantiner seam) ---

type fakeQuarantiner struct {
	calls int
	err   error
}

func (f *fakeQuarantiner) Quarantine(root, ts string, a model.Assessment) (model.ManifestItem, error) {
	f.calls++
	if f.err != nil {
		return model.ManifestItem{}, f.err
	}
	return model.ManifestItem{}, nil
}

func TestQuarantineLoop_YActs(t *testing.T) {
	as := []model.Assessment{{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/x"}}, Recommendation: model.RecQuarantine}}
	fq := &fakeQuarantiner{}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader("y\n"), fq)
	if fq.calls != 1 {
		t.Fatalf("want 1 call, got %d", fq.calls)
	}
	if !strings.Contains(out.String(), "quarantined ->") {
		t.Fatalf("missing success message: %s", out.String())
	}
}

func TestQuarantineLoop_NSkips(t *testing.T) {
	as := []model.Assessment{{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/x"}}, Recommendation: model.RecQuarantine}}
	fq := &fakeQuarantiner{}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader("n\n"), fq)
	if fq.calls != 0 {
		t.Fatalf("N must not act, got %d calls", fq.calls)
	}
}

func TestQuarantineLoop_QStopsEarly(t *testing.T) {
	as := []model.Assessment{
		{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/x"}}, Recommendation: model.RecQuarantine},
		{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/y"}}, Recommendation: model.RecQuarantine},
	}
	fq := &fakeQuarantiner{}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader("q\n"), fq)
	if fq.calls != 0 {
		t.Fatalf("q must stop before acting, got %d calls", fq.calls)
	}
}

func TestQuarantineLoop_ErrorReportsAndContinues(t *testing.T) {
	as := []model.Assessment{{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/x"}}, Recommendation: model.RecQuarantine}}
	fq := &fakeQuarantiner{err: errors.New("boom")}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader("y\n"), fq)
	if fq.calls != 1 {
		t.Fatalf("want 1 attempted call, got %d", fq.calls)
	}
	if !strings.Contains(out.String(), "stopped (partial state recorded") {
		t.Fatalf("missing error message: %s", out.String())
	}
}

func TestQuarantineLoop_MonitorRecommendationSkippedSilently(t *testing.T) {
	as := []model.Assessment{{Finding: model.Finding{Subject: model.Subject{Path: "/tmp/x"}}, Recommendation: model.RecMonitor}}
	fq := &fakeQuarantiner{}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader(""), fq)
	if fq.calls != 0 || out.Len() != 0 {
		t.Fatalf("Monitor recommendation must be skipped silently, calls=%d out=%q", fq.calls, out.String())
	}
}

func TestQuarantineLoop_NoActionsSkipped(t *testing.T) {
	// A bare process finding (no label, no path) plans no actions — nothing to prompt for.
	as := []model.Assessment{{Finding: model.Finding{Subject: model.Subject{PID: 123}}, Recommendation: model.RecQuarantine}}
	fq := &fakeQuarantiner{}
	var out bytes.Buffer
	quarantineLoop(as, &out, strings.NewReader(""), fq)
	if fq.calls != 0 || out.Len() != 0 {
		t.Fatalf("no-artifact finding must be skipped silently, calls=%d out=%q", fq.calls, out.String())
	}
}

// --- run() dispatch branches --------------------------------------------------

func TestRun_RestoreNoPath(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"restore"}, &buf); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(buf.String(), "usage: counterspy restore") {
		t.Fatalf("missing usage: %s", buf.String())
	}
}

func TestRun_RestoreBadPath(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"restore", "/no/such/manifest.json"}, &buf); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
}

func TestRun_RestoreSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte(`{"Items":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if code := run([]string{"restore", p}, &buf); code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "restored from") {
		t.Fatalf("missing success message: %s", buf.String())
	}
}

func TestRun_FeedbackDispatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	var buf bytes.Buffer
	if code := run([]string{"feedback"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(buf.String(), "pending feedback record") {
		t.Fatalf("missing output: %s", buf.String())
	}
}

func TestRun_ConsoleExfilDispatch(t *testing.T) {
	withFakeEgress(t)
	var buf bytes.Buffer
	if code := run([]string{"console", "--once"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(buf.String(), "backuptool") {
		t.Fatalf("missing output: %s", buf.String())
	}
}

func TestRun_ScanDispatch(t *testing.T) {
	var buf bytes.Buffer
	if code := run([]string{"scan", "--dry"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestRunScan_InteractiveDryEmptyAssessments(t *testing.T) {
	// --dry means no evidence is collected, so quarantineLoop iterates zero assessments —
	// this exercises the runScan -> quarantineLoop wiring without touching stdin.
	var buf bytes.Buffer
	if code := run([]string{"scan", "--dry", "--interactive"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

// --- runFeedback: list / submit / unknown -------------------------------------

func TestRunFeedback_SubmitOff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	var buf bytes.Buffer
	if code := runFeedback([]string{"submit"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(buf.String(), "sharing is off") {
		t.Fatalf("missing message: %s", buf.String())
	}
}

func TestRunFeedback_UnknownSub(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	var buf bytes.Buffer
	if code := runFeedback([]string{"bogus"}, &buf); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(buf.String(), "usage: counterspy feedback") {
		t.Fatalf("missing usage: %s", buf.String())
	}
}

func TestRunFeedback_SubmitAsksAndSends(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")
	cfgDir := filepath.Join(dir, ".config", "counterspy")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "feedback.json"), []byte(`{"share":"always"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	st := feedback.NewStore(filepath.Join(cfgDir, "feedback-store.json"))
	if err := st.Add(feedback.Capture(model.Assessment{
		Finding: model.Finding{Subject: model.Subject{Label: "com.apple.x"}}, Recommendation: model.RecInvestigate,
	}, model.LabelFalsePositive, feedback.DetailPublic, "n1")); err != nil {
		t.Fatal(err)
	}

	// runFeedback submit always asks via os.Stdin — feed it a "y" through a real pipe
	// (os.Stdin is just a package var, safe to swap for the duration of the test).
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	origStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = origStdin })

	var buf bytes.Buffer
	if code := runFeedback([]string{"submit"}, &buf); code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "shared 1 record") {
		t.Fatalf("expected a shared-record confirmation, got: %s", buf.String())
	}
}

// --- runTUI / runEgressTUI: screen seam (newScreen) + isTerminal seam --------

// keyInjectingScreen wraps a real tcell.SimulationScreen so its Init() injects a key
// event immediately after the real Init sets up the event channel — avoiding a race
// against production code's own screen.Init() call (which would otherwise discard any
// event injected beforehand, since Init() replaces the event channel).
type keyInjectingScreen struct {
	tcell.SimulationScreen
	key tcell.Key
	r   rune
}

func (k *keyInjectingScreen) Init() error {
	if err := k.SimulationScreen.Init(); err != nil {
		return err
	}
	k.SimulationScreen.InjectKey(k.key, k.r, tcell.ModNone)
	return nil
}

func TestRunTUI_FromSnapshotQuitsImmediately(t *testing.T) {
	withFakeEgress(t)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SUDO_USER", "")

	origIsTerminal, origNewScreen := isTerminal, newScreen
	t.Cleanup(func() { isTerminal, newScreen = origIsTerminal, origNewScreen })
	isTerminal = func(*os.File) bool { return true }
	newScreen = func() (tcell.Screen, error) {
		return &keyInjectingScreen{SimulationScreen: tcell.NewSimulationScreen(""), key: tcell.KeyRune, r: 'Q'}, nil
	}

	var buf bytes.Buffer
	if code := runConsole([]string{"--from", "testdata/tui_snapshot.json"}, &buf); code != 0 {
		t.Fatalf("exit %d: %s", code, buf.String())
	}
}

func TestRunTUI_NonTerminalRefuses(t *testing.T) {
	origIsTerminal := isTerminal
	t.Cleanup(func() { isTerminal = origIsTerminal })
	isTerminal = func(*os.File) bool { return false }

	// --from a snapshot: the terminal check runs after evidence is gathered, and a live
	// scan would shell out to the real collectors — use the snapshot path to stay hermetic.
	var buf bytes.Buffer
	if code := runConsole([]string{"--from", "testdata/tui_snapshot.json"}, &buf); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(buf.String(), "console needs a terminal") {
		t.Fatalf("missing message: %s", buf.String())
	}
}

// codesignAll runs the per-binary signature check concurrently with a mockable cs func
// (no shelling out), returns evidence in deterministic input order, and reports progress.
func TestCodesignAll_ConcurrentDeterministicWithProgress(t *testing.T) {
	paths := []string{"/a", "/b", "/c", "/d"}
	var calls int64
	cs := func(p string) []model.Evidence {
		atomic.AddInt64(&calls, 1)
		return []model.Evidence{{Subject: model.Subject{Path: p}, Kind: model.KindCodesign}}
	}
	var lastDone, lastTotal int64
	ev := codesignAll(paths, cs, func(done, total int) {
		atomic.StoreInt64(&lastDone, int64(done))
		atomic.StoreInt64(&lastTotal, int64(total))
	})
	if atomic.LoadInt64(&calls) != 4 {
		t.Fatalf("cs called %d times, want 4", calls)
	}
	if len(ev) != 4 || ev[0].Subject.Path != "/a" || ev[3].Subject.Path != "/d" {
		t.Fatalf("evidence not in deterministic input order: %+v", ev)
	}
	if lastDone != 4 || lastTotal != 4 {
		t.Fatalf("final progress = %d/%d, want 4/4", lastDone, lastTotal)
	}
}

func TestCodesignAll_EmptyNoWork(t *testing.T) {
	if ev := codesignAll(nil, func(string) []model.Evidence { t.Fatal("cs must not run for empty input"); return nil }, nil); ev != nil {
		t.Fatalf("empty input should return nil, got %+v", ev)
	}
}

// The startup spinner renders a progress line and clears it on stop, so the multi-second
// code-signature phase is never a silent wait.
func TestScanSpinner_ShowsProgressAndClears(t *testing.T) {
	var buf bytes.Buffer
	var done, total int64
	atomic.StoreInt64(&total, 10)
	atomic.StoreInt64(&done, 4)
	stop := make(chan struct{})
	fin := make(chan struct{})
	go func() { scanSpinner(&buf, &done, &total, stop); close(fin) }()
	time.Sleep(120 * time.Millisecond) // ~1 tick at 90ms
	close(stop)
	<-fin
	out := buf.String()
	if !strings.Contains(out, "code signatures") || !strings.Contains(out, "4/10") {
		t.Fatalf("spinner should render progress, got %q", out)
	}
	if !strings.HasSuffix(out, "\r\033[K") {
		t.Fatalf("spinner should clear its line on stop, got %q", out)
	}
	// The braille glyph is tinted with the mint accent so the progress line reads as chrome.
	if !strings.Contains(out, "\033[38;5;79m") {
		t.Fatalf("spinner glyph should be mint-tinted, got %q", out)
	}
}

// NO_COLOR must strip the spinner's tint (https://no-color.org) while still rendering progress.
func TestScanSpinner_NoColorDropsTint(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	var done, total int64
	atomic.StoreInt64(&total, 3)
	atomic.StoreInt64(&done, 1)
	stop := make(chan struct{})
	fin := make(chan struct{})
	go func() { scanSpinner(&buf, &done, &total, stop); close(fin) }()
	time.Sleep(120 * time.Millisecond)
	close(stop)
	<-fin
	out := buf.String()
	if strings.Contains(out, "\033[38;5;79m") {
		t.Fatalf("NO_COLOR must drop the mint tint, got %q", out)
	}
	if !strings.Contains(out, "1/3") {
		t.Fatalf("progress must still render under NO_COLOR, got %q", out)
	}
}

// collectWithSpinner runs the collectors (mocked here — no shelling out), surfaces gaps, and
// works on both the tty (spinner) and non-tty paths.
func TestCollectWithSpinner_MockedCollectors(t *testing.T) {
	origCol := evidenceCollectors
	evidenceCollectors = []collectorSpec{
		{"unused gap", func() ([]model.Evidence, error) {
			return []model.Evidence{{Subject: model.Subject{PID: 9}, Kind: model.KindProcess}}, nil
		}},
		{"a gap", func() ([]model.Evidence, error) { return nil, errors.New("boom") }},
	}
	t.Cleanup(func() { evidenceCollectors = origCol })
	origTerm := isTerminal
	t.Cleanup(func() { isTerminal = origTerm })

	isTerminal = func(*os.File) bool { return true } // tty → spinner path
	ev, gaps := collectWithSpinner()
	if len(ev) != 1 || ev[0].Subject.PID != 9 {
		t.Fatalf("evidence wrong: %+v", ev)
	}
	if len(gaps) != 1 || gaps[0] != "a gap" {
		t.Fatalf("gap not surfaced: %+v", gaps)
	}

	isTerminal = func(*os.File) bool { return false } // non-tty → plain collectAll
	if ev2, _ := collectWithSpinner(); len(ev2) != 1 {
		t.Fatalf("non-tty path wrong: %+v", ev2)
	}
}

// Task 6 / cp-T5 + #23: interpret derives run-state (against the live-process set) and livenessFor
// maps it to a glyph. A persistence target NOT in the running set is armed ◐ (loaded, will fire —
// not dormant); the same target running is active ▸.
func TestLivenessForMapsRunState(t *testing.T) {
	const target = "/opt/agent-xyz"
	f := model.Finding{
		Subject:  model.Subject{Path: target},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"target": target}}},
	}
	armed := livenessFor(interpret.Assess([]model.Finding{f}, nil))
	if armed["path:"+target].RunState != mark.GlyphArmed {
		t.Errorf("installed, not running → armed ◐, got %+v", armed["path:"+target])
	}
	active := livenessFor(interpret.Assess([]model.Finding{f}, map[string]bool{target: true}))
	if active["path:"+target].RunState != mark.GlyphActive {
		t.Errorf("installed and running → active ▸, got %+v", active["path:"+target])
	}
}
