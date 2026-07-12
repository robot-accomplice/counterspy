# Symbology & Legend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: this plan is executed under the CounterSpy **swarm** (`orchestrator+subagents`). This session is the single writer; each task below is one swarm checkpoint — implement it test-first, then spawn the read-only **Antagonist + Audit** subagent fan-out on the task's `git diff`, vote on findings, then advance. No `spawn_task` chips. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a three-axis mark vocabulary (concern / trust / liveness) rendered as a uniform-cadence cluster across the CLI report, TUI, and egress view, with a documented, drift-proof key — closing tickets T-4 and #23.

**Architecture:** A new pure `internal/mark` package owns the glyph vocabulary, the trust classifier (from codesign Facts), the liveness classifier (from a new running-exec-path set), the fixed-slot cluster formatter, and the `Legend` table that both the in-app legend and the README key render from. `report` and `tui` import `mark`; `mark` imports only `model` + stdlib. Liveness is display-only — the scorer is untouched.

**Tech Stack:** Go 1.24, tcell v2 (TUI only), no new dependencies.

## Global Constraints

- Pure core: `internal/mark`, `internal/model`, `internal/score`, `internal/report` import **no** `os`/`exec`/tcell and do **no** I/O. `mark` may import only `internal/model` + stdlib.
- No emoji — monospace glyphs only. Color carries concern; it is never the *sole* carrier of any axis.
- **Uniform cadence invariant:** every cluster is four fixed slots `[concern][trust][run-state][socket]`, each exactly one glyph or one space, joined by exactly one space (`mark.Gap`). Absent marks are blanks of the same width, never omitted.
- No magic-number/literal glyphs outside `internal/mark` — all surfaces reference `mark.*` constants/functions.
- Tests: no shelling out, no sudo, mockable via pure parsers over fixture bytes. Target ≥80% coverage per package.
- Liveness is **display-only**: it must not change any score, weight, recommendation, or the `score`/`interpret` packages.
- Every step ends green: `go test ./... && go vet ./... && gofmt -l` clean before commit.

---

### Task 1: `internal/mark` — vocabulary, Concern, Trust

**Files:**
- Create: `internal/mark/mark.go`
- Test: `internal/mark/mark_test.go`

**Interfaces:**
- Consumes: `model.Finding`, `model.Evidence`, `model.Recommendation`, `model.KindCodesign`, `model.RecQuarantine`, `model.RecInvestigate`.
- Produces:
  - glyph consts `GlyphQuarantine ▲… ` (see code)
  - `func Concern(r model.Recommendation) rune`
  - `func Trust(f model.Finding) rune` (returns `0` when no codesign signal)

- [ ] **Step 1: Write the failing test**

```go
package mark

import (
	"testing"

	"counterspy/internal/model"
)

func codesign(facts map[string]string) model.Finding {
	return model.Finding{Evidence: []model.Evidence{{Kind: model.KindCodesign, Facts: facts}}}
}

func TestConcern(t *testing.T) {
	if g := Concern(model.RecQuarantine); g != GlyphQuarantine {
		t.Errorf("quarantine: got %q want %q", g, GlyphQuarantine)
	}
	if g := Concern(model.RecInvestigate); g != GlyphInvestigate {
		t.Errorf("investigate: got %q want %q", g, GlyphInvestigate)
	}
	if g := Concern(model.RecMonitor); g != GlyphMonitor {
		t.Errorf("monitor: got %q want %q", g, GlyphMonitor)
	}
}

func TestTrust(t *testing.T) {
	cases := []struct {
		name  string
		facts map[string]string
		want  rune
	}{
		{"apple", map[string]string{"signed": "true", "authority": "Software Signing"}, GlyphApple},
		{"apple-named", map[string]string{"signed": "true", "authority": "Apple Mac OS Application Signing"}, GlyphApple},
		{"notarized-devid", map[string]string{"signed": "true", "authority": "Developer ID Application: Acme (TEAM1)"}, GlyphNotarized},
		{"signed-not-accepted", map[string]string{"signed": "true"}, GlyphSigned},
		{"unsigned", map[string]string{"signed": "false"}, GlyphUnsigned},
		{"revoked", map[string]string{"signed": "revoked"}, GlyphRevoked},
	}
	for _, c := range cases {
		if g := Trust(codesign(c.facts)); g != c.want {
			t.Errorf("%s: got %q want %q", c.name, g, c.want)
		}
	}
	if g := Trust(model.Finding{Evidence: []model.Evidence{{Kind: model.KindTCC}}}); g != 0 {
		t.Errorf("no codesign signal: got %q want blank(0)", g)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mark/ -run 'TestConcern|TestTrust' -v`
Expected: FAIL — build error, `GlyphQuarantine` / `Concern` / `Trust` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// Package mark is the pure symbology vocabulary: the glyph marks CounterSpy
// draws for a finding's concern tier, code-signing trust, and liveness, plus the
// Legend that documents them. It does no I/O and imports only internal/model.
package mark

import (
	"strings"

	"counterspy/internal/model"
)

// Concern (tier) glyphs — carried by BOTH color and glyph.
const (
	GlyphQuarantine  = '⚑'
	GlyphInvestigate = '▲'
	GlyphMonitor     = '·'
)

// Trust (provenance) glyphs — a filled→hollow→struck gradient of decreasing trust.
const (
	GlyphApple     = '●' // Apple system code
	GlyphNotarized = '◆' // Developer ID, Gatekeeper-accepted
	GlyphSigned    = '◇' // signed but not accepted/notarized
	GlyphUnsigned  = '○' // no signature
	GlyphRevoked   = '⊘' // revoked certificate
)

// Liveness glyphs.
const (
	GlyphActive    = '▸' // subject maps to a running process
	GlyphVestigial = '†' // persistence install whose target is not running
	GlyphSocket    = '↔' // holds a network listener
)

// Concern maps a recommendation tier to its glyph.
func Concern(r model.Recommendation) rune {
	switch r {
	case model.RecQuarantine:
		return GlyphQuarantine
	case model.RecInvestigate:
		return GlyphInvestigate
	default:
		return GlyphMonitor
	}
}

// Trust classifies a finding's code-signing provenance from its codesign
// evidence Facts. Returns 0 (blank slot) when the finding carries no codesign
// signal. Apple-authority is checked before Developer-ID so Apple system code
// reads as ● not ◆.
func Trust(f model.Finding) rune {
	for _, e := range f.Evidence {
		if e.Kind != model.KindCodesign {
			continue
		}
		switch e.Facts["signed"] {
		case "revoked":
			return GlyphRevoked
		case "false":
			return GlyphUnsigned
		case "true":
			switch a := e.Facts["authority"]; {
			case a == "":
				return GlyphSigned
			case isAppleAuthority(a):
				return GlyphApple
			default:
				return GlyphNotarized
			}
		}
	}
	return 0
}

func isAppleAuthority(a string) bool {
	return strings.Contains(a, "Apple") || strings.Contains(a, "Software Signing")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mark/ -v && go vet ./internal/mark/`
Expected: PASS. (If `model.RecMonitor` does not exist, use the actual Monitor
constant name from `internal/model/types.go` — grep `Rec` there first.)

- [ ] **Step 5: Commit**

```bash
git add internal/mark/mark.go internal/mark/mark_test.go
git commit -m "feat(mark): symbology vocabulary — concern + trust classifiers"
```

---

### Task 2: `internal/mark` — Liveness type + Classify (#23)

**Files:**
- Modify: `internal/mark/mark.go`
- Test: `internal/mark/liveness_test.go`

**Interfaces:**
- Consumes: `model.Assessment` (embeds `Finding`), `model.KindProcess`, `model.KindPersistence`, `Subject.Key()`, `Subject.Path`, evidence `Facts["listener"]`.
- Produces:
  - `type Liveness struct { RunState rune; Socket rune }`
  - `func Classify(assessments []model.Assessment, running map[string]bool) map[string]Liveness` — keyed by `Subject.Key()`.

- [ ] **Step 1: Write the failing test**

```go
package mark

import (
	"testing"

	"counterspy/internal/model"
)

func ev(kind model.SignalKind, facts map[string]string) model.Evidence {
	return model.Evidence{Kind: kind, Facts: facts}
}

func TestClassify(t *testing.T) {
	running := map[string]bool{"/usr/local/bin/live": true}

	assessments := []model.Assessment{
		// a running process holding a listener → active + socket
		{Finding: model.Finding{
			Subject:  model.Subject{PID: 777},
			Evidence: []model.Evidence{ev(model.KindProcess, map[string]string{"listener": "true"})},
		}},
		// persistence whose target IS running → active, no socket
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/live"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/usr/local/bin/live"})},
		}},
		// persistence whose target is NOT running → vestigial
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/usr/local/bin/dormant"},
			Evidence: []model.Evidence{ev(model.KindPersistence, map[string]string{"target": "/usr/local/bin/dormant"})},
		}},
		// codesign-only finding → no liveness signal (both slots blank)
		{Finding: model.Finding{
			Subject:  model.Subject{Path: "/Applications/Foo.app"},
			Evidence: []model.Evidence{ev(model.KindCodesign, map[string]string{"signed": "false"})},
		}},
	}

	got := Classify(assessments, running)

	want := map[string]Liveness{
		"pid:777":                    {RunState: GlyphActive, Socket: GlyphSocket},
		"path:/usr/local/bin/live":   {RunState: GlyphActive},
		"path:/usr/local/bin/dormant": {RunState: GlyphVestigial},
		"path:/Applications/Foo.app": {},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %+v want %+v", k, got[k], w)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mark/ -run TestClassify -v`
Expected: FAIL — `Liveness` / `Classify` undefined.

- [ ] **Step 3: Write minimal implementation** (append to `internal/mark/mark.go`)

```go
// Liveness is the run-state + socket marks for one subject. A zero field is a
// blank slot. RunState and Socket are independent so ▸ active and ↔ live-socket
// can co-occur.
type Liveness struct {
	RunState rune // GlyphActive, GlyphVestigial, or 0
	Socket   rune // GlyphSocket or 0
}

// Classify derives per-subject liveness (keyed by Subject.Key()). `running` is
// the set of real executable paths of currently-running processes (see
// collect.CollectExecPaths / T-4). Rules:
//   - socket = ↔ if any evidence reports a LISTEN socket (Facts["listener"]=="true")
//   - a finding with process evidence is active (it is a live process)
//   - else a persistence finding is active iff its target path is running, else vestigial
//   - otherwise run-state is blank (a file/grant with no process/persistence liveness)
// Liveness is DISPLAY-ONLY and never influences scoring.
func Classify(assessments []model.Assessment, running map[string]bool) map[string]Liveness {
	out := make(map[string]Liveness, len(assessments))
	for _, a := range assessments {
		var lv Liveness
		var hasProc, hasPersist bool
		for _, e := range a.Evidence {
			if e.Facts["listener"] == "true" {
				lv.Socket = GlyphSocket
			}
			switch e.Kind {
			case model.KindProcess:
				hasProc = true
			case model.KindPersistence:
				hasPersist = true
			}
		}
		switch {
		case hasProc:
			lv.RunState = GlyphActive
		case hasPersist:
			if running[a.Subject.Path] {
				lv.RunState = GlyphActive
			} else {
				lv.RunState = GlyphVestigial
			}
		}
		out[a.Subject.Key()] = lv
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mark/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/mark/mark.go internal/mark/liveness_test.go
git commit -m "feat(mark): liveness classifier — active/vestigial/socket (#23)"
```

---

### Task 3: `internal/mark` — Cluster formatter + Legend

**Files:**
- Modify: `internal/mark/mark.go`
- Test: `internal/mark/cluster_test.go`

**Interfaces:**
- Produces:
  - `const Gap = " "`
  - `func Cluster(concern, trust rune, lv Liveness) string`
  - `type LegendRow struct { Glyph rune; Axis, Meaning string }`
  - `func Legend() []LegendRow`
  - `func LegendLine() string` (one-line CLI footer)

- [ ] **Step 1: Write the failing test**

```go
package mark

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestClusterUniformCadence(t *testing.T) {
	rows := []string{
		Cluster(GlyphQuarantine, GlyphUnsigned, Liveness{RunState: GlyphActive, Socket: GlyphSocket}),
		Cluster(GlyphInvestigate, GlyphSigned, Liveness{RunState: GlyphVestigial}),
		Cluster(GlyphMonitor, GlyphApple, Liveness{}),
		Cluster(GlyphQuarantine, 0, Liveness{}), // no trust signal
	}
	width := len([]rune(rows[0]))
	for i, r := range rows {
		if got := len([]rune(r)); got != width {
			t.Errorf("row %d width %d != %d (%q)", i, got, width, r)
		}
		// cadence: slot,gap,slot,gap,slot,gap,slot -> gaps at fixed rune offsets
		rs := []rune(r)
		for _, off := range []int{1, 3, 5} {
			if rs[off] != ' ' {
				t.Errorf("row %d: expected gap at %d, got %q in %q", i, off, rs[off], r)
			}
		}
	}
	// spot-check exact content
	if got := Cluster(GlyphQuarantine, GlyphUnsigned, Liveness{RunState: GlyphActive, Socket: GlyphSocket}); got != "⚑ ○ ▸ ↔" {
		t.Errorf("cluster: got %q want %q", got, "⚑ ○ ▸ ↔")
	}
	if got := Cluster(GlyphMonitor, GlyphApple, Liveness{}); got != "· ●    " {
		t.Errorf("blank-slots cluster: got %q want %q", got, "· ●    ")
	}
}

func TestLegendCoversEveryGlyph(t *testing.T) {
	// Every glyph the app can emit must have a Legend row (anti-lie).
	all := []rune{
		GlyphQuarantine, GlyphInvestigate, GlyphMonitor,
		GlyphApple, GlyphNotarized, GlyphSigned, GlyphUnsigned, GlyphRevoked,
		GlyphActive, GlyphVestigial, GlyphSocket,
	}
	have := map[rune]bool{}
	for _, r := range Legend() {
		have[r.Glyph] = true
	}
	for _, g := range all {
		if !have[g] {
			t.Errorf("glyph %q has no Legend row", g)
		}
	}
	if !strings.Contains(LegendLine(), string(GlyphUnsigned)) {
		t.Errorf("LegendLine missing %q: %q", GlyphUnsigned, LegendLine())
	}
}

var _ = model.Version // keep model import if otherwise unused
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mark/ -run 'TestCluster|TestLegend' -v`
Expected: FAIL — `Gap`/`Cluster`/`Legend`/`LegendLine` undefined.

- [ ] **Step 3: Write minimal implementation** (append to `internal/mark/mark.go`)

```go
// Gap is the single inter-slot separator. markField is one display cell per slot.
const (
	Gap       = " "
	markField = 1
)

// Cluster renders the four fixed slots [concern][trust][run-state][socket] with
// uniform cadence: each slot is exactly one glyph or one blank cell, joined by
// exactly one Gap. A zero rune renders as a blank slot of the same width.
func Cluster(concern, trust rune, lv Liveness) string {
	slots := [...]rune{concern, trust, lv.RunState, lv.Socket}
	parts := make([]string, len(slots))
	for i, g := range slots {
		parts[i] = pad(g)
	}
	return strings.Join(parts, Gap)
}

func pad(g rune) string {
	if g == 0 {
		return strings.Repeat(" ", markField)
	}
	return string(g) // every vocabulary glyph is width-1 (see spec §3.1)
}

// LegendRow documents one glyph. Legend is the single source of truth rendered
// by both the in-app legend and the README key (see legend_doc_test.go).
type LegendRow struct {
	Glyph   rune
	Axis    string
	Meaning string
}

func Legend() []LegendRow {
	return []LegendRow{
		{GlyphQuarantine, "concern", "quarantine"},
		{GlyphInvestigate, "concern", "investigate"},
		{GlyphMonitor, "concern", "monitor"},
		{GlyphApple, "trust", "Apple system code"},
		{GlyphNotarized, "trust", "notarized (Developer ID, accepted)"},
		{GlyphSigned, "trust", "signed, not notarized"},
		{GlyphUnsigned, "trust", "unsigned"},
		{GlyphRevoked, "trust", "revoked certificate"},
		{GlyphActive, "liveness", "running"},
		{GlyphVestigial, "liveness", "vestigial (installed, not running)"},
		{GlyphSocket, "liveness", "live network socket"},
	}
}

// LegendLine is a compact one-line key for the CLI footer.
func LegendLine() string {
	var b strings.Builder
	b.WriteString("key: ")
	for i, r := range Legend() {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteString(string(r.Glyph))
		b.WriteString(" ")
		b.WriteString(r.Meaning)
	}
	return b.String()
}
```

Note: delete the now-unused `var _ = model.Version` line from the test if `model`
is otherwise imported there; keep it only if the test would fail to compile.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mark/ -v && gofmt -l internal/mark/`
Expected: PASS; gofmt prints nothing.

- [ ] **Step 5: Commit**

```bash
git add internal/mark/mark.go internal/mark/cluster_test.go
git commit -m "feat(mark): uniform-cadence cluster + Legend source of truth"
```

---

### Task 4: T-4 — real running exec paths

**Files:**
- Create: `internal/collect/exec_path.go`
- Test: `internal/collect/exec_path_test.go`

**Interfaces:**
- Produces:
  - `func ParseExecPaths(b []byte) map[string]bool` (pure)
  - `func CollectExecPaths() (map[string]bool, error)` (runs `ps -axo pid=,comm=`)

- [ ] **Step 1: Write the failing test**

```go
package collect

import "testing"

func TestParseExecPaths(t *testing.T) {
	// `ps -axo pid=,comm=` — leading spaces, pid, then the full exec path (may
	// contain spaces). We only need the set of paths.
	out := []byte(
		"  1 /sbin/launchd\n" +
			"777 /usr/local/bin/live\n" +
			"888 /Applications/Some App.app/Contents/MacOS/Some App\n")
	got := ParseExecPaths(out)
	for _, p := range []string{"/sbin/launchd", "/usr/local/bin/live", "/Applications/Some App.app/Contents/MacOS/Some App"} {
		if !got[p] {
			t.Errorf("missing path %q in %v", p, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d paths, want 3: %v", len(got), got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run TestParseExecPaths -v`
Expected: FAIL — `ParseExecPaths` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
package collect

import (
	"os/exec"
	"strconv"
	"strings"
)

// ParseExecPaths turns `ps -axo pid=,comm=` output into the set of real
// executable paths of running processes. Each line is "<pid> <path>"; the path
// may contain spaces, so we split once on the first space after the numeric pid.
// This is the trustworthy exec path (unlike argv0), enabling persistence↔process
// correlation for liveness (ticket T-4).
func ParseExecPaths(b []byte) map[string]bool {
	paths := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimLeft(line, " ")
		if line == "" {
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		if _, err := strconv.Atoi(line[:sp]); err != nil {
			continue // not a "<pid> <path>" line
		}
		if p := strings.TrimSpace(line[sp+1:]); p != "" {
			paths[p] = true
		}
	}
	return paths
}

// CollectExecPaths resolves running processes' real exec paths. Best-effort:
// callers treat an error as "no running-path knowledge" (persistence then reads
// as vestigial rather than crashing).
func CollectExecPaths() (map[string]bool, error) {
	out, err := exec.Command("ps", "-axo", "pid=,comm=").Output()
	if err != nil {
		return nil, err
	}
	return ParseExecPaths(out), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collect/ -run TestParseExecPaths -v && go vet ./internal/collect/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/exec_path.go internal/collect/exec_path_test.go
git commit -m "feat(collect): resolve real running exec paths via ps comm (T-4)"
```

---

### Task 5: CLI report — cluster, summary tier glyphs, footer

**Files:**
- Modify: `internal/report/report.go`
- Modify: `main.go` (the `report.Render` call site so it compiles)
- Test: `internal/report/report_test.go` (add cases)

**Interfaces:**
- Consumes: `mark.Concern`, `mark.Trust`, `mark.Cluster`, `mark.Liveness`, `mark.LegendLine`, `mark.Classify`.
- Produces: `func Render(assessments []model.Assessment, gaps []string, color bool, live map[string]mark.Liveness) string` (new `live` param).

- [ ] **Step 1: Write the failing test**

```go
func TestRenderShowsClusterAndKey(t *testing.T) {
	a := model.Assessment{
		Finding: model.Finding{
			Subject:  model.Subject{Path: "/tmp/xmrig"},
			Evidence: []model.Evidence{{Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}}},
		},
		Recommendation: model.RecQuarantine,
		Verdict:        "unsigned miner",
	}
	live := map[string]mark.Liveness{"path:/tmp/xmrig": {RunState: mark.GlyphActive, Socket: mark.GlyphSocket}}
	out := Render([]model.Assessment{a}, nil, false, live)

	if !strings.Contains(out, "⚑ ○ ▸ ↔") {
		t.Errorf("expected cluster in output:\n%s", out)
	}
	if !strings.Contains(out, mark.LegendLine()) {
		t.Errorf("expected legend footer in output:\n%s", out)
	}
	// summary tier count uses the tier glyph, not ●
	if !strings.Contains(out, string(mark.GlyphQuarantine)+" 1 Quarantine") {
		t.Errorf("expected '⚑ 1 Quarantine' summary:\n%s", out)
	}
}
```

(Add `import "counterspy/internal/mark"` and `strings` to the test file if absent.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestRenderShowsClusterAndKey -v`
Expected: FAIL — `Render` signature mismatch (too few args) / no cluster.

- [ ] **Step 3: Write minimal implementation**

In `internal/report/report.go`:
1. Add `"counterspy/internal/mark"` to imports.
2. Change signature: `func Render(assessments []model.Assessment, gaps []string, color bool, live map[string]mark.Liveness) string`.
3. In the summary counts line, replace the literal `●`/`▲`/`·` with
   `string(mark.GlyphQuarantine)`, `string(mark.GlyphInvestigate)`,
   `string(mark.GlyphMonitor)`.
4. Where each actionable finding is rendered, prefix it with the cluster:

```go
cluster := mark.Cluster(mark.Concern(a.Recommendation), mark.Trust(a.Finding), live[a.Subject.Key()])
// ...render `cluster` at the start of the finding's header line, styled with recStyle(a.Recommendation)...
```

5. Delete the now-unused local `func glyph(...)` (orphaned by step 3/4).
6. Before returning, append the footer (skip when there is nothing actionable is optional; always appending is fine): `fmt.Fprintf(&b, "\n  %s\n", p.s(sDim, mark.LegendLine()))`.

In `main.go`, update the call site (around line 127) to compile:

```go
live := mark.Classify(assessments, nil) // real running paths wired in Task 6
fmt.Fprint(stdout, report.Render(assessments, gaps, colorEnabled(), live))
```

Add `"counterspy/internal/mark"` to `main.go` imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/report/ ./... -run TestRender && go build ./... && go vet ./...`
Expected: PASS; build clean. Fix any other `report.Render` call sites the
compiler flags (there may be one in `main.go` interactive path and in tests).

- [ ] **Step 5: Commit**

```bash
git add internal/report/report.go main.go internal/report/report_test.go
git commit -m "feat(report): render mark cluster + legend footer; tier-glyph summary"
```

---

### Task 6: main pipeline — wire real running paths + liveness

**Files:**
- Modify: `main.go` (scan path, `runTUI`, egress path)
- Test: `main_test.go` (add a case)

**Interfaces:**
- Consumes: `collect.CollectExecPaths`, `mark.Classify`.
- Produces: a helper `func livenessFor(assessments []model.Assessment) map[string]mark.Liveness` used by every render path.

- [ ] **Step 1: Write the failing test**

```go
func TestLivenessForMarksVestigialWhenNotRunning(t *testing.T) {
	a := model.Assessment{Finding: model.Finding{
		Subject:  model.Subject{Path: "/nope/not-running"},
		Evidence: []model.Evidence{{Kind: model.KindPersistence, Facts: map[string]string{"target": "/nope/not-running"}}},
	}}
	got := livenessFor([]model.Assessment{a})
	if got["path:/nope/not-running"].RunState != mark.GlyphVestigial {
		t.Errorf("expected vestigial, got %+v", got["path:/nope/not-running"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestLivenessForMarks -v`
Expected: FAIL — `livenessFor` undefined.

- [ ] **Step 3: Write minimal implementation** (in `main.go`)

```go
// livenessFor resolves running exec paths (best-effort) and classifies liveness
// for the given assessments. A ps failure degrades gracefully to "nothing known
// running" — persistence then reads as vestigial rather than crashing.
func livenessFor(assessments []model.Assessment) map[string]mark.Liveness {
	running, _ := collect.CollectExecPaths()
	return mark.Classify(assessments, running)
}
```

Replace the `mark.Classify(assessments, nil)` from Task 5 with `livenessFor(assessments)`
in the scan path, and pass a `livenessFor(...)`-derived map into `runTUI`'s Model
and the egress render path (Tasks 7 & 8 consume it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(main): wire real running-path liveness into all render paths (T-4/#23)"
```

---

### Task 7: TUI — cluster column + `?` overlay from Legend

**Files:**
- Modify: `internal/tui/model.go` (add `Liveness` field), `internal/tui/view.go`
- Modify: the `NewModel`/construction call in `main.go` `runTUI`
- Test: `internal/tui/view_test.go` (SimulationScreen)

**Interfaces:**
- Consumes: `mark.Cluster`, `mark.Concern`, `mark.Trust`, `mark.Liveness`, `mark.Legend`.
- Produces: `Model.Liveness map[string]mark.Liveness`; the findings table renders the cluster; the `?` help overlay lists `mark.Legend()`.

- [ ] **Step 1: Write the failing test**

```go
func TestViewRendersClusterColumn(t *testing.T) {
	s := tcell.NewSimulationScreen("UTF-8")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.SetSize(120, 24)
	m := Model{
		Assessments: []model.Assessment{{
			Finding:        model.Finding{Subject: model.Subject{Path: "/tmp/xmrig"}, Evidence: []model.Evidence{{Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}}}},
			Recommendation: model.RecQuarantine,
		}},
		Done:     map[string]bool{},
		Liveness: map[string]mark.Liveness{"path:/tmp/xmrig": {RunState: mark.GlyphActive}},
	}
	view(m, s)
	s.Show()
	if !screenContains(s, "⚑") || !screenContains(s, "○") || !screenContains(s, "▸") {
		t.Errorf("expected concern+trust+liveness glyphs on the row")
	}
}
```

(`screenContains` — reuse the existing simulation-screen text helper in the tui
tests; if none exists, add a small helper that scans `s.GetContents()` cells.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestViewRendersClusterColumn -v`
Expected: FAIL — `Model.Liveness` undefined / no glyphs drawn.

- [ ] **Step 3: Write minimal implementation**

1. In `internal/tui/model.go`, add to `Model`: `Liveness map[string]mark.Liveness` and initialize it in the constructor (`map[string]mark.Liveness{}` default). Import `mark`.
2. In `internal/tui/view.go` `drawListRow`, draw the cluster
   `mark.Cluster(mark.Concern(a.Recommendation), mark.Trust(a.Finding), m.Liveness[a.Subject.Key()])`
   at the row's left, before the Display() name; keep the existing tier color.
3. In the `?` help overlay renderer, list each `mark.Legend()` row as
   `"<glyph>  <meaning> (<axis>)"`.
4. In `main.go` `runTUI`, set `Liveness: livenessFor(assessments)` on the Model.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tui/ ./... && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tui/model.go internal/tui/view.go internal/tui/view_test.go main.go
git commit -m "feat(tui): mark cluster column + legend in ? overlay"
```

---

### Task 8: Egress view — trust glyph + `+`/`−` tree toggle

**Files:**
- Modify: `internal/tui/egressview.go`
- Test: `internal/tui/egressview_test.go` (add/adjust)

**Interfaces:**
- Consumes: `mark.Trust`-style trust rendering (egress rows carry a `Trust` string,
  not a `model.Finding`; map that string to a glyph via a small `mark.TrustLabel`
  helper — see step 3).

- [ ] **Step 1: Write the failing test**

```go
func TestEgressTreeTogglesWithPlusMinus(t *testing.T) {
	// collapsed rows show '+', expanded show '−' — never ▸ (reserved for liveness).
	if collapsedMarker(false) != '+' {
		t.Errorf("collapsed marker: got %q want +", collapsedMarker(false))
	}
	if collapsedMarker(true) != '−' {
		t.Errorf("expanded marker: got %q want −", collapsedMarker(true))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestEgressTreeToggles -v`
Expected: FAIL — `collapsedMarker` undefined.

- [ ] **Step 3: Write minimal implementation**

In `internal/tui/egressview.go`:
1. Add `func collapsedMarker(expanded bool) rune { if expanded { return '−' }; return '+' }`.
2. Replace the two `marker = '▾'` / `marker = '▸'` disclosure assignments in
   `drawEgressRow` with `marker = collapsedMarker(expanded[...] /* or expandedPID[...] */)`.
3. Map the egress row `Trust` string to a trust glyph for display (add to
   `internal/mark/mark.go`: `func TrustLabel(s string) rune` mapping the egress
   trust vocabulary — e.g. "apple"/"notarized"/"signed"/"unsigned"/"revoked" —
   to the same glyphs; grep `egressview.go`/egress collector for the exact Trust
   strings first, and add a table test for `TrustLabel`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/tui/ ./internal/mark/ && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressview_test.go internal/mark/mark.go internal/mark/mark_test.go
git commit -m "feat(egress): trust glyph + +/- tree toggle (frees ▸ for liveness)"
```

---

### Task 9: README key + drift-proof golden test

**Files:**
- Modify: `README.md` (add "Reading the marks" with delimited key block)
- Create: `internal/mark/legend_doc_test.go`
- Modify: `internal/mark/mark.go` (add `LegendMarkdown`)

**Interfaces:**
- Produces: `func LegendMarkdown() string` — the canonical key block, embedded in README between markers and asserted equal by the test.

- [ ] **Step 1: Write the failing test**

```go
package mark

import (
	"os"
	"strings"
	"testing"
)

func TestReadmeKeyMatchesLegend(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin = "<!-- BEGIN LEGEND (generated) -->"
	const end = "<!-- END LEGEND -->"
	s := string(b)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("README missing legend markers")
	}
	got := strings.TrimSpace(s[i+len(begin) : j])
	want := strings.TrimSpace(LegendMarkdown())
	if got != want {
		t.Errorf("README key drifted from mark.Legend().\n--- README ---\n%s\n--- want ---\n%s", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/mark/ -run TestReadmeKeyMatchesLegend -v`
Expected: FAIL — `LegendMarkdown` undefined / markers absent.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/mark/mark.go`:

```go
// LegendMarkdown renders the Legend as a Markdown table — the single source the
// README key must match (enforced by legend_doc_test.go).
func LegendMarkdown() string {
	var b strings.Builder
	b.WriteString("| Mark | Axis | Meaning |\n|---|---|---|\n")
	for _, r := range Legend() {
		b.WriteString("| ")
		b.WriteRune(r.Glyph)
		b.WriteString(" | " + r.Axis + " | " + r.Meaning + " |\n")
	}
	return b.String()
}
```

Then run `go run` scratch or copy the `go test` failure's "want" block into
`README.md` under a new section, wrapped exactly:

```markdown
## Reading the marks

Each finding is tagged with a four-slot cluster — concern, trust, and two
liveness slots (`[concern] [trust] [run-state] [socket]`). Color also encodes
concern; the glyphs never rely on color alone.

<!-- BEGIN LEGEND (generated) -->
<paste LegendMarkdown() output here>
<!-- END LEGEND -->
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mark/ -run TestReadmeKeyMatchesLegend -v && go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md internal/mark/mark.go internal/mark/legend_doc_test.go
git commit -m "docs(readme): documented mark key + drift-proof golden test"
```

---

## Post-plan: PR

After Task 9 and a full green `go test ./... -race` + `gofmt -l` + `go vet ./...`,
open a PR `feature/symbology-legend → develop` summarizing the three axes, the
closed tickets (T-4, #23), and the PR #25 coupling flag (spec §8). CI enforces the
≥80%-coverage gate.

## Self-review notes (author)

- Spec §2 vocabulary → Task 1 (trust) + Task 3 (Legend). §2.1 trust map → Task 1.
- §3 uniform cadence → Task 3 cadence golden test. §4 T-4 → Task 4; #23 → Task 2.
- §5 surfaces → Tasks 5 (CLI), 7 (TUI), 8 (egress). §6 collisions → Task 5 (● via
  summary glyphs) + Task 8 (▸ via +/−). §7 legend/docs → Task 3 + Task 9. §8 PR #25
  → flagged in PR step. §9 tests → per-task. §4 scope guard (display-only) → Global
  Constraints + no score/interpret edits in any task.
- Open verification the executor must do live: exact `model.Rec*` Monitor constant
  name (Task 1 step 4), exact egress `Trust` string vocabulary (Task 8 step 3),
  and any additional `report.Render` call sites (Task 5 step 4).
