# CounterSpy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `counterspy`, a macOS CLI that collects four correlated spyware signals, scores them with a pure engine, and quarantines (reversibly) the items a user approves.

**Architecture:** Strict three-phase pipeline — `collect` (read-only, shells out to native macOS tools, each collector split into an exec edge + a pure parser) → `score` (a pure `[]Evidence → []Finding` function: group by subject, sum weights, correlation multiplier, allowlist, tripwires) → `act` (consented, reversible quarantine + restore, recorded in `manifest.json`). `model` sits at the center; everything depends inward on it (clean-architecture dependency rule).

**Tech Stack:** Go (stdlib only for v1 — `testing`, `encoding/json`, `howett.net/plist` is avoided; plists parsed via `plutil -convert xml1` at the exec edge or a tiny stdlib XML struct). Native tools: `launchctl`, `codesign`, `spctl`, `ps`, `lsof`, `sqlite3`.

## Global Constraints

- Binary name `counterspy`; Go module path `counterspy`; project root `~/code/counterspy/`.
- Go 1.21+ (uses `slices`, `cmp`). Stdlib only — no third-party deps in v1.
- Runs under `sudo`; **never deletes** — quarantine only moves. Permanent deletion is out of scope for v1.
- No magic numbers: every weight/threshold is a named constant in `internal/score/weights.go`.
- The scorer (`internal/score`) MUST stay pure — no imports of `os`, `exec`, `fmt` for I/O, no filesystem/network. Presentation logic must never live in `score` or `collect`.
- Every collector is split: an exec function (I/O, untested) + a `Parse…` function (pure, unit-tested against recorded fixtures in `testdata/`).
- Test framework: Go stdlib `testing`, table-driven where natural. Commit after every green test.

---

## File Structure

```
counterspy/
  go.mod
  main.go                       # flags + subcommands, orchestrates phases
  internal/
    model/types.go              # Evidence, Subject, Finding, Action, Manifest, SignalKind
    score/
      weights.go                # named constants: weights, threshold, correlation, tripwires
      allowlist.go              # IsAllowlisted(authority) bool
      score.go                  # Score([]Evidence) []Finding  (pure)
    collect/
      persistence.go            # ParsePersistencePlist + dir walker
      codesign.go               # ParseCodesign + exec
      proctree.go               # ParsePs, ParseLsof, BuildProcessEvidence + exec
      tcc.go                    # ParseTCC + exec
    report/report.go            # Render(human) + RenderJSON
    act/
      quarantine.go             # Quarantine(root, finding) → ManifestItem
      restore.go                # Restore(manifestPath)
  testdata/                     # recorded CLI output + fixtures
  docs/architext/               # generated architecture docs (Task 13)
  docs/threat-model.md          # ABORT input (Task 13)
```

---

### Task 1: Project scaffold + shared model

**Files:**
- Create: `go.mod`, `main.go`, `internal/model/types.go`
- Test: `internal/model/types_test.go`

**Interfaces:**
- Produces: `model.SignalKind` (+ consts `KindPersistence`, `KindCodesign`, `KindTCC`, `KindProcess`); `model.Subject{Path string; PID int; Label string}` with `func (Subject) Key() string`; `model.Evidence{Subject Subject; Kind SignalKind; Summary string; Weight int; Facts map[string]string}`; `model.Action{Kind, From, To string}`; `model.Finding{Subject Subject; Score int; Kinds []SignalKind; Evidence []Evidence; Tripwire string; Actions []Action}`; `model.Manifest{Timestamp string; Items []ManifestItem}`; `model.ManifestItem{Subject Subject; Actions []Action; Evidence []Evidence}`.

- [ ] **Step 1: Create the module**

```bash
cd ~/code/counterspy && go mod init counterspy && go version
```
Expected: `go.mod` created; version ≥ go1.21.

- [ ] **Step 2: Write the failing test for Subject.Key()**

`internal/model/types_test.go`:
```go
package model

import "testing"

func TestSubjectKey_PrefersPath(t *testing.T) {
	s := Subject{Path: "/tmp/evil", PID: 42}
	if got := s.Key(); got != "path:/tmp/evil" { // [swarm cp-2: namespaced key]
		t.Fatalf("want path key, got %q", got)
	}
}

func TestSubjectKey_FallsBackToPID(t *testing.T) {
	s := Subject{PID: 42}
	if got := s.Key(); got != "pid:42" {
		t.Fatalf("want pid key, got %q", got)
	}
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/model/`
Expected: FAIL — `undefined: Subject` / build error.

- [ ] **Step 4: Write `internal/model/types.go`**

```go
// Package model is the shared vocabulary. It does no I/O and imports nothing
// outside the standard library's fmt.
package model

import "fmt"

type SignalKind string

const (
	KindPersistence SignalKind = "persistence"
	KindCodesign    SignalKind = "codesign"
	KindTCC         SignalKind = "tcc"
	KindProcess     SignalKind = "process"
)

// Subject is who a piece of evidence is about.
type Subject struct {
	Path  string
	PID   int
	Label string
}

// Key is the correlation identity; namespaces are tagged ("path:" vs "pid:") so a
// captured path can never alias a synthetic PID key. Precedence: Path present drops
// PID from the key. [swarm cp-2: namespacing added to fix QA/Audit F-1 collision.]
func (s Subject) Key() string {
	if s.Path != "" {
		return "path:" + s.Path
	}
	return fmt.Sprintf("pid:%d", s.PID)
}

// Evidence is one observation from one collector about one subject.
type Evidence struct {
	Subject Subject
	Kind    SignalKind
	Summary string
	Weight  int
	Facts   map[string]string
}

// Action is a single reversible operation the actor will perform, in order.
type Action struct {
	Kind string // "bootout" | "move"
	From string
	To   string
}

// Finding is all evidence about one subject, correlated and totaled.
type Finding struct {
	Subject  Subject
	Score    int
	Kinds    []SignalKind
	Evidence []Evidence
	Tripwire string
	Actions  []Action
}

type ManifestItem struct {
	Subject  Subject
	Actions  []Action
	Evidence []Evidence
}

type Manifest struct {
	Timestamp string
	Items     []ManifestItem
}
```

- [ ] **Step 5: Add a minimal `main.go` so the module builds**

```go
package main

import "fmt"

func main() { fmt.Println("counterspy: use `scan` (see docs)") }
```

- [ ] **Step 6: Run tests, verify pass + build**

Run: `go test ./... && go build ./...`
Expected: PASS; binary builds.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: module scaffold + shared model"
```

---

### Task 2: Scoring constants + allowlist

**Files:**
- Create: `internal/score/weights.go`, `internal/score/allowlist.go`
- Test: `internal/score/allowlist_test.go`

**Interfaces:**
- Produces: named consts in `weights.go` (see code); `func IsAllowlisted(authority string) bool`.

- [ ] **Step 1: Write the failing allowlist test**

`internal/score/allowlist_test.go`:
```go
package score

import "testing"

func TestIsAllowlisted(t *testing.T) {
	cases := map[string]bool{
		"Software Signing":                         true, // Apple system
		"Apple Mac OS Application Signing":          true,
		"Developer ID Application: Some Sketchy Co": false,
		"":                                          false,
	}
	for authority, want := range cases {
		if got := IsAllowlisted(authority); got != want {
			t.Errorf("IsAllowlisted(%q)=%v want %v", authority, got, want)
		}
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/score/`
Expected: FAIL — `undefined: IsAllowlisted`.

- [ ] **Step 3: Write `internal/score/weights.go`**

```go
package score

// Signal weights (points added per observation). Tunable — this is the ONLY
// place numeric policy lives.
const (
	WeightUnsigned        = 3 // binary is unsigned or ad-hoc
	WeightRevokedCert     = 5 // signature present but revoked
	WeightHiddenPath      = 2 // lives in a dot-dir or hidden location
	WeightUserLaunchAgent = 1 // ~/Library LaunchAgent (common but noteworthy)
	WeightMissingTarget   = 2 // persistence points at a missing/renamed binary
	WeightInputMonitoring = 3 // holds Input Monitoring (keylogger shape)
	WeightAccessibility   = 3 // holds Accessibility
	WeightScreenRecording = 2 // holds Screen Recording
	WeightFullDiskAccess  = 2 // holds Full Disk Access
	WeightListener        = 2 // process listens on a socket
	WeightRawIPEgress     = 2 // established connection to a raw IP (no DNS name)
	WeightSpawnedByAgent  = 2 // parent chain includes a LaunchAgent-spawned proc
)

// Correlation: when >= CorrelationMinKinds DISTINCT signal kinds hit the same
// subject, multiply the summed weight by CorrelationFactor (scaled x100 to stay
// integer-only in the scorer).
const (
	CorrelationMinKinds     = 2
	CorrelationFactorX100   = 150 // 1.5x
	ShowThreshold           = 5   // findings at/above this are surfaced for quarantine
)
```

- [ ] **Step 4: Write `internal/score/allowlist.go`**

```go
package score

import "strings"

// knownGood are signing-authority substrings we treat as trusted, suppressing
// noise from Apple's own components. Extend deliberately.
var knownGood = []string{
	"Software Signing",                 // Apple system binaries
	"Apple Mac OS Application Signing",  // Apple-notarized Mac App Store
	"Apple Code Signing Certification",  // Apple intermediate
}

// IsAllowlisted reports whether a code-signing authority is known-good.
func IsAllowlisted(authority string) bool {
	if authority == "" {
		return false
	}
	for _, g := range knownGood {
		if strings.Contains(authority, g) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/score/`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: scoring constants + signing-authority allowlist"
```

---

### Task 3: Pure scorer — grouping, summation, sorting

**Files:**
- Create: `internal/score/score.go`
- Test: `internal/score/score_test.go`

**Interfaces:**
- Consumes: `model.Evidence`, `model.Finding`.
- Produces: `func Score(ev []model.Evidence) []model.Finding` — groups by `Subject.Key()`, sums weights, dedups kinds, sorts by `Score` desc then `Subject.Key()` asc.

- [ ] **Step 1: Write the failing test**

`internal/score/score_test.go`:
```go
package score

import (
	"testing"

	"counterspy/internal/model"
)

func ev(path string, k model.SignalKind, w int) model.Evidence {
	return model.Evidence{Subject: model.Subject{Path: path}, Kind: k, Weight: w}
}

func TestScore_SumsSameSubject(t *testing.T) {
	in := []model.Evidence{
		ev("/a", model.KindCodesign, 3),
		ev("/a", model.KindCodesign, 2), // same kind → no correlation bonus
	}
	out := Score(in)
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	if out[0].Score != 5 {
		t.Fatalf("want score 5, got %d", out[0].Score)
	}
}

func TestScore_SortsDescending(t *testing.T) {
	in := []model.Evidence{
		ev("/low", model.KindCodesign, 2),
		ev("/high", model.KindCodesign, 9),
	}
	out := Score(in)
	if out[0].Subject.Path != "/high" {
		t.Fatalf("want /high first, got %q", out[0].Subject.Path)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/score/`
Expected: FAIL — `undefined: Score`.

- [ ] **Step 3: Write `internal/score/score.go`**

```go
package score

import (
	"slices"

	"counterspy/internal/model"
)

// Score folds raw evidence into ranked findings. Pure: no I/O.
func Score(ev []model.Evidence) []model.Finding {
	groups := map[string]*model.Finding{}
	order := []string{}
	for _, e := range ev {
		k := e.Subject.Key()
		f, ok := groups[k]
		if !ok {
			f = &model.Finding{Subject: e.Subject}
			groups[k] = f
			order = append(order, k)
		}
		f.Evidence = append(f.Evidence, e)
		f.Score += e.Weight
		if !slices.Contains(f.Kinds, e.Kind) {
			f.Kinds = append(f.Kinds, e.Kind)
		}
	}

	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		f := groups[k]
		f.Score = applyCorrelation(f.Score, len(f.Kinds))
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b model.Finding) int {
		if a.Score != b.Score {
			return b.Score - a.Score // desc
		}
		return cmpStr(a.Subject.Key(), b.Subject.Key())
	})
	return out
}

func applyCorrelation(sum, distinctKinds int) int {
	if distinctKinds >= CorrelationMinKinds {
		return sum * CorrelationFactorX100 / 100
	}
	return sum
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/score/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: pure scorer — group, sum, sort"
```

---

### Task 4: Scorer — correlation multiplier

**Files:**
- Modify: `internal/score/score_test.go` (add test; `applyCorrelation` already exists from Task 3)

**Interfaces:**
- Consumes/Produces: no new symbols; proves `applyCorrelation` behavior via `Score`.

- [ ] **Step 1: Write the failing test**

Append to `internal/score/score_test.go`:
```go
func TestScore_CorrelationBonusForDistinctKinds(t *testing.T) {
	// Same total raw weight (6), but subject B has two distinct kinds.
	in := []model.Evidence{
		ev("/A", model.KindCodesign, 6),
		ev("/B", model.KindCodesign, 3),
		ev("/B", model.KindTCC, 3),
	}
	out := Score(in)
	byPath := map[string]int{}
	for _, f := range out {
		byPath[f.Subject.Path] = f.Score
	}
	if byPath["/A"] != 6 {
		t.Fatalf("A: want 6, got %d", byPath["/A"])
	}
	if byPath["/B"] != 9 { // 6 * 1.5
		t.Fatalf("B: want 9 (correlation bonus), got %d", byPath["/B"])
	}
}
```

- [ ] **Step 2: Run it, verify it passes** (implementation done in Task 3)

Run: `go test ./internal/score/ -run Correlation -v`
Expected: PASS. (If it fails, fix `applyCorrelation` before proceeding.)

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "test: correlation multiplier for distinct-kind subjects"
```

---

### Task 5: Scorer — allowlist suppression + tripwires

**Files:**
- Modify: `internal/score/score.go` (add allowlist suppression + tripwire pass)
- Create: `internal/score/tripwire.go`
- Test: `internal/score/tripwire_test.go`

**Interfaces:**
- Consumes: `IsAllowlisted`, weights consts.
- Produces: `func tripwire(f model.Finding) string` (empty = none); allowlisted subjects are dropped from output. `Score` now sets `Finding.Tripwire`. An allowlisted subject is identified by an evidence `Facts["authority"]` that `IsAllowlisted` accepts.

- [ ] **Step 1: Write the failing tripwire test**

`internal/score/tripwire_test.go`:
```go
package score

import (
	"testing"

	"counterspy/internal/model"
)

func TestScore_AllowlistedSubjectSuppressed(t *testing.T) {
	in := []model.Evidence{{
		Subject: model.Subject{Path: "/Applications/Safari.app"},
		Kind:    model.KindCodesign, Weight: 0,
		Facts: map[string]string{"authority": "Software Signing"},
	}}
	if out := Score(in); len(out) != 0 {
		t.Fatalf("allowlisted subject should be suppressed, got %d findings", len(out))
	}
}

func TestScore_TripwireFiresOnUnsignedPersistenceListener(t *testing.T) {
	sub := model.Subject{Path: "/tmp/x", PID: 5}
	in := []model.Evidence{
		{Subject: sub, Kind: model.KindCodesign, Summary: "unsigned", Weight: 3,
			Facts: map[string]string{"signed": "false"}},
		{Subject: sub, Kind: model.KindPersistence, Summary: "launch agent", Weight: 1},
		{Subject: sub, Kind: model.KindProcess, Summary: "listener", Weight: 2,
			Facts: map[string]string{"listener": "true"}},
	}
	out := Score(in)
	if len(out) != 1 || out[0].Tripwire == "" {
		t.Fatalf("expected a tripwire finding, got %+v", out)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/score/ -run 'Allowlist|Tripwire'`
Expected: FAIL.

- [ ] **Step 3: Write `internal/score/tripwire.go`**

```go
package score

import "counterspy/internal/model"

// tripwire returns a non-empty label when a finding matches a hard
// "always surface" combination, regardless of numeric score.
func tripwire(f model.Finding) string {
	var unsigned, persistence, listener bool
	for _, e := range f.Evidence {
		switch e.Kind {
		case model.KindCodesign:
			if e.Facts["signed"] == "false" {
				unsigned = true
			}
		case model.KindPersistence:
			persistence = true
		case model.KindProcess:
			if e.Facts["listener"] == "true" {
				listener = true
			}
		}
	}
	if unsigned && persistence && listener {
		return "unsigned binary with persistence and a live network listener"
	}
	return ""
}

// subjectAllowlisted reports whether any evidence carries a trusted authority.
func subjectAllowlisted(f model.Finding) bool {
	for _, e := range f.Evidence {
		if IsAllowlisted(e.Facts["authority"]) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Wire suppression + tripwire into `Score`**

In `internal/score/score.go`, replace the output-building loop with:
```go
	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		f := groups[k]
		if subjectAllowlisted(*f) {
			continue // trusted — suppress noise
		}
		f.Score = applyCorrelation(f.Score, len(f.Kinds))
		f.Tripwire = tripwire(*f)
		out = append(out, *f)
	}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/score/`
Expected: PASS (all scorer tests).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: allowlist suppression + hard tripwire rule"
```

---

### Task 6: Persistence collector

**Files:**
- Create: `internal/collect/persistence.go`
- Test: `internal/collect/persistence_test.go`, `testdata/agent_evil.plist.xml`

**Interfaces:**
- Consumes: `model.Evidence`, weights (via literals passed in — collector stays independent of `score`; it emits raw weights it owns). NOTE: to avoid a `collect → score` dependency, persistence weights are local consts here mirroring policy; the scorer only sums. (Keeps `score` importable-by-nobody-inward.)
- Produces: `func ParsePersistencePlist(xmlBytes []byte, path string) ([]model.Evidence, error)`.

- [ ] **Step 1: Create the fixture** `testdata/agent_evil.plist.xml` (already `plutil -convert xml1` form):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.evil.updater</string>
	<key>ProgramArguments</key>
	<array><string>/Users/me/Library/.hidden/beacon</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
</dict>
</plist>
```

- [ ] **Step 2: Write the failing test**

`internal/collect/persistence_test.go`:
```go
package collect

import (
	"os"
	"testing"

	"counterspy/internal/model"
)

func TestParsePersistencePlist_FlagsHiddenTarget(t *testing.T) {
	b, err := os.ReadFile("../../testdata/agent_evil.plist.xml")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ParsePersistencePlist(b, "/Users/me/Library/LaunchAgents/com.evil.updater.plist")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) == 0 {
		t.Fatal("expected evidence")
	}
	var sawHidden bool
	for _, e := range ev {
		if e.Kind != model.KindPersistence {
			t.Errorf("wrong kind %q", e.Kind)
		}
		if e.Subject.Label != "com.evil.updater" {
			t.Errorf("label not propagated: %q", e.Subject.Label)
		}
		if e.Facts["target"] == "/Users/me/Library/.hidden/beacon" {
			sawHidden = true
		}
	}
	if !sawHidden {
		t.Error("expected the hidden target path in Facts")
	}
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/collect/ -run Persistence`
Expected: FAIL — `undefined: ParsePersistencePlist`.

- [ ] **Step 4: Write `internal/collect/persistence.go`** (parser only; the exec-edge walker is added in Step 6 so this step compiles with exactly the imports it uses)

```go
package collect

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// Persistence signal weights (local to the collector so `collect` never imports `score`).
const (
	wHiddenPath = 2
	wUserAgent  = 1
	wMissingTgt = 2
)

// ParsePersistencePlist turns one launchd plist (already `plutil -convert xml1`)
// into evidence. Pure over its byte input except a stat() existence check.
func ParsePersistencePlist(xmlBytes []byte, path string) ([]model.Evidence, error) {
	label, target := extractLabelAndTarget(xmlBytes)
	sub := model.Subject{Path: target, Label: label}
	if target == "" {
		sub.Path = path
	}
	var ev []model.Evidence
	facts := map[string]string{"plist": path, "target": target}

	if strings.Contains(target, "/.") || strings.HasPrefix(filepath.Base(target), ".") {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence targets a hidden path", Weight: wHiddenPath, Facts: facts})
	}
	if strings.Contains(path, "/Users/") {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "user-level LaunchAgent", Weight: wUserAgent, Facts: facts})
	}
	if target != "" && !statExists(target) {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence target is missing/renamed", Weight: wMissingTgt, Facts: facts})
	}
	return ev, nil
}

// extractLabelAndTarget tolerantly scans the xml1 dict for Label and the first
// ProgramArguments entry.
func extractLabelAndTarget(b []byte) (label, target string) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	var lastKey string
	var inArgs bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s == "" {
				continue
			}
			if lastKey == "Label" && label == "" {
				label = s
			}
			if inArgs && target == "" {
				target = s
			}
			lastKey = s
		case xml.StartElement:
			if t.Name.Local == "array" {
				inArgs = lastKey == "ProgramArguments"
			}
		}
	}
	return label, target
}

func statExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}
```

- [ ] **Step 5: Run the test**

Run: `go test ./internal/collect/ -run Persistence -v`
Expected: PASS (hidden-target + user-level evidence present).

- [ ] **Step 6: Add the directory walker (exec edge, not unit-tested)**

Add `"os/exec"` to the import block, then append to `persistence.go`:
```go
// CollectPersistence walks the launchd search paths and returns evidence.
// I/O edge — exercised via integration, not unit tests.
func CollectPersistence() ([]model.Evidence, error) {
	dirs := []string{
		expand("~/Library/LaunchAgents"),
		"/Library/LaunchAgents", "/Library/LaunchDaemons",
	}
	var all []model.Evidence
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue // reported as a gap by the caller if the whole phase fails
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			xmlBytes, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", p).Output()
			if err != nil {
				continue
			}
			ev, _ := ParsePersistencePlist(xmlBytes, p)
			all = append(all, ev...)
		}
	}
	return all, nil
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
```

- [ ] **Step 7: Run tests + build, commit**

Run: `go test ./... && go build ./...`
Expected: PASS + builds.
```bash
git add -A && git commit -m "feat: persistence collector (parser + dir walker)"
```

---

### Task 7: Codesign collector

**Files:**
- Create: `internal/collect/codesign.go`
- Test: `internal/collect/codesign_test.go`

**Interfaces:**
- Produces: `func ParseCodesign(path, verifyErr, assessOut, authority string) []model.Evidence`. (Inputs are the raw strings the exec edge captures: `codesign --verify` stderr, `spctl --assess` output, and the extracted authority line.)

- [ ] **Step 1: Write the failing test**

`internal/collect/codesign_test.go`:
```go
package collect

import (
	"testing"

	"counterspy/internal/model"
)

func TestParseCodesign_UnsignedFlagged(t *testing.T) {
	ev := ParseCodesign("/tmp/x", "code object is not signed at all", "", "")
	if len(ev) != 1 {
		t.Fatalf("want 1 evidence, got %d", len(ev))
	}
	if ev[0].Facts["signed"] != "false" {
		t.Errorf("expected signed=false fact, got %v", ev[0].Facts)
	}
	if ev[0].Kind != model.KindCodesign {
		t.Errorf("wrong kind %q", ev[0].Kind)
	}
}

func TestParseCodesign_SignedTrustedNoEvidence(t *testing.T) {
	ev := ParseCodesign("/Applications/Safari.app", "", "accepted", "Software Signing")
	// signed + allowlisted authority → still emit the authority fact so the
	// scorer can suppress, but zero weight.
	if len(ev) != 1 || ev[0].Weight != 0 {
		t.Fatalf("want one zero-weight authority marker, got %+v", ev)
	}
	if ev[0].Facts["authority"] != "Software Signing" {
		t.Errorf("authority fact missing: %v", ev[0].Facts)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/collect/ -run Codesign`
Expected: FAIL — `undefined: ParseCodesign`.

- [ ] **Step 3: Write `internal/collect/codesign.go`**

```go
package collect

import (
	"os/exec"
	"strings"

	"counterspy/internal/model"
)

const (
	wUnsigned = 3
	wRevoked  = 5
)

// ParseCodesign turns captured codesign/spctl output into evidence.
func ParseCodesign(path, verifyErr, assessOut, authority string) []model.Evidence {
	sub := model.Subject{Path: path}
	facts := map[string]string{"authority": authority}

	switch {
	case strings.Contains(verifyErr, "not signed"):
		facts["signed"] = "false"
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "binary is unsigned", Weight: wUnsigned, Facts: facts}}
	case strings.Contains(verifyErr, "revoked"):
		facts["signed"] = "revoked"
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signing certificate revoked", Weight: wRevoked, Facts: facts}}
	default:
		facts["signed"] = "true"
		// Emit a zero-weight marker so the scorer can allowlist-suppress.
		return []model.Evidence{{Subject: sub, Kind: model.KindCodesign,
			Summary: "signed by " + authority, Weight: 0, Facts: facts}}
	}
}

// CollectCodesign runs codesign/spctl for a path (I/O edge).
func CollectCodesign(path string) []model.Evidence {
	verify, _ := exec.Command("codesign", "--verify", "--deep", path).CombinedOutput()
	assess, _ := exec.Command("spctl", "--assess", "--type", "execute", path).CombinedOutput()
	authOut, _ := exec.Command("codesign", "-dv", "--verbose=2", path).CombinedOutput()
	return ParseCodesign(path, string(verify), string(assess), extractAuthority(string(authOut)))
}

func extractAuthority(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority=")
		}
	}
	return ""
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/collect/ -run Codesign -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: codesign/notarization collector"
```

---

### Task 8: Process-tree + network collector

**Files:**
- Create: `internal/collect/proctree.go`
- Test: `internal/collect/proctree_test.go`, `testdata/ps.txt`, `testdata/lsof.txt`

**Interfaces:**
- Produces: `func ParsePs(b []byte) map[int]*Proc`, `func ParseLsof(b []byte) map[int][]string` (pid→listener descriptions), `func BuildProcessEvidence(ps map[int]*Proc, listeners map[int][]string) []model.Evidence`. `Proc{PID, PPID int; User, Cmd string; Args string}`.

- [ ] **Step 1: Create fixtures**

`testdata/ps.txt` (header + rows as `ps -axo pid,ppid,user,command` yields):
```
  PID  PPID USER     COMMAND
    1     0 root     /sbin/launchd
  501     1 me       /System/Library/.../launchd
  777   501 me       python3 /Users/me/Library/.hidden/beacon.py --c2 1.2.3.4
```

`testdata/lsof.txt` (subset of `lsof -i -nP`):
```
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3   777 me     5u  IPv4 0x1234      0t0  TCP *:4444 (LISTEN)
```

- [ ] **Step 2: Write the failing test**

`internal/collect/proctree_test.go`:
```go
package collect

import (
	"os"
	"strings"
	"testing"
)

func TestBuildProcessEvidence_AttributesListenerToAncestry(t *testing.T) {
	psb, _ := os.ReadFile("../../testdata/ps.txt")
	lsb, _ := os.ReadFile("../../testdata/lsof.txt")
	procs := ParsePs(psb)
	listeners := ParseLsof(lsb)
	ev := BuildProcessEvidence(procs, listeners)

	var found bool
	for _, e := range ev {
		if e.Subject.PID == 777 && e.Facts["listener"] == "true" {
			found = true
			if !strings.Contains(e.Facts["argv"], "beacon.py") {
				t.Errorf("argv should reveal the script: %q", e.Facts["argv"])
			}
			if !strings.Contains(e.Facts["ancestry"], "launchd") {
				t.Errorf("ancestry chain missing: %q", e.Facts["ancestry"])
			}
		}
	}
	if !found {
		t.Fatal("expected listener evidence for pid 777 with ancestry+argv")
	}
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/collect/ -run Process`
Expected: FAIL — undefined symbols.

- [ ] **Step 4: Write `internal/collect/proctree.go`**

```go
package collect

import (
	"os/exec"
	"strconv"
	"strings"

	"counterspy/internal/model"
)

const wListener = 2

type Proc struct {
	PID, PPID int
	User      string
	Cmd       string // full command line (argv)
}

// ParsePs parses `ps -axo pid,ppid,user,command` output.
func ParsePs(b []byte) map[int]*Proc {
	out := map[int]*Proc{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(ln)
		if len(fields) < 4 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		cmd := strings.TrimSpace(strings.SplitN(ln, fields[2], 2)[1])
		out[pid] = &Proc{PID: pid, PPID: ppid, User: fields[2], Cmd: cmd}
	}
	return out
}

// ParseLsof maps a PID to human listener descriptions.
func ParseLsof(b []byte) map[int][]string {
	out := map[int][]string{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		out[pid] = append(out[pid], strings.Join(fields[8:], " "))
	}
	return out
}

func ancestry(procs map[int]*Proc, pid int) string {
	var chain []string
	seen := map[int]bool{}
	for p := procs[pid]; p != nil && !seen[p.PID]; p = procs[p.PPID] {
		seen[p.PID] = true
		name := p.Cmd
		if sp := strings.Fields(p.Cmd); len(sp) > 0 {
			name = sp[0]
		}
		chain = append([]string{name}, chain...)
		if p.PID == 1 {
			break
		}
	}
	return strings.Join(chain, " → ")
}

// BuildProcessEvidence emits evidence for processes that hold listeners,
// attributing each to its full ancestry and argv.
func BuildProcessEvidence(procs map[int]*Proc, listeners map[int][]string) []model.Evidence {
	var ev []model.Evidence
	for pid, descs := range listeners {
		p := procs[pid]
		if p == nil {
			continue
		}
		facts := map[string]string{
			"listener": "true",
			"argv":     p.Cmd,
			"ancestry": ancestry(procs, pid),
			"ports":    strings.Join(descs, ", "),
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{PID: pid, Path: execPath(p.Cmd)},
			Kind:    model.KindProcess,
			Summary: "process holds a network listener",
			Weight:  wListener,
			Facts:   facts,
		})
	}
	return ev
}

// execPath best-effort extracts the on-disk binary path from argv so process
// evidence can correlate with codesign/persistence evidence by Path.
func execPath(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], "/") {
		return fields[0]
	}
	return "" // interpreter without absolute path — correlate by PID only
}

// CollectProcesses runs ps + lsof (I/O edge).
func CollectProcesses() ([]model.Evidence, error) {
	psb, err := exec.Command("ps", "-axo", "pid,ppid,user,command").Output()
	if err != nil {
		return nil, err
	}
	lsb, _ := exec.Command("lsof", "-i", "-nP").Output() // may be partial without root
	return BuildProcessEvidence(ParsePs(psb), ParseLsof(lsb)), nil
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/collect/ -run Process -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: process-tree + network collector with ancestry/argv"
```

---

### Task 9: TCC (privacy grants) collector

**Files:**
- Create: `internal/collect/tcc.go`
- Test: `internal/collect/tcc_test.go`, `testdata/tcc.txt`

**Interfaces:**
- Produces: `func ParseTCC(rows []byte) []model.Evidence`. Input is `sqlite3 -separator '|'` output of `SELECT service, client, auth_value FROM access;`.

- [ ] **Step 1: Create fixture** `testdata/tcc.txt`:
```
kTCCServiceAccessibility|/Users/me/Library/.hidden/beacon|2
kTCCServiceListenEvent|/Users/me/Library/.hidden/beacon|2
kTCCServiceScreenCapture|/Applications/Zoom.app|2
```

- [ ] **Step 2: Write the failing test**

`internal/collect/tcc_test.go`:
```go
package collect

import (
	"os"
	"testing"

	"counterspy/internal/model"
)

func TestParseTCC_KeyloggerShapeScoresHigher(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/tcc.txt")
	ev := ParseTCC(b)
	byPath := map[string]int{}
	for _, e := range ev {
		if e.Kind != model.KindTCC {
			t.Errorf("wrong kind %q", e.Kind)
		}
		byPath[e.Subject.Path] += e.Weight
	}
	if byPath["/Users/me/Library/.hidden/beacon"] <= byPath["/Applications/Zoom.app"] {
		t.Errorf("accessibility+input-monitoring should outweigh a single screen-capture grant")
	}
}
```

- [ ] **Step 3: Run it, verify it fails**

Run: `go test ./internal/collect/ -run TCC`
Expected: FAIL — `undefined: ParseTCC`.

- [ ] **Step 4: Write `internal/collect/tcc.go`**

```go
package collect

import (
	"os/exec"
	"strings"

	"counterspy/internal/model"
)

// TCC service → weight (only grants that matter to spyware).
var tccWeights = map[string]struct {
	weight  int
	summary string
}{
	"kTCCServiceAccessibility": {3, "holds Accessibility"},
	"kTCCServiceListenEvent":   {3, "holds Input Monitoring"},
	"kTCCServiceScreenCapture": {2, "holds Screen Recording"},
	"kTCCServiceSystemPolicyAllFiles": {2, "holds Full Disk Access"},
}

// ParseTCC turns `service|client|auth_value` rows into evidence (auth_value 2 = allowed).
func ParseTCC(rows []byte) []model.Evidence {
	var ev []model.Evidence
	for _, ln := range strings.Split(strings.TrimSpace(string(rows)), "\n") {
		parts := strings.Split(ln, "|")
		if len(parts) < 3 || parts[2] != "2" {
			continue
		}
		w, ok := tccWeights[parts[0]]
		if !ok {
			continue
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{Path: parts[1]},
			Kind:    model.KindTCC,
			Summary: w.summary,
			Weight:  w.weight,
			Facts:   map[string]string{"service": parts[0]},
		})
	}
	return ev
}

// CollectTCC reads the user + system TCC databases (I/O edge, needs sudo for system db).
func CollectTCC() ([]model.Evidence, error) {
	const q = "SELECT service, client, auth_value FROM access;"
	dbs := []string{
		expand("~/Library/Application Support/com.apple.TCC/TCC.db"),
		"/Library/Application Support/com.apple.TCC/TCC.db",
	}
	var all []model.Evidence
	for _, db := range dbs {
		out, err := exec.Command("sqlite3", "-separator", "|", db, q).Output()
		if err != nil {
			continue
		}
		all = append(all, ParseTCC(out)...)
	}
	return all, nil
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/collect/ -run TCC -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: TCC privacy-grant collector"
```

---

### Task 10: Interpret + Report (synthesis, not a raw dump)

> **[design update — user directive]** Before formatting, add a **pure `internal/interpret`
> package** that turns each `model.Finding` into a `model.Assessment{Finding; Verdict,
> Category, Recommendation string}`:
> - **Verdict**: one composed sentence from the subject's signals (mix of unsigned /
>   persistence / TCC grants / listener + ancestry).
> - **Category**: `keylogger` (Input Monitoring + Accessibility), `backdoor` (unsigned +
>   listener + persistence), `spyware-generic`, `persistence-only`, `unknown`.
> - **Recommendation**: `Quarantine` (tripwire OR score ≥ high tier with an actionable
>   target), `Investigate` (mid band), `Monitor` (low). Rule-based/deterministic (Rule 6).
> `report.Render` then leads with an **executive summary** (counts per recommendation) and
> renders ranked `Assessment`s (verdict + recommendation + supporting evidence story),
> omitting low-signal noise. `RenderJSON` emits `[]Assessment`. Tests: keylogger-shape →
> Category=keylogger + Recommendation=Quarantine; a single Monitor-tier item is summarized,
> not front-paged. Add `HighTier` constant to score/weights.go. This synthesis lives in the
> core so the future TUI/WebUI reuse it (spec §8.1, §12 invariant).

The base human+JSON rendering below still applies, now over `[]model.Assessment`:

**Files:**
- Create: `internal/report/report.go`
- Test: `internal/report/report_test.go`

**Interfaces:**
- Consumes: `[]model.Finding`.
- Produces: `func Render(findings []model.Finding, threshold int) string`, `func RenderJSON(findings []model.Finding) ([]byte, error)`.

- [ ] **Step 1: Write the failing test**

`internal/report/report_test.go`:
```go
package report

import (
	"encoding/json"
	"strings"
	"testing"

	"counterspy/internal/model"
)

func sample() []model.Finding {
	return []model.Finding{{
		Subject:  model.Subject{Path: "/tmp/x", PID: 777, Label: "com.evil"},
		Score:    12,
		Kinds:    []model.SignalKind{model.KindCodesign, model.KindProcess},
		Tripwire: "unsigned + persistence + listener",
		Evidence: []model.Evidence{{Kind: model.KindProcess, Summary: "listener",
			Facts: map[string]string{"ancestry": "launchd → python3", "argv": "python3 beacon.py"}}},
	}}
}

func TestRender_ShowsEvidenceStory(t *testing.T) {
	out := Render(sample(), 5)
	for _, want := range []string{"com.evil", "12", "TRIPWIRE", "launchd → python3", "beacon.py"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n%s", want, out)
		}
	}
}

func TestRenderJSON_RoundTrips(t *testing.T) {
	b, err := RenderJSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var back []model.Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back[0].Subject.Label != "com.evil" {
		t.Errorf("json round-trip lost data: %+v", back)
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/report/`
Expected: FAIL — undefined `Render`/`RenderJSON`.

- [ ] **Step 3: Write `internal/report/report.go`**

```go
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"counterspy/internal/model"
)

// RenderJSON emits the machine-readable form fed to CI / the ABORT gate / future UIs.
func RenderJSON(findings []model.Finding) ([]byte, error) {
	return json.MarshalIndent(findings, "", "  ")
}

// Render produces the human report, telling each finding as its evidence story.
func Render(findings []model.Finding, threshold int) string {
	var b strings.Builder
	shown := 0
	for _, f := range findings {
		if f.Score < threshold && f.Tripwire == "" {
			continue
		}
		shown++
		id := f.Subject.Label
		if id == "" {
			id = f.Subject.Path
		}
		fmt.Fprintf(&b, "\n[%d] %s  (score %d)\n", shown, id, f.Score)
		if f.Tripwire != "" {
			fmt.Fprintf(&b, "  ⚠ TRIPWIRE: %s\n", f.Tripwire)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "  - %s: %s\n", e.Kind, e.Summary)
			if a := e.Facts["ancestry"]; a != "" {
				fmt.Fprintf(&b, "      ancestry: %s\n", a)
			}
			if a := e.Facts["argv"]; a != "" {
				fmt.Fprintf(&b, "      argv:     %s\n", a)
			}
		}
	}
	if shown == 0 {
		return "No findings at or above the surface threshold.\n"
	}
	return b.String()
}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `go test ./internal/report/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: human + JSON reporting"
```

---

### Task 11: Actor — quarantine + restore (sandbox round-trip)

> **[swarm ticket T-2]** While implementing this task, introduce `type ActionKind string`
> with consts `ActionBootout`/`ActionMove` in `model` and change `Action.Kind` to it (deferred
> from tick 1, Audit F-3 — do it here alongside its only consumer). Update the string literals
> `"move"`/`"bootout"` in this task's and main.go's code to the typed consts.

**Files:**
- Create: `internal/act/quarantine.go`, `internal/act/restore.go`
- Test: `internal/act/act_test.go`

**Interfaces:**
- Consumes: `model.Finding`, `model.Manifest`, `model.ManifestItem`, `model.Action`.
- Produces: `func Quarantine(quarantineRoot string, f model.Finding) (model.ManifestItem, error)` — moves each `Action{Kind:"move"}` file into `quarantineRoot`, returns the item (with `To` paths filled). `func WriteManifest(dir string, m model.Manifest) (string, error)`. `func Restore(manifestPath string) error` — moves every item back to its `From`. (For v1 tests, `bootout` actions are recorded but not executed in the sandbox.)

- [ ] **Step 1: Write the failing round-trip test**

`internal/act/act_test.go`:
```go
package act

import (
	"os"
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

func TestQuarantineRestore_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	origDir := filepath.Join(tmp, "orig")
	qRoot := filepath.Join(tmp, "quarantine")
	os.MkdirAll(origDir, 0o755)
	orig := filepath.Join(origDir, "beacon")
	if err := os.WriteFile(orig, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := model.Finding{
		Subject: model.Subject{Path: orig, Label: "com.evil"},
		Actions: []model.Action{{Kind: "move", From: orig}},
	}
	item, err := Quarantine(qRoot, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		t.Fatal("original should have moved")
	}
	mpath, err := WriteManifest(qRoot, model.Manifest{Timestamp: "t", Items: []model.ManifestItem{item}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Restore(mpath); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(orig)
	if err != nil || string(got) != "payload" {
		t.Fatalf("restore did not return original bytes: %v / %q", err, got)
	}
}

func TestQuarantine_RefusesProtectedSystemPath(t *testing.T) {
	f := model.Finding{
		Subject: model.Subject{Path: "/System/Library/LaunchDaemons/com.apple.x.plist"},
		Actions: []model.Action{{Kind: "move", From: "/System/Library/LaunchDaemons/com.apple.x.plist"}},
	}
	if _, err := Quarantine(t.TempDir(), f); err == nil {
		t.Fatal("expected refusal to move a /System path, got nil error")
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test ./internal/act/`
Expected: FAIL — undefined symbols.

- [ ] **Step 3: Write `internal/act/quarantine.go`**

```go
package act

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// protectedPrefixes are paths CounterSpy refuses to move, even under sudo.
// Belt-and-suspenders: SIP already blocks /System, but we refuse explicitly so
// a bug can never even attempt it (spec §9 hard refusal; success criterion #5).
var protectedPrefixes = []string{"/System/", "/usr/lib/", "/usr/bin/", "/bin/", "/sbin/"}

func isProtected(p string) bool {
	for _, pre := range protectedPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Quarantine moves each "move" action's file under quarantineRoot, preserving
// the base name, and returns the manifest item with To paths filled.
func Quarantine(quarantineRoot string, f model.Finding) (model.ManifestItem, error) {
	if err := os.MkdirAll(quarantineRoot, 0o755); err != nil {
		return model.ManifestItem{}, err
	}
	item := model.ManifestItem{Subject: f.Subject, Evidence: f.Evidence}
	for _, a := range f.Actions {
		if a.Kind != "move" {
			item.Actions = append(item.Actions, a) // record bootout etc. as-is
			continue
		}
		if isProtected(a.From) {
			return item, fmt.Errorf("refusing to move protected system path: %s", a.From)
		}
		to := filepath.Join(quarantineRoot, filepath.Base(a.From))
		if err := os.Rename(a.From, to); err != nil {
			return item, err // stop on first failure; caller reports partial state
		}
		a.To = to
		item.Actions = append(item.Actions, a)
	}
	return item, nil
}

// WriteManifest persists the manifest JSON and returns its path.
func WriteManifest(dir string, m model.Manifest) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "manifest.json")
	return p, os.WriteFile(p, b, 0o644)
}
```

- [ ] **Step 4: Write `internal/act/restore.go`**

```go
package act

import (
	"encoding/json"
	"os"

	"counterspy/internal/model"
)

// Restore reverses a quarantine: every "move" action goes To → From.
func Restore(manifestPath string) error {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m model.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for _, item := range m.Items {
		for _, a := range item.Actions {
			if a.Kind == "move" && a.To != "" {
				if err := os.Rename(a.To, a.From); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `go test ./internal/act/ -v`
Expected: PASS (round-trip returns identical bytes).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: reversible quarantine + restore with manifest"
```

---

### Task 12: main.go — CLI wiring

**Files:**
- Modify: `main.go`
- Test: `main_test.go`

**Interfaces:**
- Consumes: `collect.*`, `score.Score`, `report.*`, `act.*`, `score.ShowThreshold`.
- Produces: subcommands `scan` (flags `--json`, `--interactive`), `restore <manifest>`. `func run(args []string, stdout io.Writer) int` for testability.

- [ ] **Step 1: Write the failing test** (drives a `run()` seam that scans a fixture-free, no-op path and prints a header)

`main_test.go`:
```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_ScanJSONEmitsArray(t *testing.T) {
	var buf bytes.Buffer
	// --json on a machine with no findings should still emit valid JSON "[]"
	// (we only assert it starts like JSON; real collection needs sudo/live host).
	code := run([]string{"scan", "--json", "--dry"}, &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Fatalf("expected JSON array, got: %s", buf.String())
	}
}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `go test . -run Run`
Expected: FAIL — `undefined: run`.

- [ ] **Step 3: Rewrite `main.go`**

```go
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"counterspy/internal/act"
	"counterspy/internal/collect"
	"counterspy/internal/model"
	"counterspy/internal/report"
	"counterspy/internal/score"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stdout, "usage: counterspy scan [--json] [--interactive] | counterspy restore <manifest>")
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout)
	case "restore":
		if len(args) < 2 {
			fmt.Fprintln(stdout, "usage: counterspy restore <manifest.json>")
			return 2
		}
		if err := act.Restore(args[1]); err != nil {
			fmt.Fprintln(stdout, "restore failed:", err)
			return 1
		}
		fmt.Fprintln(stdout, "restored from", args[1])
		return 0
	default:
		fmt.Fprintln(stdout, "unknown command:", args[0])
		return 2
	}
}

func runScan(flags []string, stdout io.Writer) int {
	asJSON := has(flags, "--json")
	interactive := has(flags, "--interactive")
	dry := has(flags, "--dry") // collect nothing; used by tests

	var ev []model.Evidence
	if !dry {
		ev = collectAll(stdout)
	}
	findings := score.Score(ev)

	if asJSON {
		b, _ := report.RenderJSON(findings)
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, report.Render(findings, score.ShowThreshold))
	if interactive {
		quarantineLoop(findings, stdout)
	}
	return 0
}

// collectAll fans out the collectors, printing a gap line for any that fail
// (fail loud — never let a missing signal read as "clean").
func collectAll(stdout io.Writer) []model.Evidence {
	var ev []model.Evidence
	if p, err := collect.CollectPersistence(); err == nil {
		ev = append(ev, p...)
	} else {
		fmt.Fprintln(stdout, "! persistence signal unavailable:", err)
	}
	if p, err := collect.CollectProcesses(); err == nil {
		ev = append(ev, p...)
	} else {
		fmt.Fprintln(stdout, "! process/network signal unavailable:", err)
	}
	if p, err := collect.CollectTCC(); err == nil {
		ev = append(ev, p...)
	} else {
		fmt.Fprintln(stdout, "! TCC signal unavailable:", err)
	}
	// codesign runs per-path against subjects surfaced by the other collectors.
	for _, e := range append([]model.Evidence{}, ev...) {
		if e.Subject.Path != "" {
			ev = append(ev, collect.CollectCodesign(e.Subject.Path)...)
		}
	}
	return ev
}

func quarantineLoop(findings []model.Finding, stdout io.Writer) {
	in := bufio.NewReader(os.Stdin)
	for _, f := range findings {
		if f.Score < score.ShowThreshold && f.Tripwire == "" {
			continue
		}
		fmt.Fprintf(stdout, "Quarantine %s? [y/N/q] ", f.Subject.Key())
		line, _ := in.ReadString('\n')
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "q":
			return
		case "y":
			home, _ := os.UserHomeDir()
			root := home + "/CounterSpyQuarantine"
			f.Actions = plannedActions(f)
			item, err := act.Quarantine(root, f)
			if err != nil {
				fmt.Fprintln(stdout, "  quarantine failed (partial state):", err)
				continue
			}
			if _, err := act.WriteManifest(root, model.Manifest{Timestamp: "now", Items: []model.ManifestItem{item}}); err != nil {
				fmt.Fprintln(stdout, "  manifest write failed:", err)
			}
			fmt.Fprintln(stdout, "  quarantined.")
		}
	}
}

// plannedActions derives the reversible actions from a finding.
func plannedActions(f model.Finding) []model.Action {
	var a []model.Action
	if f.Subject.Label != "" {
		a = append(a, model.Action{Kind: "bootout", From: f.Subject.Label})
	}
	for _, e := range f.Evidence {
		if p := e.Facts["plist"]; p != "" {
			a = append(a, model.Action{Kind: "move", From: p})
		}
	}
	if f.Subject.Path != "" {
		a = append(a, model.Action{Kind: "move", From: f.Subject.Path})
	}
	return a
}

func has(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests + vet + build**

Run: `go test ./... && go vet ./... && go build -o counterspy .`
Expected: PASS; `./counterspy scan --json --dry` prints `[]`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: CLI wiring — scan/restore, fail-loud collection, interactive quarantine"
```

---

### Task 13: Architecture docs (architext) + threat model (ABORT input)

**Files:**
- Create: `docs/architext/` (generated), `docs/threat-model.md`, `README.md`

**Interfaces:** none (documentation deliverables required by §11 of the spec / the ABORT gate).

- [ ] **Step 1: Generate architext docs against the now-real source**

Invoke the `architext` skill on the repo so it reads the actual Go packages (`model`, `collect`, `score`, `act`, `report`) and emits C4-style views + data-movement + decisions into `docs/architext/`. (architext needs source to read — this is why it runs here, after the code exists, not against the spec.)

- [ ] **Step 2: Write `docs/threat-model.md`** covering, at minimum:
  - What CounterSpy defends against (userland persistence/process/TCC/codesign-based spyware) and **explicitly does not** (kernel implants, firmware, supply-chain, anything SIP-protected).
  - False-positive posture: allowlist + move-not-delete + `restore` round-trip guarantee.
  - The correlation/tripwire logic as the false-positive control.

- [ ] **Step 3: Write `README.md`** with build (`go build -o counterspy .`), usage (`sudo ./counterspy scan`, `--json`, `--interactive`, `restore`), and the safety guarantees (never deletes; reversible).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "docs: architext architecture docs + threat model + README"
```

---

## Post-plan: the ABORT gate

After Task 13, the codebase satisfies every input §11 enumerated (green `go test`/`go vet`, `--json`, `manifest.json`, threat model, reversibility). At that point run the `/abort` skill with the decision pinned to: *"Publish `counterspy` v0.1 as a public sudo tool that quarantines user-selected items on third parties' Macs."* A GO ships; a NO-GO returns explicit convertibility conditions.
