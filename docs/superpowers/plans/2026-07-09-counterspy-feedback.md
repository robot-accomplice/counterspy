# CounterSpy Field Feedback Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users label findings true/false-positive and push anonymous heuristic fingerprints to an author-owned, POST-only endpoint, so the false-positive rate can be measured from the field.

**Architecture:** A new pure `internal/feedback` package (Capture → Minimize) produces intrinsically-anonymous records; a write-only `Transmitter` interface (file + http impls) sends them; a local `Store` persists/dedupes labels; three-way consent (`off`/`ask`/`always`) gates submission. Labeling is a TUI keypress that flows through the existing `Actor` seam — `internal/tui` still imports only `internal/model`.

**Tech Stack:** Go stdlib (`crypto/rand`, `crypto/sha256`, `net/http`, `encoding/json`, `os/user`), tcell v2 (existing), Cloudflare Worker (author-owned, out of scope for this plan).

## Global Constraints

- `internal/tui` imports ONLY `counterspy/internal/model` (enforced by `TestDecouplingInvariant`). Labeling emits a `Cmd`; `main` performs the effect.
- **Egress-only invariant:** the feedback path is push-only. `Transmitter` returns only `error`; the HTTP impl reads only the status code and discards the response body without decoding it; the tool never fetches config/allowlists/updates from the network. Enforced by `TestEgressOnly`.
- **Off by default:** a fresh install shares nothing. Consent is `off` unless the user explicitly sets `ask` or `always`; revocable.
- **Anonymity in the data:** records carry no raw path, username, hostname, or private identifier. Paths become classes; private app identities are dropped unless the user consents (`ask`) or opts in (`detail=full`).
- **Config/store live under the INVOKING user's home** (resolve `SUDO_USER`), never root's, since the tool runs under sudo.
- Standard library only for the feedback package; no new third-party dependencies.
- Move-not-delete and all existing safety behavior are untouched.

---

### Task 1: `model.FeedbackRecord` type + version bump

**Files:**
- Modify: `internal/model/types.go`
- Test: `internal/model/feedback_test.go`

**Interfaces:**
- Produces: `model.FeedbackRecord` struct (JSON-tagged); consts `LabelFalsePositive`, `LabelTruePositive`, `FeedbackSchema`; `Version` bumped to `"v0.3.0-rc1"`.

- [ ] **Step 1: Write the failing test**

```go
// internal/model/feedback_test.go
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFeedbackRecordJSON(t *testing.T) {
	r := FeedbackRecord{
		Schema: FeedbackSchema, Tool: Version, Nonce: "n1",
		Label: LabelFalsePositive, Recommendation: "quarantine",
		Category: "surveillance-capable", ScoreBand: "10-14",
		Signals: []string{"persistence", "codesign"}, Codesign: "unsigned",
		PathClass: "user-library", Tripwire: true, Identity: "com.docker.docker",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"schema":"1"`, `"score_band":"10-14"`, `"path_class":"user-library"`, `"identity":"com.docker.docker"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	// Empty identity/extra must be omitted (public default carries neither).
	var empty FeedbackRecord
	b2, _ := json.Marshal(empty)
	if strings.Contains(string(b2), "identity") || strings.Contains(string(b2), "extra") {
		t.Fatalf("empty identity/extra must be omitted: %s", b2)
	}
	if Version != "v0.3.0-rc1" {
		t.Fatalf("Version = %s, want v0.3.0-rc1", Version)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run TestFeedbackRecordJSON`
Expected: FAIL — `undefined: FeedbackRecord` / `Version` mismatch.

- [ ] **Step 3: Write minimal implementation**

In `internal/model/types.go`, change the Version line:

```go
const Version = "v0.3.0-rc1"
```

And append at the end of the file:

```go
// FeedbackSchema is the FeedbackRecord wire-schema version (independent of tool Version).
const FeedbackSchema = "1"

// Feedback labels: the user's verdict on a finding.
const (
	LabelFalsePositive = "false_positive" // the tool flagged legitimate software
	LabelTruePositive  = "true_positive"  // the tool flagged correctly
)

// FeedbackRecord is an intrinsically-anonymous field report: a finding's heuristic
// fingerprint plus the user's label. It carries no raw path, username, hostname, or
// (by default) private identifier — anonymity lives in the data, not the transport.
type FeedbackRecord struct {
	Schema         string            `json:"schema"`
	Tool           string            `json:"tool"`  // Version — weights/allowlist provenance
	Nonce          string            `json:"nonce"` // per-submission, non-correlatable
	Label          string            `json:"label"`
	Recommendation string            `json:"recommendation"`
	Category       string            `json:"category"`
	ScoreBand      string            `json:"score_band"` // banded, not exact
	Signals        []string          `json:"signals"`
	Codesign       string            `json:"codesign"`
	PathClass      string            `json:"path_class"` // class, never the path
	Tripwire       bool              `json:"tripwire"`
	Identity       string            `json:"identity,omitempty"` // public, or consented private
	Extra          map[string]string `json:"extra,omitempty"`    // detail=full only
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run TestFeedbackRecordJSON`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/types.go internal/model/feedback_test.go
git commit -m "feat(model): FeedbackRecord type + bump Version to v0.3.0-rc1"
```

---

### Task 2: `feedback.Minimize` — the deterministic scrub

The heart of the privacy guarantee. Turns an `Assessment` + label into an anonymous
record. All helpers are pure and deterministic (Rule 6 — code answers, no model).

**Note on `codesign` values:** the spec listed `unsigned|adhoc|signed|notarized`, but
the collector's real states (`internal/collect/codesign.go`) are unsigned / revoked /
signed / signed-and-Gatekeeper-accepted. We map to `unsigned|revoked|signed|notarized|unknown`
(`notarized` = signed AND an `authority` fact is present, i.e. Gatekeeper accepted;
`unknown` = no codesign evidence). This is a faithful reconciliation of the spec to the
signals we actually collect; `adhoc` is not collected and is omitted.

**Files:**
- Create: `internal/feedback/minimize.go`
- Test: `internal/feedback/minimize_test.go`

**Interfaces:**
- Consumes: `model.Assessment`, `model.FeedbackRecord`, `model.Evidence`, `model.KindCodesign`.
- Produces: `func Minimize(a model.Assessment, label string) model.FeedbackRecord` (Nonce empty, Extra nil — filled by Capture). Package `feedback`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/minimize_test.go
package feedback

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func asmt(path, label string, score int, rec model.Recommendation, ev ...model.Evidence) model.Assessment {
	return model.Assessment{
		Finding:        model.Finding{Subject: model.Subject{Path: path, Label: label}, Score: score, Evidence: ev, Tripwire: ""},
		Recommendation: rec, Category: "surveillance-capable",
	}
}

func TestMinimize_DropsRawIdentifiers(t *testing.T) {
	a := asmt("/Users/jon/secret-project/beacon", "com.private.beacon", 12, model.RecQuarantine,
		model.Evidence{Kind: model.KindPersistence, Subject: model.Subject{Path: "/Users/jon/secret-project/beacon"}},
		model.Evidence{Kind: model.KindCodesign, Facts: map[string]string{"signed": "false"}})
	r := Minimize(a, model.LabelFalsePositive)
	blob := r.Schema + r.Tool + r.Label + r.Recommendation + r.Category + r.ScoreBand +
		strings.Join(r.Signals, ",") + r.Codesign + r.PathClass + r.Identity
	for _, secret := range []string{"jon", "secret-project", "beacon", "com.private"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("record leaked %q: %+v", secret, r)
		}
	}
	if r.Identity != "" {
		t.Fatalf("private identity must be dropped, got %q", r.Identity)
	}
	if r.PathClass != "user-library" && r.PathClass != "other" {
		// /Users/... without /Library/ classes as "other"
		if r.PathClass != "other" {
			t.Fatalf("unexpected path_class %q", r.PathClass)
		}
	}
	if r.Recommendation != "quarantine" || r.ScoreBand != "10-14" || r.Codesign != "unsigned" {
		t.Fatalf("bad fingerprint: %+v", r)
	}
	if want := []string{"codesign", "persistence"}; strings.Join(r.Signals, ",") != strings.Join(want, ",") {
		t.Fatalf("signals = %v, want sorted %v", r.Signals, want)
	}
}

func TestMinimize_PublicIdentityKept(t *testing.T) {
	apple := asmt("/Applications/Safari.app", "com.apple.Safari", 6, model.RecInvestigate)
	if got := Minimize(apple, model.LabelFalsePositive).Identity; got != "com.apple.Safari" {
		t.Fatalf("apple-namespace identity should be kept, got %q", got)
	}
	notarized := asmt("/Applications/Docker.app/x", "com.docker.docker", 6, model.RecInvestigate,
		model.Evidence{Kind: model.KindCodesign, Facts: map[string]string{"signed": "true", "authority": "Developer ID Application: Docker Inc"}})
	got := Minimize(notarized, model.LabelFalsePositive)
	if got.Identity != "com.docker.docker" {
		t.Fatalf("Gatekeeper-accepted identity should be kept, got %q", got.Identity)
	}
	if got.Codesign != "notarized" {
		t.Fatalf("codesign = %q, want notarized", got.Codesign)
	}
}

func TestScoreBandBoundaries(t *testing.T) {
	for _, c := range []struct {
		s    int
		want string
	}{{0, "0-4"}, {4, "0-4"}, {5, "5-9"}, {9, "5-9"}, {14, "10-14"}, {15, "15+"}, {99, "15+"}} {
		if got := scoreBand(c.s); got != c.want {
			t.Fatalf("scoreBand(%d) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestPathClass(t *testing.T) {
	for _, c := range []struct{ p, want string }{
		{"/System/Library/x", "system"},
		{"/usr/local/bin/x", "system"},
		{"/Users/jon/Library/LaunchAgents/x.plist", "user-library"},
		{"/Users/jon/.hidden/beacon", "hidden"},
		{"/private/var/folders/xx/T/x", "tmp"},
		{"/tmp/x", "tmp"},
		{"/opt/weird/x", "system"},
		{"/Users/jon/Downloads/x", "other"},
		{"", "other"},
	} {
		if got := pathClass(c.p); got != c.want {
			t.Fatalf("pathClass(%q) = %q, want %q", c.p, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/`
Expected: FAIL — `undefined: Minimize` (package doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/minimize.go

// Package feedback turns labeled findings into intrinsically-anonymous field reports
// and pushes them to a write-only sink. Anonymity lives in the data: no raw path,
// username, hostname, or (by default) private identifier ever leaves the machine.
package feedback

import (
	"sort"
	"strings"

	"counterspy/internal/model"
)

// Minimize scrubs an Assessment into an anonymous fingerprint + label. It leaves Nonce
// empty and Extra nil — Capture fills those. Deterministic; no I/O.
func Minimize(a model.Assessment, label string) model.FeedbackRecord {
	return model.FeedbackRecord{
		Schema:         model.FeedbackSchema,
		Tool:           model.Version,
		Label:          label,
		Recommendation: strings.ToLower(string(a.Recommendation)),
		Category:       a.Category,
		ScoreBand:      scoreBand(a.Score),
		Signals:        signalsOf(a),
		Codesign:       codesignClass(a),
		PathClass:      pathClass(a.Subject.Path),
		Tripwire:       a.Tripwire != "",
		Identity:       publicIdentity(a),
	}
}

func scoreBand(s int) string {
	switch {
	case s <= 4:
		return "0-4"
	case s <= 9:
		return "5-9"
	case s <= 14:
		return "10-14"
	default:
		return "15+"
	}
}

// pathClass maps a path to a coarse class, never revealing the path itself.
// Precedence: tmp → user-library → system → hidden → other.
func pathClass(p string) string {
	switch {
	case p == "":
		return "other"
	case hasAnyPrefix(p, "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"):
		return "tmp"
	case strings.Contains(p, "/Users/") && strings.Contains(p, "/Library/"):
		return "user-library"
	case hasAnyPrefix(p, "/System", "/usr", "/bin", "/sbin", "/Library/", "/opt"):
		return "system"
	case strings.Contains(p, "/."):
		return "hidden"
	default:
		return "other"
	}
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// signalsOf returns the distinct collector kinds that contributed, sorted for stability.
func signalsOf(a model.Assessment) []string {
	set := map[string]bool{}
	for _, e := range a.Evidence {
		set[string(e.Kind)] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// codesignClass derives the signature state from codesign evidence facts.
// notarized = signed AND Gatekeeper-accepted (an authority fact was recorded).
func codesignClass(a model.Assessment) string {
	for _, e := range a.Evidence {
		if e.Kind != model.KindCodesign {
			continue
		}
		switch e.Facts["signed"] {
		case "false":
			return "unsigned"
		case "revoked":
			return "revoked"
		case "true":
			if e.Facts["authority"] != "" {
				return "notarized"
			}
			return "signed"
		}
	}
	return "unknown"
}

// publicIdentity returns the app identity ONLY when it is recognizably public:
// an Apple-namespace bundle ID, or a Gatekeeper-accepted binary (authority fact present).
// Everything else returns "" — a private identifier is never published without consent.
func publicIdentity(a model.Assessment) string {
	label := a.Subject.Label
	if label == "" {
		return ""
	}
	if strings.HasPrefix(label, "com.apple.") {
		return label
	}
	for _, e := range a.Evidence {
		if e.Kind == model.KindCodesign && e.Facts["authority"] != "" {
			return label
		}
	}
	return ""
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/feedback/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/minimize.go internal/feedback/minimize_test.go
git commit -m "feat(feedback): Minimize — deterministic anonymous scrub with public-identity gating"
```

---

### Task 3: `feedback.Capture` — nonce + detail=full opt-in

**Files:**
- Create: `internal/feedback/capture.go`
- Test: `internal/feedback/capture_test.go`

**Interfaces:**
- Consumes: `Minimize`, `model.Assessment`.
- Produces: `type Detail string`; consts `DetailPublic`, `DetailFull`; `func Capture(a model.Assessment, label string, detail Detail, nonce string) model.FeedbackRecord`; `func NewNonce() string`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/capture_test.go
package feedback

import (
	"testing"

	"counterspy/internal/model"
)

func TestCapture_PublicDropsPrivate(t *testing.T) {
	a := asmt("/Users/jon/.tools/x", "com.private.tool", 8, model.RecInvestigate)
	r := Capture(a, model.LabelFalsePositive, DetailPublic, "nonce-1")
	if r.Nonce != "nonce-1" {
		t.Fatalf("nonce not set: %q", r.Nonce)
	}
	if r.Identity != "" {
		t.Fatalf("public detail must drop private identity, got %q", r.Identity)
	}
	if r.Extra != nil {
		t.Fatalf("public detail must carry no extra, got %+v", r.Extra)
	}
}

func TestCapture_FullIncludesPrivateIdentityAndPath(t *testing.T) {
	a := asmt("/Users/jon/.tools/x", "com.private.tool", 8, model.RecInvestigate)
	r := Capture(a, model.LabelFalsePositive, DetailFull, "nonce-2")
	if r.Identity != "com.private.tool" {
		t.Fatalf("full detail should include the private identity, got %q", r.Identity)
	}
	if r.Extra["path"] != "/Users/jon/.tools/x" {
		t.Fatalf("full detail should include raw path in extra, got %+v", r.Extra)
	}
}

func TestNewNonce_NonEmptyAndVaries(t *testing.T) {
	if a, b := NewNonce(), NewNonce(); a == "" || a == b {
		t.Fatalf("nonce should be non-empty and vary: %q %q", a, b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/ -run TestCapture`
Expected: FAIL — `undefined: Capture`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/capture.go
package feedback

import (
	"crypto/rand"
	"encoding/hex"

	"counterspy/internal/model"
)

// Detail is the user-chosen richness of shared data.
type Detail string

const (
	DetailPublic Detail = "public" // default: fingerprint + public identity only
	DetailFull   Detail = "full"   // opt-in: also private identity + raw context
)

// Capture builds the final record: the anonymous fingerprint from Minimize, plus a
// per-submission nonce, plus (only under DetailFull) the private identity and raw context.
func Capture(a model.Assessment, label string, detail Detail, nonce string) model.FeedbackRecord {
	r := Minimize(a, label)
	r.Nonce = nonce
	if detail == DetailFull {
		if a.Subject.Label != "" {
			r.Identity = a.Subject.Label // consented: include the private identifier too
		}
		extra := map[string]string{}
		if a.Subject.Path != "" {
			extra["path"] = a.Subject.Path
		}
		if len(extra) > 0 {
			r.Extra = extra
		}
	}
	return r
}

// NewNonce returns a random, non-correlatable submission nonce. Not used for identity —
// it deduplicates a single submission's records, not a user across submissions.
func NewNonce() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/feedback/ -run 'TestCapture|TestNewNonce'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/capture.go internal/feedback/capture_test.go
git commit -m "feat(feedback): Capture with nonce + detail=full opt-in"
```

---

### Task 4: `feedback.Store` — local persistence + dedup by fingerprint

**Files:**
- Create: `internal/feedback/store.go`
- Test: `internal/feedback/store_test.go`

**Interfaces:**
- Consumes: `model.FeedbackRecord`.
- Produces: `type Store`; `func NewStore(path string) *Store`; `func (s *Store) Add(r model.FeedbackRecord) error`; `func (s *Store) Pending() ([]model.FeedbackRecord, error)`; `func (s *Store) MarkSent(sent []model.FeedbackRecord) error`; `func Fingerprint(r model.FeedbackRecord) string`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/store_test.go
package feedback

import (
	"path/filepath"
	"testing"

	"counterspy/internal/model"
)

func rec(label, cat, band string) model.FeedbackRecord {
	return model.FeedbackRecord{Schema: "1", Label: label, Category: cat, ScoreBand: band,
		Signals: []string{"persistence"}, Codesign: "unsigned", PathClass: "hidden", Nonce: "x"}
}

func TestStore_AddDedupesByFingerprint(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "feedback.json"))
	if err := s.Add(rec(model.LabelTruePositive, "backdoor", "10-14")); err != nil {
		t.Fatal(err)
	}
	// Same fingerprint, relabeled → updates in place, does not duplicate.
	if err := s.Add(rec(model.LabelFalsePositive, "backdoor", "10-14")); err != nil {
		t.Fatal(err)
	}
	p, err := s.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 {
		t.Fatalf("expected 1 deduped record, got %d", len(p))
	}
	if p[0].Label != model.LabelFalsePositive {
		t.Fatalf("relabel should win, got %q", p[0].Label)
	}
	// A different fingerprint is a separate record.
	if err := s.Add(rec(model.LabelTruePositive, "keylogger", "15+")); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(); len(p) != 2 {
		t.Fatalf("expected 2 records, got %d", len(p))
	}
}

func TestStore_MarkSentClearsPending(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "feedback.json"))
	r := rec(model.LabelFalsePositive, "backdoor", "10-14")
	_ = s.Add(r)
	if err := s.MarkSent([]model.FeedbackRecord{r}); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Fatalf("expected 0 pending after MarkSent, got %d", len(p))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/ -run TestStore`
Expected: FAIL — `undefined: NewStore`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/store.go
package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// Store persists labeled records locally (under the invoking user's home) so ask-mode
// review, offline retry, and manual export all work. Records dedupe by fingerprint.
type Store struct{ path string }

type entry struct {
	Record model.FeedbackRecord `json:"record"`
	Sent   bool                 `json:"sent"`
}

func NewStore(path string) *Store { return &Store{path: path} }

// Fingerprint is the stable identity of a finding's anonymous shape (nonce/label excluded)
// so relabeling the same finding updates rather than duplicates.
func Fingerprint(r model.FeedbackRecord) string {
	key := strings.Join([]string{
		r.Recommendation, r.Category, r.ScoreBand,
		strings.Join(r.Signals, ","), r.Codesign, r.PathClass, r.Identity,
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) load() ([]entry, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []entry
	if len(b) == 0 {
		return nil, nil
	}
	return es, json.Unmarshal(b, &es)
}

func (s *Store) save(es []entry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// Add upserts a record by fingerprint (relabel wins; a re-added sent record re-opens).
func (s *Store) Add(r model.FeedbackRecord) error {
	es, err := s.load()
	if err != nil {
		return err
	}
	fp := Fingerprint(r)
	for i := range es {
		if Fingerprint(es[i].Record) == fp {
			es[i].Record = r
			es[i].Sent = false
			return s.save(es)
		}
	}
	return s.save(append(es, entry{Record: r}))
}

// Pending returns records not yet marked sent.
func (s *Store) Pending() ([]model.FeedbackRecord, error) {
	es, err := s.load()
	if err != nil {
		return nil, err
	}
	var out []model.FeedbackRecord
	for _, e := range es {
		if !e.Sent {
			out = append(out, e.Record)
		}
	}
	return out, nil
}

// MarkSent flags the given records (by fingerprint) as submitted.
func (s *Store) MarkSent(sent []model.FeedbackRecord) error {
	es, err := s.load()
	if err != nil {
		return err
	}
	mark := map[string]bool{}
	for _, r := range sent {
		mark[Fingerprint(r)] = true
	}
	for i := range es {
		if mark[Fingerprint(es[i].Record)] {
			es[i].Sent = true
		}
	}
	return s.save(es)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/feedback/ -run TestStore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/store.go internal/feedback/store_test.go
git commit -m "feat(feedback): local Store with fingerprint dedup + sent tracking"
```

---

### Task 5: `Transmitter` interface + `FileTransmitter`

**Files:**
- Create: `internal/feedback/transmit.go`
- Test: `internal/feedback/transmit_test.go`

**Interfaces:**
- Consumes: `model.FeedbackRecord`.
- Produces: `type Transmitter interface { Send(ctx context.Context, records []model.FeedbackRecord) error }`; `type FileTransmitter struct { Path string }`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/transmit_test.go
package feedback

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestFileTransmitter_WritesJSONL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.jsonl")
	var tx Transmitter = &FileTransmitter{Path: p}
	err := tx.Send(context.Background(), []model.FeedbackRecord{
		rec(model.LabelFalsePositive, "backdoor", "10-14"),
		rec(model.LabelTruePositive, "keylogger", "15+"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d: %s", len(lines), b)
	}
	if !strings.Contains(lines[0], `"category":"backdoor"`) {
		t.Fatalf("line not a record: %s", lines[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/ -run TestFileTransmitter`
Expected: FAIL — `undefined: Transmitter`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/transmit.go
package feedback

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"counterspy/internal/model"
)

// Transmitter is the write-only egress seam. It returns ONLY an error — there is no
// method that reads, so the network can never speak back into program state
// (egress-only invariant; enforced by TestEgressOnly).
type Transmitter interface {
	Send(ctx context.Context, records []model.FeedbackRecord) error
}

// FileTransmitter appends records as JSONL — the build/test stub and the manual-export path.
type FileTransmitter struct{ Path string }

func (f *FileTransmitter) Send(_ context.Context, records []model.FeedbackRecord) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(f.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	enc := json.NewEncoder(fh)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/feedback/ -run TestFileTransmitter`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/transmit.go internal/feedback/transmit_test.go
git commit -m "feat(feedback): write-only Transmitter interface + FileTransmitter"
```

---

### Task 6: `HTTPTransmitter` + `TestEgressOnly`

**Files:**
- Create: `internal/feedback/http.go`
- Test: `internal/feedback/http_test.go`
- Test: `internal/feedback/egress_test.go`

**Interfaces:**
- Consumes: `Transmitter`, `model.FeedbackRecord`.
- Produces: `type HTTPTransmitter struct { URL string; Client *http.Client }`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/http_test.go
package feedback

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"counterspy/internal/model"
)

func TestHTTPTransmitter_PostsAndIgnoresBody(t *testing.T) {
	var got []model.FeedbackRecord
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		// Return a body the client MUST ignore (egress-only): if the client ever decoded
		// this into an allowlist/command, that would violate the invariant.
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"command":"disable-all"}`))
	}))
	defer srv.Close()

	tx := &HTTPTransmitter{URL: srv.URL}
	if err := tx.Send(context.Background(), []model.FeedbackRecord{rec(model.LabelFalsePositive, "backdoor", "10-14")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(got) != 1 || got[0].Category != "backdoor" {
		t.Fatalf("server did not receive the record: %+v", got)
	}
}

func TestHTTPTransmitter_NonNamed2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	tx := &HTTPTransmitter{URL: srv.URL}
	if err := tx.Send(context.Background(), []model.FeedbackRecord{rec(model.LabelFalsePositive, "x", "0-4")}); err == nil {
		t.Fatal("a 500 must return an error so the record is kept for retry")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/ -run TestHTTPTransmitter`
Expected: FAIL — `undefined: HTTPTransmitter`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/http.go
package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"counterspy/internal/model"
)

// HTTPTransmitter POSTs records to the author-owned endpoint. It is strictly egress-only:
// it reads ONLY the HTTP status code to decide keep-for-retry vs. clear, and discards the
// response body without decoding it. No allowlist/command/config can flow back.
type HTTPTransmitter struct {
	URL    string
	Client *http.Client
}

func (h *HTTPTransmitter) Send(ctx context.Context, records []model.FeedbackRecord) error {
	body, err := json.Marshal(records)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	// Egress-only: drain-and-discard. The body is NEVER decoded into program state.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("feedback endpoint returned %d", resp.StatusCode)
	}
	return nil
}
```

- [ ] **Step 4: Write the egress-only invariant guard**

```go
// internal/feedback/egress_test.go
package feedback

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEgressOnly enforces the push-only invariant as CI, not memory: no file in the
// feedback package may decode an HTTP response body into program state, and the only
// place a response is touched is the drain-and-discard in http.go. Any future refactor
// that reads resp.Body back into a value fails here (Egress-Only Invariant, layer 2/3).
func TestEgressOnly(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	// Patterns that would mean "the network spoke back into the program".
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`Decode\(\s*&?\w*[rR]esp`),           // json.NewDecoder(resp.Body).Decode(&x)
		regexp.MustCompile(`Unmarshal\([^)]*[rR]esp`),           // json.Unmarshal(respBody, &x)
		regexp.MustCompile(`NewDecoder\(\s*\w*[rR]esp\.Body\s*\)\.Decode`),
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, re := range forbidden {
			if re.MatchString(src) {
				t.Errorf("%s decodes an HTTP response — egress-only invariant forbids reading a reply into program state", f)
			}
		}
	}
	// Positive assertion: the http transmitter drains-and-discards.
	b, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "io.Discard") {
		t.Error("http.go must drain the response body to io.Discard (egress-only)")
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/feedback/ -run 'TestHTTPTransmitter|TestEgressOnly'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/feedback/http.go internal/feedback/http_test.go internal/feedback/egress_test.go
git commit -m "feat(feedback): egress-only HTTPTransmitter + TestEgressOnly invariant guard"
```

---

### Task 7: `feedback.Config` — three-way consent + detail

**Files:**
- Create: `internal/feedback/config.go`
- Test: `internal/feedback/config_test.go`

**Interfaces:**
- Produces: `type Config struct { Share string; Detail Detail; Endpoint string }`; consts `ShareOff`, `ShareAsk`, `ShareAlways`; `func LoadConfig(path string) Config`.

- [ ] **Step 1: Write the failing test**

```go
// internal/feedback/config_test.go
package feedback

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_DefaultsToOff(t *testing.T) {
	c := LoadConfig(filepath.Join(t.TempDir(), "nope.json")) // missing file
	if c.Share != ShareOff || c.Detail != DetailPublic {
		t.Fatalf("missing config must default to off/public, got %+v", c)
	}
}

func TestLoadConfig_ParsesAndFailsSafe(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	_ = os.WriteFile(p, []byte(`{"share":"always","detail":"full","endpoint":"https://x"}`), 0o600)
	c := LoadConfig(p)
	if c.Share != ShareAlways || c.Detail != DetailFull || c.Endpoint != "https://x" {
		t.Fatalf("bad parse: %+v", c)
	}
	// An unknown share value fails safe to off.
	_ = os.WriteFile(p, []byte(`{"share":"bogus"}`), 0o600)
	if LoadConfig(p).Share != ShareOff {
		t.Fatal("unknown share must fail safe to off")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/feedback/ -run TestLoadConfig`
Expected: FAIL — `undefined: LoadConfig`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/feedback/config.go
package feedback

import (
	"encoding/json"
	"os"
)

// Share is the three-way consent level. Default (and any invalid value) is off.
const (
	ShareOff    = "off"    // never touches the network (default)
	ShareAsk    = "ask"    // show exact records, confirm each session
	ShareAlways = "always" // standing consent
)

// Config is the user's feedback preference, stored under the invoking user's home.
type Config struct {
	Share    string `json:"share"`
	Detail   Detail `json:"detail"`
	Endpoint string `json:"endpoint"`
}

// LoadConfig reads the config, failing safe to off/public on any error or unknown value —
// a fresh install shares nothing until the user explicitly opts in.
func LoadConfig(path string) Config {
	c := Config{Share: ShareOff, Detail: DetailPublic}
	b, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	var raw Config
	if json.Unmarshal(b, &raw) != nil {
		return c
	}
	switch raw.Share {
	case ShareAsk, ShareAlways:
		c.Share = raw.Share
	}
	if raw.Detail == DetailFull {
		c.Detail = DetailFull
	}
	c.Endpoint = raw.Endpoint
	return c
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/feedback/ -run TestLoadConfig`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/feedback/config.go internal/feedback/config_test.go
git commit -m "feat(feedback): three-way consent Config, off-by-default fail-safe"
```

---

### Task 8: TUI labeling keys (`g`/`b`) + toast

Labeling flows through the existing `Actor` seam (extended with `Label`) so `internal/tui`
keeps importing only `internal/model`. `update` stays pure — it emits a `Cmd`.

**Files:**
- Modify: `internal/tui/update.go`
- Modify: `internal/tui/run.go:9-13` (extend `Actor`), `internal/tui/run.go` (handle new Cmds)
- Modify: `internal/tui/view.go` (help lines)
- Test: `internal/tui/label_test.go`

**Interfaces:**
- Consumes: `model.LabelFalsePositive`, `model.LabelTruePositive`.
- Produces: `Cmd.Op` values `"labelFP"` and `"labelTP"`; `Actor.Label(a model.Assessment, falsePositive bool) error`.

- [ ] **Step 1: Write the failing test**

```go
// internal/tui/label_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type labelActor struct {
	lastFP bool
	labeled model.Assessment
	calls  int
}

func (l *labelActor) Quarantine(a model.Assessment) (string, error) { return "", nil }
func (l *labelActor) Restore(string) error                          { return nil }
func (l *labelActor) Label(a model.Assessment, fp bool) error {
	l.calls++
	l.lastFP = fp
	l.labeled = a
	return nil
}

func TestUpdate_GBEmitLabelCmds(t *testing.T) {
	m := New([]model.Assessment{mk("beacon", model.RecInvestigate, 8)}, nil)
	_, cmds := update(m, tcell.KeyRune, 'g')
	if len(cmds) != 1 || cmds[0].Op != "labelFP" {
		t.Fatalf("g should emit labelFP, got %+v", cmds)
	}
	_, cmds = update(m, tcell.KeyRune, 'b')
	if len(cmds) != 1 || cmds[0].Op != "labelTP" {
		t.Fatalf("b should emit labelTP, got %+v", cmds)
	}
}

func TestRun_LabelReachesActorViaSimScreen(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	s.InjectKey(tcell.KeyRune, 'g', tcell.ModNone) // label FP
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone) // quit
	la := &labelActor{}
	m := New([]model.Assessment{mk("beacon", model.RecInvestigate, 8)}, nil)
	if err := Run(s, m, la); err != nil {
		t.Fatal(err)
	}
	if la.calls != 1 || la.lastFP != true || la.labeled.Subject.Label != "beacon" {
		t.Fatalf("label did not reach the actor: %+v", la)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run 'TestUpdate_GB|TestRun_Label'`
Expected: FAIL — `Actor` has no `Label` / no `labelFP` handling.

- [ ] **Step 3: Extend the `Actor` interface and comment**

In `internal/tui/run.go`, replace the `Actor` interface (lines 9-13):

```go
// Actor performs the effects the pure loop requests (satisfied by internal/act +
// internal/feedback via a main adapter). Label records a TP/FP judgement locally.
type Actor interface {
	Quarantine(a model.Assessment) (string, error)
	Restore(manifest string) error
	Label(a model.Assessment, falsePositive bool) error
}
```

- [ ] **Step 4: Handle the label Cmds in `update` and `Run`**

In `internal/tui/update.go`, add two cases inside the `switch r {` block (after `case 'u':`):

```go
			case 'g':
				if n == 0 || m.Selected >= n {
					break
				}
				return m, []Cmd{{Op: "labelFP", A: v[m.Selected]}}
			case 'b':
				if n == 0 || m.Selected >= n {
					break
				}
				return m, []Cmd{{Op: "labelTP", A: v[m.Selected]}}
```

In `internal/tui/run.go`, add two cases to the `switch c.Op {` block (after the `"restore"` case):

```go
			case "labelFP", "labelTP":
				fp := c.Op == "labelFP"
				if err := actor.Label(c.A, fp); err != nil {
					m.Toast = "could not record label: " + err.Error()
					break
				}
				verdict := "correctly flagged"
				if fp {
					verdict = "false positive"
				}
				m.Toast = "marked " + c.A.Subject.Display() + " as " + verdict
```

- [ ] **Step 5: Add help lines**

In `internal/tui/view.go`, find `drawHelp` and add these two lines to the key list (match the existing help-line format used for `q`/`u`):

```go
	// in the slice/sequence of help lines drawHelp renders:
	"  g          mark selected as a FALSE positive (legit)",
	"  b          mark selected as correctly flagged (bad)",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/tui/`
Expected: PASS (including the unchanged `TestDecouplingInvariant` — tui still imports only model).

- [ ] **Step 7: Commit**

```bash
git add internal/tui/update.go internal/tui/run.go internal/tui/view.go internal/tui/label_test.go
git commit -m "feat(tui): g/b label keys flowing through the Actor seam"
```

---

### Task 9: main wiring — invoking-user home, config, `cliActor.Label`

**Files:**
- Modify: `main.go` (add helpers + `cliActor` fields + `Label`)
- Test: `main_test.go`

**Interfaces:**
- Consumes: `feedback.Config`, `feedback.Store`, `feedback.Capture`, `feedback.NewNonce`, `feedback.LoadConfig`.
- Produces: `func invokingUserHome() string`; `func feedbackPaths() (configPath, storePath string)`; `cliActor` gains `store *feedback.Store`, `detail feedback.Detail`, and a `Label` method.

- [ ] **Step 1: Write the failing test**

```go
// add to main_test.go
func TestInvokingUserHome_PrefersSudoUser(t *testing.T) {
	// When SUDO_USER is unset, falls back to os.UserHomeDir (non-empty).
	t.Setenv("SUDO_USER", "")
	if invokingUserHome() == "" {
		t.Fatal("expected a non-empty home fallback")
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
```

Add `"counterspy/internal/feedback"` to the imports of `main_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestInvokingUserHome|TestCliActor_Label'`
Expected: FAIL — `undefined: invokingUserHome` / `cliActor` has no `store`.

- [ ] **Step 3: Write minimal implementation**

Add `"os/user"` and `"counterspy/internal/feedback"` to `main.go` imports. Add these helpers:

```go
// invokingUserHome resolves the HOME of the human who ran the tool, not root's — the tool
// runs under sudo, so os.UserHomeDir() would point at /var/root. Falls back to os.UserHomeDir.
func invokingUserHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

// feedbackPaths returns the config and local-store paths under the invoking user's home.
func feedbackPaths() (configPath, storePath string) {
	base := filepath.Join(invokingUserHome(), ".config", "counterspy")
	return filepath.Join(base, "feedback.json"), filepath.Join(base, "feedback-store.json")
}
```

Extend the `cliActor` struct (add two fields):

```go
type cliActor struct {
	root, ts string
	readOnly bool
	store    *feedback.Store
	detail   feedback.Detail
}
```

Add the `Label` method:

```go
// Label records a TP/FP judgement to the local store (no network — submission is a
// separate, consent-gated step). A read-only snapshot may still be labeled.
func (c *cliActor) Label(a model.Assessment, falsePositive bool) error {
	if c.store == nil {
		return nil
	}
	label := model.LabelTruePositive
	if falsePositive {
		label = model.LabelFalsePositive
	}
	return c.store.Add(feedback.Capture(a, label, c.detail, feedback.NewNonce()))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestInvokingUserHome|TestCliActor_Label'`
Expected: PASS. Also run `go build ./...` — the `cliActor` in `runTUI` must still compile (its literal doesn't set the new fields yet; that's wired in Task 10).

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(main): invoking-user home + cliActor.Label persisting to the local store"
```

---

### Task 10: submission (consent gates) + `counterspy feedback` subcommand

**Files:**
- Modify: `main.go` (wire store/config into `runTUI`; add `submitFeedback`; add `runFeedback`; dispatch)
- Test: `main_test.go`

**Interfaces:**
- Consumes: `feedback.Transmitter`, `feedback.Config`, `feedback.Store`.
- Produces: `func submitFeedback(cfg feedback.Config, store *feedback.Store, tx feedback.Transmitter, ask bool, in io.Reader, out io.Writer) error`; `func chooseTransmitter(cfg feedback.Config, storePath string) feedback.Transmitter`; `feedback` subcommand.

- [ ] **Step 1: Write the failing test**

```go
// add to main_test.go
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
```

Ensure `main_test.go` imports include `"context"`, `"io"`, `"strings"` (add any missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestSubmit`
Expected: FAIL — `undefined: submitFeedback`.

- [ ] **Step 3: Write minimal implementation**

Add to `main.go` (imports already include `context`? add `"context"` if missing):

```go
// submitFeedback pushes pending labels according to the consent level. off → nothing;
// ask → show the exact records and require an explicit yes; always → best-effort send.
// A failed send keeps the records for retry (triage never blocks on telemetry).
func submitFeedback(cfg feedback.Config, store *feedback.Store, tx feedback.Transmitter, ask bool, in io.Reader, out io.Writer) error {
	if cfg.Share == feedback.ShareOff {
		return nil
	}
	pending, err := store.Pending()
	if err != nil || len(pending) == 0 {
		return err
	}
	if ask {
		fmt.Fprintf(out, "\n  Share %d anonymized feedback record(s)? The exact bytes:\n", len(pending))
		b, _ := json.MarshalIndent(pending, "  ", "  ")
		fmt.Fprintf(out, "  %s\n  send? [y/N] ", string(b))
		line, _ := bufio.NewReader(in).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			fmt.Fprintln(out, "  not shared (kept locally).")
			return nil
		}
	}
	if err := tx.Send(context.Background(), pending); err != nil {
		fmt.Fprintln(out, "  feedback not sent (kept for retry):", err)
		return err
	}
	fmt.Fprintf(out, "  shared %d record(s). Thank you.\n", len(pending))
	return store.MarkSent(pending)
}

// chooseTransmitter uses the configured HTTP endpoint when set, else falls back to a local
// export file (the manual-share path) so labels are never lost when no endpoint is configured.
func chooseTransmitter(cfg feedback.Config, storeDir string) feedback.Transmitter {
	if cfg.Endpoint != "" {
		return &feedback.HTTPTransmitter{URL: cfg.Endpoint}
	}
	return &feedback.FileTransmitter{Path: filepath.Join(storeDir, "feedback-export.jsonl")}
}
```

- [ ] **Step 4: Wire the store into `runTUI` and add end-of-session submission**

In `main.go`, inside `runTUI`, replace the actor construction (around line 275) and add submission before `return 0`:

```go
	cfgPath, storePath := feedbackPaths()
	cfg := feedback.LoadConfig(cfgPath)
	store := feedback.NewStore(storePath)
	actor := &cliActor{
		root: filepath.Join(home, "CounterSpyQuarantine", ts), ts: ts,
		readOnly: from != "", store: store, detail: cfg.Detail,
	}
	// ... existing plannedActions loop, tui.New, ReadOnly, tui.Run(...) unchanged ...
```

And immediately before the final `return 0` of `runTUI` (after a successful `tui.Run`):

```go
	_ = submitFeedback(cfg, store, chooseTransmitter(cfg, filepath.Dir(storePath)), cfg.Share == feedback.ShareAsk, os.Stdin, stdout)
	return 0
```

- [ ] **Step 5: Add the `feedback` subcommand**

In `main.go` `run()`, add a case to the dispatch switch (after `"restore"`):

```go
	case "feedback":
		return runFeedback(args[1:], stdout)
```

And add:

```go
// runFeedback is the non-TUI surface: list queued labels or force a submit.
func runFeedback(args []string, stdout io.Writer) int {
	cfgPath, storePath := feedbackPaths()
	cfg := feedback.LoadConfig(cfgPath)
	store := feedback.NewStore(storePath)
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		p, err := store.Pending()
		if err != nil {
			fmt.Fprintln(stdout, "feedback:", err)
			return 1
		}
		fmt.Fprintf(stdout, "%d pending feedback record(s); sharing is %q.\n", len(p), cfg.Share)
		b, _ := json.MarshalIndent(p, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	case "submit":
		if cfg.Share == feedback.ShareOff {
			fmt.Fprintln(stdout, "sharing is off — set share to \"ask\" or \"always\" in", cfgPath)
			return 0
		}
		if err := submitFeedback(cfg, store, chooseTransmitter(cfg, filepath.Dir(storePath)), true, os.Stdin, stdout); err != nil {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stdout, "usage: counterspy feedback [list|submit]")
		return 2
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test . -run TestSubmit && go build ./... && go test ./...`
Expected: PASS across all packages; build clean.

- [ ] **Step 7: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(main): consent-gated end-of-session submission + counterspy feedback subcommand"
```

---

### Task 11: docs, Release Truth, roadmap, gate, tag

**Files:**
- Modify: `README.md` (feedback + privacy section)
- Create: `docs/architext/data/roadmap.json` (v0.4.0 egress monitor)
- Modify: `docs/architext/data/releases/index.json`, `docs/architext/data/releases/v0-3-0-feedback.json` (new)
- Modify: `docs/architext/data/nodes.json` (add `mod-feedback` node; wire into `counterspy-cli` deps)

- [ ] **Step 1: Add a README section**

Add a "Field feedback (opt-in)" section to `README.md` documenting: off by default; the three levels (`off`/`ask`/`always`) and `detail` (`public`/`full`) in `~/.config/counterspy/feedback.json`; that data is an anonymous fingerprint with no raw paths/usernames; the egress-only guarantee (push-only, the tool never fetches from the network); and `counterspy feedback list|submit`.

- [ ] **Step 2: Add the `mod-feedback` architext node**

Add a node to `docs/architext/data/nodes.json` (source-backed from `internal/feedback`), and add `"mod-feedback"` to `counterspy-cli`'s `dependencies`:

```jsonc
{
  "id": "mod-feedback",
  "type": "module",
  "name": "internal/feedback",
  "summary": "Turns labeled findings into intrinsically-anonymous field reports and pushes them to a write-only sink. Egress-only: Transmitter returns only error; HTTP impl reads status only and discards the body; the tool never fetches from the network (enforced by TestEgressOnly).",
  "responsibilities": ["Minimize an Assessment to an anonymous fingerprint (public-identity gating)", "Persist/dedupe labels locally; consent-gated submission", "Push-only transport (file + http)"],
  "owner": "Project maintainers",
  "sourcePaths": ["internal/feedback/minimize.go", "internal/feedback/capture.go", "internal/feedback/store.go", "internal/feedback/transmit.go", "internal/feedback/http.go", "internal/feedback/config.go"],
  "runtime": "in-process + outbound HTTPS (POST only)",
  "interfaces": ["Minimize", "Capture", "Store", "Transmitter", "LoadConfig"],
  "dependencies": ["mod-model"],
  "dataHandled": ["scan-findings"],
  "security": ["No raw path/username/hostname leaves the machine", "Private identity dropped unless consented", "Egress-only: no network reads"],
  "observability": ["local feedback store", "feedback-export.jsonl"],
  "relatedFlows": ["scan-pipeline"],
  "relatedDecisions": [],
  "knownRisks": ["risk-false-positive-volume"],
  "verification": ["go test ./internal/feedback/", "TestEgressOnly"]
}
```

- [ ] **Step 3: Create the roadmap with the v0.4.0 egress monitor**

Create `docs/architext/data/roadmap.json` recording the future push (privacy egress monitor: per-process network observation of trusted apps, destination/volume tracking, consent deltas) with `source: "roadmap"` and its rationale. Register it in `docs/architext/data/manifest.json` if the schema requires it (run `architext doctor` to confirm).

- [ ] **Step 4: Advance Release Truth to v0.3.0**

Create `docs/architext/data/releases/v0-3-0-feedback.json` (status in-progress → complete) and update `index.json` (`currentReleaseId` → `v0-3-0-feedback`), following the shape of `v0-2-0-tui.json`. Record the false-positive blocker as **mitigated** (field feedback loop shipped) rather than open.

- [ ] **Step 5: Full gate + fix any doctor drift**

Run:
```bash
gofmt -l $(git ls-files '*.go' | grep -v '^vendor/')
go vet ./... && go test ./...
architext doctor        # apply deterministic repairs if prompted
architext validate
```
Expected: fmt clean, vet clean, all tests PASS, `architext validate` passes.

- [ ] **Step 6: Commit + tag**

```bash
git add README.md docs/
git commit -m "docs(v0.3.0): feedback README, mod-feedback node, roadmap v0.4.0, Release Truth"
git tag -a v0.3.0-rc1 -m "CounterSpy v0.3.0-rc1 — field feedback loop"
```

---

## Self-Review

**Spec coverage:**
- Anonymity-in-data → Task 2 (`Minimize`), Task 3 (`Capture`). ✓
- Egress-only invariant (3 layers) → Task 5 (interface), Task 6 (http + `TestEgressOnly`). ✓
- Data model / banding / path-class / identity policy → Tasks 1–3. ✓
- Three-way consent + detail + SUDO_USER home → Task 7, Task 9. ✓
- Labeling UX (g/b, CLI) → Task 8, Task 10. ✓
- Batched, deduped, graceful submission → Task 4 (dedup), Task 10 (submit/degrade). ✓
- Transport + GitHub mirror → Task 6 (client); Worker/mirror are author-owned prerequisites, noted out of scope. ✓
- Trust/poisoning → advisory-only is a maintainer process (documented in README, Task 11); write-only client enforced by `TestEgressOnly`. ✓
- Testing strategy → each task is TDD; `Minimize` gets the heaviest coverage. ✓
- v0.4.0 egress monitor → Task 11 (roadmap). ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. The one deliberately-external item (the Cloudflare Worker) is called out as an author-owned prerequisite, consistent with the spec.

**Type consistency:** `FeedbackRecord` fields (Task 1) are used verbatim in Tasks 2–6. `Transmitter.Send(ctx, []model.FeedbackRecord) error` is identical in Tasks 5, 6, 10. `Actor.Label(a, falsePositive bool) error` matches between Task 8 (interface + fake) and Task 9 (`cliActor`). `Detail`/`DetailPublic`/`DetailFull` consistent across Tasks 3, 7, 9. `ShareOff/Ask/Always` consistent across Tasks 7, 10.
