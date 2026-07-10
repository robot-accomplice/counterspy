# CounterSpy Egress Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A live "egress top" TUI (and non-TTY report) that profiles per-app outbound traffic — rate, destinations, cadence, and an inferred exfiltration risk — through CounterSpy's trust/provenance lens, via sudo-CLI observation.

**Architecture:** A new `internal/egress` package polls `nettop` + `lsof` per tick, joins provenance/codesign-trust/TCC-capabilities from `internal/collect`, aggregates by application (collapsing PIDs/ports/protocols), and scores concern + exfil inference — all pure given inputs. A tick-driven view in `internal/tui` renders it live; a `report` path serves non-TTY. Spec: `docs/superpowers/specs/2026-07-09-counterspy-egress-monitor-design.md`.

**Tech Stack:** Go stdlib + `os/exec`; tcell v2 (existing); reuses `internal/collect`.

## Global Constraints

- Standard library + existing internal packages + tcell only. No new third-party deps.
- `internal/model` imports only `fmt`/`strings`. `internal/tui` imports ONLY `internal/model` (+ tcell) — enforced by `TestDecouplingInvariant`; keep it green.
- All analysis is **pure and deterministic** (Rule 6): parsing, rate-diff, cadence, aggregation, concern, and exfil inference are functions of their inputs — no I/O, no clocks, no randomness inside them. The impure exec edge is isolated in one file.
- **Observe-only.** No blocking/filtering. **No payload reading** — "what is exfiltrated" is inferred from TCC capability × egress, surfaced as *candidates*, never confirmed content.
- Concern buckets are exactly `Minimal < Low < Notable < Elevated`.
- Sudo-CLI exec: `nettop -P -L 1 -x -J bytes_in,bytes_out` and `lsof -i -nP`.
- Reuse `internal/collect` (proctree, codesign, TCC) — no second process enumerator or privacy-grant reader.

---

### Task 1: model egress types

**Files:**
- Create: `internal/model/egress.go`
- Test: `internal/model/egress_test.go`

**Interfaces:**
- Produces: `Endpoint`, `Conn`, `ConcernLevel` (+ `String()`), `EgressGroup` — all in package `model`.

- [ ] **Step 1: Write the failing test**

```go
// internal/model/egress_test.go
package model

import "testing"

func TestConcernLevelString(t *testing.T) {
	for _, c := range []struct {
		l    ConcernLevel
		want string
	}{{Minimal, "minimal"}, {Low, "low"}, {Notable, "notable"}, {Elevated, "elevated"}} {
		if got := c.l.String(); got != c.want {
			t.Fatalf("ConcernLevel(%d).String() = %q, want %q", c.l, got, c.want)
		}
	}
}

func TestEgressGroupCarriesConnsAndExfil(t *testing.T) {
	g := EgressGroup{
		App: "backuptool", Trust: "unsigned", Instances: 2,
		Conns:        []Conn{{PID: 4821, Endpoint: Endpoint{IP: "198.51.100.7", Port: 443}, Proto: "tcp", OutRate: 620}},
		Capabilities: []string{"screen", "keystrokes"},
		Concern:      Elevated, ExfilRisk: Elevated, Candidate: []string{"screen", "keystrokes"},
	}
	if g.Conns[0].Endpoint.Port != 443 || g.ExfilRisk != Elevated || len(g.Candidate) != 2 {
		t.Fatalf("EgressGroup fields wrong: %+v", g)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run 'TestConcernLevel|TestEgressGroup'`
Expected: FAIL — `undefined: ConcernLevel` / `EgressGroup`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/model/egress.go
package model

// Endpoint is a remote network peer.
type Endpoint struct {
	IP   string
	Port int
}

// Conn is one established outbound connection — a constituent of an EgressGroup, revealed
// when the group is expanded in the TUI.
type Conn struct {
	PID      int
	Endpoint Endpoint
	Proto    string // "tcp" | "udp"
	OutRate  uint64 // bytes/sec (may be 0 if per-connection rate is unavailable)
}

// ConcernLevel is the coarse concern/exfil band used for coloring and sorting.
type ConcernLevel int

const (
	Minimal ConcernLevel = iota
	Low
	Notable
	Elevated
)

func (l ConcernLevel) String() string {
	switch l {
	case Elevated:
		return "elevated"
	case Notable:
		return "notable"
	case Low:
		return "low"
	default:
		return "minimal"
	}
}

// EgressGroup aggregates ALL instances (PIDs) and connections (ports/protocols/destinations)
// of one application into a single collapsible row.
type EgressGroup struct {
	App          string
	Path         string
	Ancestry     string
	Trust        string // "apple" | "notarized" | "signed" | "unsigned" | "unknown"
	Instances    int
	OutRate      uint64
	InRate       uint64
	OutTotal     uint64
	Spark        []uint64
	Cadence      string // "one-off" | "bursty" | "steady" | "periodic"
	Destinations []Endpoint
	Conns        []Conn
	Background   bool
	Capabilities []string // "screen" "keystrokes" "contacts" "full-disk" ...
	Concern      ConcernLevel
	ExfilRisk    ConcernLevel
	Candidate    []string // inferred candidate exfiltrated categories (never payloads)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -run 'TestConcernLevel|TestEgressGroup'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/egress.go internal/model/egress_test.go
git commit -m "feat(model): egress types (Endpoint, Conn, ConcernLevel, EgressGroup)"
```

---

### Task 2: export `Ancestry` from collect

The egress package needs the provenance chain; `collect.ancestry` is unexported. Export it (surgical rename) so egress reuses it instead of re-walking the process tree.

**Files:**
- Modify: `internal/collect/proctree.go` (rename `ancestry` → `Ancestry`, update its caller)
- Test: `internal/collect/proctree_test.go` (add a direct test)

**Interfaces:**
- Produces: `func Ancestry(procs map[int]*Proc, pid int) string`.

- [ ] **Step 1: Write the failing test**

```go
// add to internal/collect/proctree_test.go
func TestAncestry_Exported(t *testing.T) {
	procs := map[int]*Proc{
		1:   {PID: 1, PPID: 0, Cmd: "/sbin/launchd"},
		200: {PID: 200, PPID: 1, Cmd: "/Applications/X.app/Contents/MacOS/X --flag"},
	}
	got := Ancestry(procs, 200)
	if got != "/sbin/launchd -> /Applications/X.app/Contents/MacOS/X" {
		t.Fatalf("Ancestry = %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run TestAncestry_Exported`
Expected: FAIL — `undefined: Ancestry`.

- [ ] **Step 3: Rename**

In `internal/collect/proctree.go`: rename `func ancestry(` → `func Ancestry(` and update the one call site inside `BuildProcessEvidence` (`ancestry(procs, pid)` → `Ancestry(procs, pid)`). Update the doc comment first line to `// Ancestry walks parent links...`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collect/`
Expected: PASS (the new test + all existing collect tests — the rename is internal).

- [ ] **Step 5: Commit**

```bash
git add internal/collect/proctree.go internal/collect/proctree_test.go
git commit -m "refactor(collect): export Ancestry for reuse by internal/egress"
```

---

### Task 3: egress exec-output parsers

Two pure parsers. **Capture real output into fixtures first** (the exact `nettop` CSV columns must be confirmed on a real Mac), then make the parsers match.

**Files:**
- Create: `internal/egress/parse.go`
- Create: `internal/egress/testdata/nettop.csv`, `internal/egress/testdata/lsof.txt`
- Test: `internal/egress/parse_test.go`

**Interfaces:**
- Consumes: `model.Conn`, `model.Endpoint`.
- Produces: `type Bytes struct{ Out, In uint64 }`; `func ParseNettop([]byte) map[int]Bytes`; `func ParseLsofConns([]byte) map[int][]model.Conn`.

- [ ] **Step 1: Capture real fixtures (do this on the target Mac)**

```bash
sudo nettop -P -L 1 -x -J bytes_in,bytes_out > internal/egress/testdata/nettop.csv
sudo lsof -i -nP > internal/egress/testdata/lsof.txt
```
If you cannot run on a Mac now, create representative fixtures with these exact shapes:

`internal/egress/testdata/nettop.csv`:
```
time,,bytes_in,bytes_out
15:04:05.000000,Claude.12345,1048576,5242880
15:04:05.000000,backuptool.4821,3072,860160
```

`internal/egress/testdata/lsof.txt`:
```
COMMAND      PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Claude     12345  jon   30u  IPv4  0x1      0t0  TCP  192.168.1.5:52345->17.253.144.10:443 (ESTABLISHED)
backuptool  4821  jon   10u  IPv4  0x2      0t0  TCP  192.168.1.5:52301->198.51.100.7:443 (ESTABLISHED)
backuptool  4821  jon   11u  IPv4  0x3      0t0  UDP  192.168.1.5:52302->198.51.100.9:443
launchd        1  root   5u  IPv4  0x4      0t0  TCP  *:22 (LISTEN)
```

- [ ] **Step 2: Write the failing test**

```go
// internal/egress/parse_test.go
package egress

import (
	"os"
	"testing"
)

func TestParseNettop(t *testing.T) {
	b, _ := os.ReadFile("testdata/nettop.csv")
	m := ParseNettop(b)
	if got := m[12345]; got.Out != 5242880 || got.In != 1048576 {
		t.Fatalf("pid 12345 = %+v, want Out 5242880 In 1048576", got)
	}
	if m[4821].Out != 860160 {
		t.Fatalf("pid 4821 Out = %d, want 860160", m[4821].Out)
	}
}

func TestParseLsofConns_EstablishedOnly(t *testing.T) {
	b, _ := os.ReadFile("testdata/lsof.txt")
	m := ParseLsofConns(b)
	if len(m[12345]) != 1 || m[12345][0].Endpoint.IP != "17.253.144.10" || m[12345][0].Endpoint.Port != 443 || m[12345][0].Proto != "tcp" {
		t.Fatalf("pid 12345 conns wrong: %+v", m[12345])
	}
	if len(m[4821]) != 2 {
		t.Fatalf("pid 4821 should have 2 conns (tcp+udp), got %d", len(m[4821]))
	}
	if _, ok := m[1]; ok {
		t.Fatal("a LISTEN socket (no ->remote) must be skipped, not counted as egress")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/egress/ -run Parse`
Expected: FAIL — package/functions undefined.

- [ ] **Step 4: Write minimal implementation**

```go
// internal/egress/parse.go

// Package egress observes per-application outbound traffic via sudo-CLI polling (nettop +
// lsof), joins trust/provenance/capability from internal/collect, and scores concern and
// exfiltration-risk — all pure given inputs. Observe-only; no payloads are read.
package egress

import (
	"strconv"
	"strings"

	"counterspy/internal/model"
)

// Bytes is a cumulative byte counter pair from nettop.
type Bytes struct{ Out, In uint64 }

// ParseNettop parses `nettop -P -L 1 -x -J bytes_in,bytes_out` CSV into per-PID cumulative
// bytes. The process column is "name.pid"; byte columns are located by header name so a
// column-order change doesn't silently misread.
func ParseNettop(b []byte) map[int]Bytes {
	out := map[int]Bytes{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 0 {
		return out
	}
	header := strings.Split(lines[0], ",")
	inCol, outCol := -1, -1
	for i, h := range header {
		switch strings.TrimSpace(h) {
		case "bytes_in":
			inCol = i
		case "bytes_out":
			outCol = i
		}
	}
	for _, ln := range lines[1:] {
		f := strings.Split(ln, ",")
		if len(f) <= outCol || len(f) <= inCol || outCol < 0 || inCol < 0 {
			continue
		}
		pid := pidFromNameDotPid(f)
		if pid == 0 {
			continue
		}
		o, _ := strconv.ParseUint(strings.TrimSpace(f[outCol]), 10, 64)
		in, _ := strconv.ParseUint(strings.TrimSpace(f[inCol]), 10, 64)
		g := out[pid]
		g.Out += o
		g.In += in
		out[pid] = g
	}
	return out
}

// pidFromNameDotPid finds the "name.pid" field and returns the trailing pid, else 0.
func pidFromNameDotPid(fields []string) int {
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if dot := strings.LastIndex(f, "."); dot > 0 {
			if pid, err := strconv.Atoi(f[dot+1:]); err == nil {
				return pid
			}
		}
	}
	return 0
}

// ParseLsofConns parses `lsof -i -nP` into per-PID ESTABLISHED outbound connections. A row
// is egress only if its NAME has a "->remote" peer; LISTEN sockets (no "->") are skipped.
func ParseLsofConns(b []byte) map[int][]model.Conn {
	out := map[int][]model.Conn{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(ln)
		if len(f) < 9 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		proto := strings.ToLower(f[7]) // NODE column: TCP/UDP
		if proto != "tcp" && proto != "udp" {
			continue
		}
		name := f[8]
		arrow := strings.Index(name, "->")
		if arrow < 0 {
			continue // LISTEN / no remote peer — not egress
		}
		remote := name[arrow+2:]
		if sp := strings.IndexByte(remote, ' '); sp >= 0 {
			remote = remote[:sp] // strip " (ESTABLISHED)"
		}
		ip, port := splitHostPort(remote)
		if ip == "" {
			continue
		}
		out[pid] = append(out[pid], model.Conn{PID: pid, Endpoint: model.Endpoint{IP: ip, Port: port}, Proto: proto})
	}
	return out
}

// splitHostPort splits "IP:port" from the right so IPv6 (which contains colons) keeps its host.
func splitHostPort(s string) (string, int) {
	c := strings.LastIndex(s, ":")
	if c < 0 {
		return "", 0
	}
	port, _ := strconv.Atoi(s[c+1:])
	return s[:c], port
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/egress/ -run Parse`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/egress/parse.go internal/egress/parse_test.go internal/egress/testdata/
git commit -m "feat(egress): nettop + lsof-conns parsers (fixture-driven)"
```

---

### Task 4: rate diff + cadence

**Files:**
- Create: `internal/egress/rate.go`
- Test: `internal/egress/rate_test.go`

**Interfaces:**
- Consumes: `Bytes`.
- Produces: `func RateOut(prev, cur Bytes, intervalSec float64) uint64`; `func Cadence(history []uint64) string`.

- [ ] **Step 1: Write the failing test**

```go
// internal/egress/rate_test.go
package egress

import "testing"

func TestRateOut(t *testing.T) {
	if got := RateOut(Bytes{Out: 1000}, Bytes{Out: 3000}, 2); got != 1000 {
		t.Fatalf("RateOut = %d, want 1000 (2000 bytes / 2s)", got)
	}
	// Counter reset / process restart (cur < prev) → 0, not a huge underflow.
	if got := RateOut(Bytes{Out: 5000}, Bytes{Out: 100}, 2); got != 0 {
		t.Fatalf("RateOut on counter reset = %d, want 0", got)
	}
}

func TestCadence(t *testing.T) {
	for _, c := range []struct {
		name string
		h    []uint64
		want string
	}{
		{"one-off", []uint64{9000, 0, 0, 0, 0}, "one-off"},
		{"steady", []uint64{1000, 1100, 950, 1050, 1000}, "steady"},
		{"periodic", []uint64{0, 5000, 0, 0, 5000}, "periodic"},
		{"bursty", []uint64{200, 9000, 300, 8000, 250}, "bursty"},
	} {
		if got := Cadence(c.h); got != c.want {
			t.Fatalf("Cadence(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run 'TestRateOut|TestCadence'`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/egress/rate.go
package egress

// RateOut returns bytes/sec of OUTbound traffic between two cumulative samples. A counter
// reset (cur < prev, e.g. the process restarted) yields 0 rather than an underflow.
func RateOut(prev, cur Bytes, intervalSec float64) uint64 {
	if intervalSec <= 0 || cur.Out < prev.Out {
		return 0
	}
	return uint64(float64(cur.Out-prev.Out) / intervalSec)
}

// Cadence classifies an out-rate history (oldest→newest) into a coarse pattern:
//   one-off  — sent in exactly one sample, silent otherwise
//   periodic — multiple separated bursts with silent gaps between
//   bursty   — highly variable, no steady floor
//   steady   — consistently active with low relative variance
func Cadence(history []uint64) string {
	active := 0
	var max, sum uint64
	transitions := 0 // silent→active edges
	prevActive := false
	for _, v := range history {
		a := v > 0
		if a {
			active++
			sum += v
			if v > max {
				max = v
			}
			if !prevActive {
				transitions++
			}
		}
		prevActive = a
	}
	if active == 0 {
		return "steady" // nothing sent this window; not interesting — treat as calm
	}
	if active == 1 {
		return "one-off"
	}
	if transitions >= 2 {
		return "periodic" // repeated bursts separated by silence
	}
	mean := sum / uint64(active)
	if mean > 0 && max > mean*3 {
		return "bursty"
	}
	return "steady"
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/egress/ -run 'TestRateOut|TestCadence'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/egress/rate.go internal/egress/rate_test.go
git commit -m "feat(egress): out-rate diff (reset-safe) + cadence classifier"
```

---

### Task 5: group-by-app aggregation

Collapses per-PID instance data into one `EgressGroup` per application.

**Files:**
- Create: `internal/egress/aggregate.go`
- Test: `internal/egress/aggregate_test.go`

**Interfaces:**
- Consumes: `model.EgressGroup`, `model.Conn`, `model.Endpoint`.
- Produces: `type Instance struct{...}` (per-PID assembled data); `func Aggregate(insts []Instance, spark map[string][]uint64) []model.EgressGroup`.

- [ ] **Step 1: Write the failing test**

```go
// internal/egress/aggregate_test.go
package egress

import (
	"testing"

	"counterspy/internal/model"
)

func TestAggregate_CollapsesInstancesAndConns(t *testing.T) {
	insts := []Instance{
		{PID: 4821, App: "backuptool", Path: "/x/backuptool", Trust: "unsigned", OutRate: 620, OutTotal: 40000,
			Conns: []model.Conn{{PID: 4821, Endpoint: model.Endpoint{IP: "198.51.100.7", Port: 443}, Proto: "tcp", OutRate: 620}}},
		{PID: 4830, App: "backuptool", Path: "/x/backuptool", Trust: "unsigned", OutRate: 30, OutTotal: 2000,
			Conns: []model.Conn{{PID: 4830, Endpoint: model.Endpoint{IP: "198.51.100.7", Port: 8443}, Proto: "tcp", OutRate: 30}}},
		{PID: 99, App: "Safari", Path: "/Applications/Safari.app/Contents/MacOS/Safari", Trust: "apple", OutRate: 120, OutTotal: 5000,
			Conns: []model.Conn{{PID: 99, Endpoint: model.Endpoint{IP: "17.1.1.1", Port: 443}, Proto: "tcp"}}},
	}
	groups := Aggregate(insts, map[string][]uint64{"/x/backuptool": {600, 650, 620}})
	var bt *model.EgressGroup
	for i := range groups {
		if groups[i].App == "backuptool" {
			bt = &groups[i]
		}
	}
	if bt == nil {
		t.Fatal("backuptool group missing")
	}
	if bt.Instances != 2 {
		t.Fatalf("Instances = %d, want 2", bt.Instances)
	}
	if bt.OutRate != 650 {
		t.Fatalf("summed OutRate = %d, want 650", bt.OutRate)
	}
	if len(bt.Conns) != 2 {
		t.Fatalf("Conns = %d, want 2 (both ports)", len(bt.Conns))
	}
	if len(bt.Destinations) != 2 { // :443 and :8443 are distinct endpoints
		t.Fatalf("distinct Destinations = %d, want 2", len(bt.Destinations))
	}
	if len(bt.Spark) != 3 {
		t.Fatalf("Spark not attached: %v", bt.Spark)
	}
	// Safari (foreground .app) must be flagged Background=false.
	for _, g := range groups {
		if g.App == "Safari" && g.Background {
			t.Fatal("Safari is a .app foreground process, Background must be false")
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run TestAggregate`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/egress/aggregate.go
package egress

import (
	"sort"
	"strings"

	"counterspy/internal/model"
)

// Instance is one process's assembled egress data, before grouping by application.
type Instance struct {
	PID          int
	App          string
	Path         string
	Ancestry     string
	Trust        string
	OutRate      uint64
	InRate       uint64
	OutTotal     uint64
	Conns        []model.Conn
	Capabilities []string
}

// Aggregate collapses instances into one EgressGroup per application (keyed by Path, else
// App), summing rates/volume, unioning destinations/conns/capabilities, and taking the
// worst-case trust. `spark` maps the group key → recent summed out-rate history.
func Aggregate(insts []Instance, spark map[string][]uint64) []model.EgressGroup {
	byKey := map[string]*model.EgressGroup{}
	order := []string{}
	dests := map[string]map[string]bool{}
	caps := map[string]map[string]bool{}
	for _, in := range insts {
		key := in.Path
		if key == "" {
			key = in.App
		}
		g, ok := byKey[key]
		if !ok {
			g = &model.EgressGroup{App: in.App, Path: in.Path, Ancestry: in.Ancestry, Trust: in.Trust,
				Background: isBackground(in.Path)}
			byKey[key] = g
			order = append(order, key)
			dests[key] = map[string]bool{}
			caps[key] = map[string]bool{}
		}
		g.Instances++
		g.OutRate += in.OutRate
		g.InRate += in.InRate
		g.OutTotal += in.OutTotal
		g.Conns = append(g.Conns, in.Conns...)
		g.Trust = worseTrust(g.Trust, in.Trust)
		for _, c := range in.Conns {
			dests[key][c.Endpoint.IP+":"+itoa(c.Endpoint.Port)] = true
		}
		for _, cp := range in.Capabilities {
			if !caps[key][cp] {
				caps[key][cp] = true
				g.Capabilities = append(g.Capabilities, cp)
			}
		}
	}
	out := make([]model.EgressGroup, 0, len(order))
	for _, key := range order {
		g := byKey[key]
		for _, c := range g.Conns {
			_ = c
		}
		g.Destinations = distinctEndpoints(g.Conns)
		g.Spark = spark[key]
		g.Cadence = Cadence(g.Spark)
		sort.Strings(g.Capabilities)
		out = append(out, *g)
	}
	return out
}

// isBackground: a process is foreground iff its executable lives in a .app bundle.
func isBackground(path string) bool {
	return !strings.Contains(path, ".app/Contents/MacOS/")
}

// worseTrust returns the less-trusted of two trust labels (unknown/unsigned beat notarized).
func worseTrust(a, b string) string {
	rank := map[string]int{"unsigned": 0, "unknown": 1, "revoked": 0, "signed": 2, "notarized": 3, "apple": 4, "": 1}
	if rank[b] < rank[a] {
		return b
	}
	return a
}

func distinctEndpoints(conns []model.Conn) []model.Endpoint {
	seen := map[string]bool{}
	var out []model.Endpoint
	for _, c := range conns {
		k := c.Endpoint.IP + ":" + itoa(c.Endpoint.Port)
		if !seen[k] {
			seen[k] = true
			out = append(out, c.Endpoint)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
```

Remove the dead `for _, c := range g.Conns { _ = c }` loop before committing (it's a leftover — delete it).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/egress/ -run TestAggregate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/egress/aggregate.go internal/egress/aggregate_test.go
git commit -m "feat(egress): group-by-app aggregation (collapse pids/ports, worst-case trust)"
```

---

### Task 6: concern + exfil inference

**Files:**
- Create: `internal/egress/concern.go`
- Test: `internal/egress/concern_test.go`

**Interfaces:**
- Consumes: `model.EgressGroup`, `model.ConcernLevel`.
- Produces: `func Concern(g model.EgressGroup) model.ConcernLevel`; `func Exfil(g model.EgressGroup) (model.ConcernLevel, []string)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/egress/concern_test.go
package egress

import (
	"testing"

	"counterspy/internal/model"
)

func TestConcern(t *testing.T) {
	// Unsigned background daemon, sustained upload, raw IP → elevated.
	bad := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: 800_000,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}}}
	if got := Concern(bad); got != model.Elevated {
		t.Fatalf("Concern(bad) = %s, want elevated", got)
	}
	// Apple foreground app → minimal.
	good := model.EgressGroup{Trust: "apple", Background: false, OutRate: 120_000,
		Destinations: []model.Endpoint{{IP: "17.1.1.1", Port: 443}}}
	if got := Concern(good); got != model.Minimal {
		t.Fatalf("Concern(good) = %s, want minimal", got)
	}
}

func TestExfil(t *testing.T) {
	// Screen + keystroke capability + sustained raw-IP upload from a daemon → elevated,
	// candidates named from capabilities.
	g := model.EgressGroup{Trust: "unsigned", Background: true, OutRate: 800_000,
		Capabilities: []string{"screen", "keystrokes"},
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}}}
	risk, cand := Exfil(g)
	if risk != model.Elevated {
		t.Fatalf("Exfil risk = %s, want elevated", risk)
	}
	if len(cand) != 2 || cand[0] != "screen" {
		t.Fatalf("candidates = %v, want [screen keystrokes]", cand)
	}
	// Same capabilities but notarized foreground app sending modestly → low, candidates
	// still listed (they COULD leave) but risk is low.
	g2 := model.EgressGroup{Trust: "notarized", Background: false, OutRate: 5000,
		Capabilities: []string{"screen"}, Destinations: []model.Endpoint{{IP: "17.1.1.1", Port: 443}}}
	if risk2, _ := Exfil(g2); risk2 > model.Low {
		t.Fatalf("Exfil(notarized foreground) = %s, want <= low", risk2)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run 'TestConcern|TestExfil'`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/egress/concern.go
package egress

import "counterspy/internal/model"

const sustainedBytesPerSec = 100_000 // ~100 KB/s = a real, sustained upload

// Concern scores an aggregated group: trust × destination × volume × background-nature.
func Concern(g model.EgressGroup) model.ConcernLevel {
	score := 0
	switch g.Trust {
	case "unsigned", "unknown", "revoked":
		score += 2
	case "signed":
		score += 1
	case "notarized", "apple", "":
		// trusted — no add
	}
	if allRawIP(g.Destinations) && len(g.Destinations) > 0 {
		score += 2
	}
	if g.OutRate >= sustainedBytesPerSec {
		score++
		if g.Background {
			score++ // a quiet daemon uploading is worse than a foreground app you're using
		}
	}
	return band(score)
}

// Exfil infers exfiltration risk and candidate data categories from capability × egress.
// It NEVER reads payloads — candidates are what the capabilities COULD leak.
func Exfil(g model.EgressGroup) (model.ConcernLevel, []string) {
	candidates := append([]string(nil), g.Capabilities...)
	if len(candidates) == 0 {
		return model.Minimal, nil
	}
	// Base risk tracks concern (trust/destination/volume/nature), then capability presence
	// with real outbound volume raises it.
	score := int(Concern(g))
	if g.OutRate >= sustainedBytesPerSec {
		score++
		if g.Background {
			score++
		}
	}
	return band(score), candidates
}

func allRawIP(dests []model.Endpoint) bool {
	for _, d := range dests {
		if !isRawIP(d.IP) {
			return false
		}
	}
	return true
}

// isRawIP is a placeholder for "no resolved name" — in v1 every lsof destination is an IP,
// so this is true unless a future reverse-DNS/pcap step attaches a name. Kept as a seam.
func isRawIP(host string) bool { return host != "" }

func band(score int) model.ConcernLevel {
	switch {
	case score >= 4:
		return model.Elevated
	case score >= 3:
		return model.Notable
	case score >= 1:
		return model.Low
	default:
		return model.Minimal
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/egress/ -run 'TestConcern|TestExfil'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/egress/concern.go internal/egress/concern_test.go
git commit -m "feat(egress): concern scoring + exfil inference (capability × egress)"
```

---

### Task 7: monitor orchestrator (exec edge + per-tick pipeline)

The one impure file: runs the tools, joins collect data, holds the previous sample + per-app spark ring buffers, and produces `[]model.EgressGroup` per tick. The exec + capability lookups are injected so it's testable without a live network.

**Files:**
- Create: `internal/egress/monitor.go`
- Test: `internal/egress/monitor_test.go`

**Interfaces:**
- Consumes: everything above; `collect.ParsePs`, `collect.Ancestry`.
- Produces: `type Monitor struct{...}`; `func New(interval float64) *Monitor`; `func (m *Monitor) Sample() []model.EgressGroup`. Exec + trust + capability are `func` fields on `Monitor` (defaulted in `New`, overridable in tests).

- [ ] **Step 1: Write the failing test**

```go
// internal/egress/monitor_test.go
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
		return map[int]*collect.Proc{4821: {PID: 4821, PPID: 1, Cmd: "/Users/jon/.hidden/daemon"}}
	}
	m.trustOf = func(path string) string { return "unsigned" }
	m.capsOf = func(path string) []string { return []string{"screen", "keystrokes"} }

	m.Sample()             // first tick: establishes the baseline, rate 0
	groups := m.Sample()   // second tick: cur==prev cumulative here, so rate 0 — assert structure
	if len(groups) != 1 || groups[0].App == "" {
		t.Fatalf("expected one group, got %+v", groups)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/egress/ -run TestMonitor`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/egress/monitor.go
package egress

import (
	"os/exec"
	"path/filepath"

	"counterspy/internal/collect"
	"counterspy/internal/model"
)

const sparkLen = 24 // recent out-rate samples kept per app for the sparkline

// Monitor holds the sampling state (previous cumulative bytes + per-app spark history) and
// the injectable exec/join seams. Sample() is called once per tick.
type Monitor struct {
	interval float64
	prev     map[int]Bytes
	spark    map[string][]uint64

	runNettop func() []byte
	runLsof   func() []byte
	procs     func() map[int]*collect.Proc
	trustOf   func(path string) string
	capsOf    func(path string) []string
}

func New(interval float64) *Monitor {
	return &Monitor{
		interval:  interval,
		prev:      map[int]Bytes{},
		spark:     map[string][]uint64{},
		runNettop: func() []byte { b, _ := exec.Command("nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out").Output(); return b },
		runLsof:   func() []byte { b, _ := exec.Command("lsof", "-i", "-nP").Output(); return b },
		procs:     defaultProcs,
		trustOf:   defaultTrust,
		capsOf:    defaultCaps,
	}
}

// Sample runs one observation tick and returns the current aggregated, scored groups.
func (m *Monitor) Sample() []model.EgressGroup {
	cur := ParseNettop(m.runNettop())
	conns := ParseLsofConns(m.runLsof())
	procs := m.procs()

	insts := make([]Instance, 0, len(conns))
	activeKeys := map[string]bool{}
	for pid, cs := range conns {
		p := procs[pid]
		path, app := binaryPath(p), displayName(p, pid)
		key := path
		if key == "" {
			key = app
		}
		rate := RateOut(m.prev[pid], cur[pid], m.interval)
		insts = append(insts, Instance{
			PID: pid, App: app, Path: path, Ancestry: collect.Ancestry(procs, pid),
			Trust: m.trustOf(path), OutRate: rate, OutTotal: cur[pid].Out, InRate: 0,
			Conns: cs, Capabilities: m.capsOf(path),
		})
		activeKeys[key] = true
	}
	// Advance per-app spark ring buffers from this tick's summed rate.
	summed := map[string]uint64{}
	for _, in := range insts {
		k := in.Path
		if k == "" {
			k = in.App
		}
		summed[k] += in.OutRate
	}
	for k, r := range summed {
		s := append(m.spark[k], r)
		if len(s) > sparkLen {
			s = s[len(s)-sparkLen:]
		}
		m.spark[k] = s
	}
	m.prev = cur

	groups := Aggregate(insts, m.spark)
	for i := range groups {
		groups[i].Concern = Concern(groups[i])
		groups[i].ExfilRisk, groups[i].Candidate = Exfil(groups[i])
	}
	return groups
}

func binaryPath(p *collect.Proc) string {
	if p == nil {
		return ""
	}
	return firstToken(p.Cmd)
}

func displayName(p *collect.Proc, pid int) string {
	if p == nil {
		return "pid:" + itoa(pid)
	}
	return filepath.Base(firstToken(p.Cmd))
}

func firstToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}

// defaultProcs/defaultTrust/defaultCaps are the real joins, kept tiny so Sample stays the
// orchestrator. defaultTrust maps a binary's codesign state; defaultCaps maps TCC grants.
func defaultProcs() map[int]*collect.Proc {
	b, _ := exec.Command("ps", "-axo", "pid,ppid,user,command").Output()
	return collect.ParsePs(b)
}

func defaultTrust(path string) string {
	if path == "" {
		return "unknown"
	}
	for _, e := range collect.CollectCodesign(path) {
		switch e.Facts["signed"] {
		case "false":
			return "unsigned"
		case "revoked":
			return "revoked"
		case "true":
			if e.Facts["authority"] != "" {
				if isAppleAuthority(e.Facts["authority"]) {
					return "apple"
				}
				return "notarized"
			}
			return "signed"
		}
	}
	return "unknown"
}

func isAppleAuthority(a string) bool {
	return a == "Software Signing" || a == "Apple Mac OS Application Signing"
}

// defaultCaps reads TCC grants once and maps the sensitive services to capability names,
// matching a grant to a binary path by prefix (the TCC client is a bundle/binary path).
var tccServiceCap = map[string]string{
	"kTCCServiceAccessibility":        "keystrokes",
	"kTCCServiceListenEvent":          "keystrokes",
	"kTCCServiceScreenCapture":        "screen",
	"kTCCServiceSystemPolicyAllFiles": "full-disk",
}

func defaultCaps(path string) []string {
	if path == "" {
		return nil
	}
	ev, _ := collect.CollectTCC()
	seen := map[string]bool{}
	var out []string
	for _, e := range ev {
		if cap, ok := tccServiceCap[e.Facts["service"]]; ok && pathMatchesClient(path, e.Subject.Path) && !seen[cap] {
			seen[cap] = true
			out = append(out, cap)
		}
	}
	return out
}

// pathMatchesClient links a running binary path to a TCC client path (a bundle path): the
// binary lives inside the bundle, or they share a base name.
func pathMatchesClient(binary, client string) bool {
	if client == "" || binary == "" {
		return false
	}
	return filepath.HasPrefix(binary, client) ||
		filepath.Base(binary) == filepath.Base(client)
}
```

> Note: `filepath.HasPrefix` is deprecated but adequate here; if the reviewer prefers, use `strings.HasPrefix(binary, client)` with a `strings` import. Keep whichever compiles cleanly and delete the unused import.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/egress/ -run TestMonitor && go test ./internal/egress/`
Expected: PASS (whole package).

- [ ] **Step 5: Commit**

```bash
git add internal/egress/monitor.go internal/egress/monitor_test.go
git commit -m "feat(egress): Monitor orchestrator — exec edge, joins, per-tick scored groups"
```

---

### Task 8: non-TTY egress report + JSON

**Files:**
- Create: `internal/report/egress.go`
- Test: `internal/report/egress_test.go`

**Interfaces:**
- Consumes: `model.EgressGroup`.
- Produces: `func RenderEgress(groups []model.EgressGroup, color bool) string`; `func RenderEgressJSON(groups []model.EgressGroup) ([]byte, error)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/report/egress_test.go
package report

import (
	"strings"
	"testing"

	"counterspy/internal/model"
)

func TestRenderEgress_ShowsConcernAndExfil(t *testing.T) {
	groups := []model.EgressGroup{{
		App: "backuptool", Trust: "unsigned", Instances: 2, OutRate: 840_000, Background: true,
		Destinations: []model.Endpoint{{IP: "198.51.100.7", Port: 443}},
		Capabilities: []string{"screen", "keystrokes"},
		Concern:      model.Elevated, ExfilRisk: model.Elevated, Candidate: []string{"screen", "keystrokes"},
	}}
	out := RenderEgress(groups, false)
	for _, want := range []string{"backuptool", "unsigned", "elevated", "screen", "keystrokes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q:\n%s", want, out)
		}
	}
}

func TestRenderEgressJSON(t *testing.T) {
	b, err := RenderEgressJSON([]model.EgressGroup{{App: "x", Concern: model.Low}})
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		t.Fatalf("json: %v %s", err, b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -run TestRenderEgress`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/report/egress.go
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"counterspy/internal/model"
)

// RenderEgressJSON emits the machine-readable per-app egress form.
func RenderEgressJSON(groups []model.EgressGroup) ([]byte, error) {
	return json.MarshalIndent(groups, "", "  ")
}

// RenderEgress prints a per-app egress report: one block per app with rate, trust,
// destinations, cadence, capabilities, and the inferred exfil risk + candidates.
func RenderEgress(groups []model.EgressGroup, color bool) string {
	p := pen{color}
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s  %s\n", p.s(sBold+sMint, "CounterSpy"), p.s(sDim, "egress observation"))
	for _, g := range groups {
		style := sGray
		switch g.Concern {
		case model.Elevated:
			style = sRed
		case model.Notable:
			style = sAmber
		}
		fmt.Fprintf(&b, "\n  %s  %s  %s\n",
			p.s(style, g.Concern.String()+" "+Clean(g.App)),
			p.s(sDim, fmt.Sprintf("%s · %s · out %s/s", g.Trust, backgroundLabel(g.Background), humanBytes(g.OutRate))),
			p.s(sDim, fmt.Sprintf("%d instance(s) · %s", g.Instances, g.Cadence)))
		if len(g.Destinations) > 0 {
			fmt.Fprintf(&b, "     %s %s\n", p.s(sDim, "→"), Clean(destList(g.Destinations)))
		}
		if len(g.Capabilities) > 0 {
			fmt.Fprintf(&b, "     %s %s — %s %s %s\n", p.s(sDim, "can access"), strings.Join(g.Capabilities, ", "),
				p.s(style, "exfil "+g.ExfilRisk.String()), p.s(sDim, "candidate:"), strings.Join(g.Candidate, ", "))
		}
	}
	return b.String()
}

func backgroundLabel(bg bool) string {
	if bg {
		return "background"
	}
	return "foreground"
}

func destList(dests []model.Endpoint) string {
	parts := make([]string, 0, len(dests))
	for i, d := range dests {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d", len(dests)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("%s:%d", d.IP, d.Port))
	}
	return strings.Join(parts, "  ")
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
```

(`pen`, `sBold`, `sMint`, `sDim`, `sRed`, `sAmber`, `sGray`, `Clean` already exist in `internal/report/report.go` — reuse them.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/report/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report/egress.go internal/report/egress_test.go
git commit -m "feat(report): non-TTY egress report + JSON"
```

---

### Task 9: TUI egress model + update (pure)

**Files:**
- Create: `internal/tui/egressmodel.go`
- Test: `internal/tui/egressmodel_test.go`

**Interfaces:**
- Consumes: `model.EgressGroup`.
- Produces: `type EgressModel struct{...}`; `func NewEgress() EgressModel`; `func (m EgressModel) withGroups([]model.EgressGroup) EgressModel`; `func egressUpdate(EgressModel, tcell.Key, rune) (EgressModel, bool)` (bool = quit); `func (m EgressModel) visibleRows() []egressRow`.

- [ ] **Step 1: Write the failing test**

```go
// internal/tui/egressmodel_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func eg(app string, c model.ConcernLevel, rate uint64) model.EgressGroup {
	return model.EgressGroup{App: app, Path: "/x/" + app, Concern: c, OutRate: rate,
		Conns: []model.Conn{{Endpoint: model.Endpoint{IP: "1.2.3.4", Port: 443}, Proto: "tcp"}}}
}

func TestEgressUpdate_QuitAndPause(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Low, 10)})
	if _, quit := egressUpdate(m, tcell.KeyRune, 'Q'); !quit {
		t.Fatal("Q should quit")
	}
	m2, _ := egressUpdate(m, tcell.KeyRune, 'p')
	if !m2.Paused {
		t.Fatal("p should toggle pause")
	}
}

func TestEgressUpdate_ExpandCollapseAddsChildRows(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("a", model.Elevated, 900)})
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("collapsed = %d rows, want 1", n)
	}
	m, _ = egressUpdate(m, tcell.KeyEnter, 0) // expand selected
	if n := len(m.visibleRows()); n != 2 {   // group + its 1 conn
		t.Fatalf("expanded = %d rows, want 2", n)
	}
	m, _ = egressUpdate(m, tcell.KeyLeft, 0) // collapse
	if n := len(m.visibleRows()); n != 1 {
		t.Fatalf("re-collapsed = %d rows, want 1", n)
	}
}

func TestEgressUpdate_SortByConcern(t *testing.T) {
	m := NewEgress().withGroups([]model.EgressGroup{eg("low", model.Low, 999), eg("elev", model.Elevated, 1)})
	m.Sort = sortConcern
	rows := m.visibleRows()
	if rows[0].group.App != "elev" {
		t.Fatalf("sort by concern should put elevated first, got %s", rows[0].group.App)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestEgress`
Expected: FAIL — undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/tui/egressmodel.go
package tui

import (
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type egressSort int

const (
	sortRate egressSort = iota
	sortConcern
	sortExfil
	sortApp
)

// egressRow is one rendered line: a group header, or (when expanded) one of its conns.
type egressRow struct {
	group model.EgressGroup
	conn  *model.Conn // nil = the group header row; non-nil = a child connection row
}

// EgressModel is the pure state of the live egress view.
type EgressModel struct {
	Groups   []model.EgressGroup
	Selected int
	Sort     egressSort
	Filter   string
	Paused   bool
	expanded map[string]bool // group key (App) → expanded
}

func NewEgress() EgressModel { return EgressModel{expanded: map[string]bool{}} }

// withGroups returns a copy with fresh data (called each tick). Selection/expanded/sort
// are preserved.
func (m EgressModel) withGroups(gs []model.EgressGroup) EgressModel {
	m.Groups = gs
	if m.Selected >= len(m.orderedGroups()) {
		m.Selected = 0
	}
	return m
}

func (m EgressModel) orderedGroups() []model.EgressGroup {
	out := make([]model.EgressGroup, 0, len(m.Groups))
	for _, g := range m.Groups {
		if m.Filter == "" || strings.Contains(strings.ToLower(g.App), strings.ToLower(m.Filter)) {
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		switch m.Sort {
		case sortConcern:
			return out[i].Concern > out[j].Concern
		case sortExfil:
			return out[i].ExfilRisk > out[j].ExfilRisk
		case sortApp:
			return out[i].App < out[j].App
		default:
			return out[i].OutRate > out[j].OutRate
		}
	})
	return out
}

// visibleRows expands the ordered groups: each group header, followed by its conns when the
// group is expanded.
func (m EgressModel) visibleRows() []egressRow {
	var rows []egressRow
	for _, g := range m.orderedGroups() {
		g := g
		rows = append(rows, egressRow{group: g})
		if m.expanded[g.App] {
			for i := range g.Conns {
				rows = append(rows, egressRow{group: g, conn: &g.Conns[i]})
			}
		}
	}
	return rows
}

// egressUpdate is the pure transition. Returns (model, quit).
func egressUpdate(m EgressModel, key tcell.Key, r rune) (EgressModel, bool) {
	if key == tcell.KeyCtrlC {
		return m, true
	}
	groups := m.orderedGroups()
	switch key {
	case tcell.KeyDown:
		m.Selected = clamp(m.Selected+1, len(groups))
	case tcell.KeyUp:
		m.Selected = clamp(m.Selected-1, len(groups))
	case tcell.KeyEnter, tcell.KeyRight:
		if m.Selected < len(groups) {
			m.expanded = cloneSet(m.expanded)
			m.expanded[groups[m.Selected].App] = true
		}
	case tcell.KeyLeft:
		if m.Selected < len(groups) {
			m.expanded = cloneSet(m.expanded)
			delete(m.expanded, groups[m.Selected].App)
		}
	case tcell.KeyRune:
		switch r {
		case 'j':
			m.Selected = clamp(m.Selected+1, len(groups))
		case 'k':
			m.Selected = clamp(m.Selected-1, len(groups))
		case 's':
			m.Sort = (m.Sort + 1) % 4
		case 'p':
			m.Paused = !m.Paused
		case 'Q':
			return m, true
		}
	}
	return m, false
}

func clamp(i, n int) int {
	if n == 0 || i < 0 {
		return 0
	}
	if i > n-1 {
		return n - 1
	}
	return i
}

func cloneSet(s map[string]bool) map[string]bool {
	n := make(map[string]bool, len(s)+1)
	for k, v := range s {
		n[k] = v
	}
	return n
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tui/ -run TestEgress && go test ./internal/tui/ -run TestDecouplingInvariant`
Expected: PASS (both; the invariant holds — this file imports only tcell + model).

- [ ] **Step 5: Commit**

```bash
git add internal/tui/egressmodel.go internal/tui/egressmodel_test.go
git commit -m "feat(tui): pure egress model + update (nav/sort/filter/expand/pause)"
```

---

### Task 10: TUI egress view + run (tick loop)

**Files:**
- Create: `internal/tui/egressview.go`, `internal/tui/egressrun.go`
- Test: `internal/tui/egressrun_test.go`

**Interfaces:**
- Consumes: `EgressModel`, `egressUpdate`, `model.EgressGroup`.
- Produces: `type Sampler interface { Sample() []model.EgressGroup }`; `func RunEgress(s tcell.Screen, sampler Sampler, tick <-chan struct{}) error`; `func egressView(EgressModel, tcell.Screen)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/tui/egressrun_test.go
package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

type fakeSampler struct{ groups []model.EgressGroup }

func (f fakeSampler) Sample() []model.EgressGroup { return f.groups }

func TestRunEgress_RendersAndQuits(t *testing.T) {
	s := tcell.NewSimulationScreen("")
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	tick := make(chan struct{}, 1)
	tick <- struct{}{} // one sample
	s.InjectKey(tcell.KeyRune, 'Q', tcell.ModNone)
	sampler := fakeSampler{groups: []model.EgressGroup{eg("backuptool", model.Elevated, 900)}}
	if err := RunEgress(s, sampler, tick); err != nil {
		t.Fatal(err)
	}
	// The screen should have drawn the app name somewhere.
	if !simContains(s, "backuptool") {
		t.Fatal("expected 'backuptool' on screen")
	}
}

func simContains(s tcell.SimulationScreen, want string) bool {
	cells, w, h := s.GetContents()
	var b []rune
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			b = append(b, cells[y*w+x].Runes...)
		}
	}
	return len(b) > 0 && contains(string(b), want)
}

func contains(hay, needle string) bool { return len(hay) >= len(needle) && (indexOf(hay, needle) >= 0) }
func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tui/ -run TestRunEgress`
Expected: FAIL — undefined.

- [ ] **Step 3: Write the view**

```go
// internal/tui/egressview.go
package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

func concernColor(c model.ConcernLevel) tcell.Color {
	switch c {
	case model.Elevated:
		return colQuarantine
	case model.Notable:
		return colInvestigate
	case model.Low:
		return colMonitor
	default:
		return colDim
	}
}

var sparkGlyphs = []rune("▁▂▃▄▅▆▇█")

func sparkline(vals []uint64) string {
	if len(vals) == 0 {
		return ""
	}
	var max uint64
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		idx := 0
		if max > 0 {
			idx = int(v * uint64(len(sparkGlyphs)-1) / max)
		}
		b.WriteRune(sparkGlyphs[idx])
	}
	return b.String()
}

// egressView renders the full-width top table + detail strip.
func egressView(m EgressModel, s tcell.Screen) {
	s.Clear()
	w, h := s.Size()
	if w < 24 || h < 6 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	drawText(s, 2, 0, tcell.StyleDefault.Foreground(colAccent).Bold(true), "CounterSpy · Egress")
	status := "sampling · p pause · Q quit"
	if m.Paused {
		status = "PAUSED · p resume · Q quit"
	}
	drawText(s, w-len(status)-2, 0, tcell.StyleDefault.Foreground(colDim), status)
	drawText(s, 2, 1, tcell.StyleDefault.Foreground(colDim),
		fmt.Sprintf("%-18s %-10s %-9s %-8s %-26s %s", "APP / PROCESS", "TRUST", "OUT↑", "RATE", "TOP DESTINATION", "CONCERN"))

	rows := m.visibleRows()
	y := 2
	for i, row := range rows {
		if y >= h-6 {
			break
		}
		st := tcell.StyleDefault.Foreground(model.Clean != nil && false && true || true, colText).(tcell.Style) // placeholder guard removed below
		_ = st
		if row.conn != nil {
			line := fmt.Sprintf("    %-14s %s %s:%d  %s/s", "pid "+itoa(row.conn.PID), row.conn.Proto,
				row.conn.Endpoint.IP, row.conn.Endpoint.Port, human(row.conn.OutRate))
			drawText(s, 2, y, tcell.StyleDefault.Foreground(colDim), model.Clean(line))
			y++
			continue
		}
		g := row.group
		marker := "▸"
		if m.expanded[g.App] {
			marker = "▾"
		}
		style := tcell.StyleDefault.Foreground(concernColor(g.Concern))
		if i == selectedRowIndex(m, rows) {
			style = style.Background(colSelBg)
		}
		line := fmt.Sprintf("%s %-16s %-10s %-9s %-8s %-26s %s",
			marker, trunc(g.App, 16), g.Trust, human(g.OutRate)+"/s", sparkline(g.Spark),
			trunc(topDest(g), 26), g.Concern.String())
		drawText(s, 2, y, style, model.Clean(line))
		y++
	}
	drawEgressDetail(m, s, h)
}

func selectedRowIndex(m EgressModel, rows []egressRow) int {
	groups := m.orderedGroups()
	if m.Selected >= len(groups) {
		return -1
	}
	sel := groups[m.Selected].App
	for i, r := range rows {
		if r.conn == nil && r.group.App == sel {
			return i
		}
	}
	return -1
}

func drawEgressDetail(m EgressModel, s tcell.Screen, h int) {
	groups := m.orderedGroups()
	if m.Selected >= len(groups) {
		return
	}
	g := groups[m.Selected]
	base := h - 6
	col := concernColor(g.Concern)
	drawText(s, 2, base, tcell.StyleDefault.Foreground(colDim),
		model.Clean(fmt.Sprintf("DETAIL — %s · %d instance(s) · %d conn(s)", g.App, g.Instances, len(g.Conns))))
	drawText(s, 2, base+1, tcell.StyleDefault.Foreground(colDim), model.Clean(g.Ancestry))
	drawText(s, 2, base+2, tcell.StyleDefault.Foreground(col),
		model.Clean(fmt.Sprintf("%s · %s · cadence: %s", g.Trust, bgLabel(g.Background), g.Cadence)))
	if len(g.Capabilities) > 0 {
		drawText(s, 2, base+3, tcell.StyleDefault.Foreground(colDim),
			model.Clean("can access  "+strings.Join(g.Capabilities, " · ")))
		drawText(s, 2, base+4, tcell.StyleDefault.Foreground(col),
			model.Clean(fmt.Sprintf("exfil %s — candidate: %s (inferred from capability)",
				g.ExfilRisk.String(), strings.Join(g.Candidate, ", "))))
	}
}

func bgLabel(bg bool) string {
	if bg {
		return "background daemon"
	}
	return "foreground app"
}

func topDest(g model.EgressGroup) string {
	if len(g.Destinations) == 0 {
		return "—"
	}
	d := g.Destinations[0]
	extra := ""
	if len(g.Destinations) > 1 {
		extra = fmt.Sprintf(" +%d", len(g.Destinations)-1)
	}
	return fmt.Sprintf("%s:%d%s", d.IP, d.Port, extra)
}

func human(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
```

> The `st := ... placeholder guard ...` line above is a deliberate NON-compiling marker to force you to delete it — remove that one line entirely (it exists only to stop a copy-paste-and-ship). `drawText`, `trunc`, and the `col*` palette already exist in `internal/tui/view.go`/`model.go`; reuse them.

- [ ] **Step 4: Write the run loop**

```go
// internal/tui/egressrun.go
package tui

import (
	"github.com/gdamore/tcell/v2"

	"counterspy/internal/model"
)

// Sampler yields the current aggregated egress groups (satisfied by internal/egress.Monitor
// via a main adapter).
type Sampler interface {
	Sample() []model.EgressGroup
}

// RunEgress drives the live loop. Each receive on `tick` triggers a sample (unless paused);
// key events drive the pure egressUpdate. Screen is injected for tests; the caller
// Inits/Finis it. The caller closes `tick` (or lets the process exit) to stop.
func RunEgress(s tcell.Screen, sampler Sampler, tick <-chan struct{}) error {
	m := NewEgress()
	// Post tick signals as screen events so a single event loop serializes samples + keys.
	go func() {
		for range tick {
			s.PostEvent(tcell.NewEventInterrupt(nil))
		}
	}()
	m = m.withGroups(sampler.Sample())
	egressView(m, s)
	s.Show()
	for {
		switch ev := s.PollEvent().(type) {
		case *tcell.EventKey:
			next, quit := egressUpdate(m, ev.Key(), ev.Rune())
			m = next
			if quit {
				return nil
			}
		case *tcell.EventInterrupt:
			if !m.Paused {
				m = m.withGroups(sampler.Sample())
			}
		case nil:
			return nil // screen finished
		}
		egressView(m, s)
		s.Show()
	}
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/tui/`
Expected: PASS (incl. `TestRunEgress`, `TestDecouplingInvariant`, and existing scan-TUI tests). Fix any compile error from the two deliberate delete-me markers (Task 5 dead loop, Task 10 placeholder line).

- [ ] **Step 6: Commit**

```bash
git add internal/tui/egressview.go internal/tui/egressrun.go internal/tui/egressrun_test.go
git commit -m "feat(tui): live egress view + tick-driven run loop"
```

---

### Task 11: main wiring — `egress` subcommand

**Files:**
- Modify: `main.go` (dispatch + `runEgress` + usage)
- Test: `main_test.go`

**Interfaces:**
- Consumes: `egress.New`, `report.RenderEgress`/`RenderEgressJSON`, `tui.RunEgress`, `tui.Sampler`.
- Produces: `func runEgress(flags []string, stdout io.Writer) int`.

- [ ] **Step 1: Write the failing test**

```go
// add to main_test.go
func TestRunEgress_JSONReport(t *testing.T) {
	// Non-TTY (test) → report path; --json emits an array. --once avoids the live loop.
	var buf bytes.Buffer
	if code := runEgress([]string{"--json", "--once"}, &buf); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Fatalf("expected JSON array, got: %s", buf.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestRunEgress_JSON`
Expected: FAIL — `undefined: runEgress`.

- [ ] **Step 3: Write minimal implementation**

Add `"counterspy/internal/egress"` to `main.go` imports. Add the dispatch case in `run()` after the `feedback` case:

```go
	case "egress":
		return runEgress(args[1:], stdout)
```

Add:

```go
// runEgress observes per-app outbound traffic. On a TTY it launches the live "egress top"
// TUI; piped/redirected (or with --once) it prints a one-shot report (or --json).
func runEgress(flags []string, stdout io.Writer) int {
	asJSON := has(flags, "--json")
	once := has(flags, "--once")
	interval := 2.0
	mon := egress.New(interval)

	fi, _ := os.Stdout.Stat()
	isTTY := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	if once || asJSON || !isTTY {
		mon.Sample()               // establish a baseline
		groups := mon.Sample()     // second sample carries rates
		if asJSON {
			b, err := report.RenderEgressJSON(groups)
			if err != nil {
				fmt.Fprintln(os.Stderr, "render:", err)
				return 1
			}
			fmt.Fprintln(stdout, string(b))
			return 0
		}
		fmt.Fprint(stdout, report.RenderEgress(groups, colorEnabled()))
		return 0
	}
	return runEgressTUI(mon, interval, stdout)
}
```

Add the TUI driver (mirrors `runTUI`'s screen/signal/fini handling):

```go
func runEgressTUI(mon *egress.Monitor, interval float64, stdout io.Writer) (code int) {
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Fprintln(stdout, "egress: cannot open screen:", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		fmt.Fprintln(stdout, "egress: cannot init screen:", err)
		return 1
	}
	var finiOnce sync.Once
	fini := func() { finiOnce.Do(func() { screen.Fini() }) }
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() { <-sigCh; fini(); os.Exit(130) }()
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "egress: internal error: %v\n%s\n", r, debug.Stack())
			code = 1
		}
	}()
	defer fini()

	tick := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Duration(interval * float64(time.Second)))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case tick <- struct{}{}:
				default:
				}
			case <-stop:
				return
			}
		}
	}()
	err = tui.RunEgress(screen, mon, tick)
	close(stop)
	fini()
	if err != nil {
		fmt.Fprintln(stdout, "egress:", err)
		return 1
	}
	return 0
}
```

Update the usage string in `run()` to mention `egress`. Ensure `time`, `sync`, `os/signal`, `syscall`, `runtime/debug`, `github.com/gdamore/tcell/v2` are imported (most already are from `runTUI`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test . -run TestRunEgress_JSON && go build ./... && go test ./...`
Expected: PASS across all packages; build clean.

- [ ] **Step 5: Commit**

```bash
git add main.go main_test.go
git commit -m "feat(main): egress subcommand — live TUI on a tty, report/--json otherwise"
```

---

### Task 12: docs, architext, Release Truth, tag

**Files:**
- Modify: `README.md` (egress section)
- Modify: `docs/architext/data/nodes.json` (add `mod-egress`; wire into `counterspy-cli` deps)
- Modify: `docs/architext/data/roadmap.json` (mark the egress-monitor item in-development)
- Create: `docs/architext/data/releases/v0-4-0-egress.json`; modify `releases/index.json`

- [ ] **Step 1: README section**

Add an "Egress monitor" section to `README.md`: `counterspy egress` launches a live per-app outbound "top" (rate, destinations, cadence) with concern coloring and an *inferred* exfiltration risk (capability × egress — candidates, never payloads); non-TTY prints a report / `--json`. Note it's observe-only and reads no payloads.

- [ ] **Step 2: architext `mod-egress` node**

Add a node (source-backed from `internal/egress`) and add `"mod-egress"` to `counterspy-cli`'s `dependencies`:

```jsonc
{
  "id": "mod-egress",
  "type": "module",
  "name": "internal/egress",
  "summary": "Sudo-CLI egress observation: polls nettop + lsof per tick, joins provenance/codesign-trust/TCC-capability from internal/collect, aggregates by application (collapsing pids/ports/protocols), and scores concern + exfiltration-risk (capability × egress). Pure given inputs; the exec edge is isolated in monitor.go. Observe-only; reads no payloads.",
  "responsibilities": ["Parse nettop/lsof; diff to out-rates; classify cadence", "Group by app; infer exfil risk + candidate categories", "Feed the live TUI + non-TTY report"],
  "owner": "Project maintainers",
  "sourcePaths": ["internal/egress/parse.go", "internal/egress/rate.go", "internal/egress/aggregate.go", "internal/egress/concern.go", "internal/egress/monitor.go"],
  "runtime": "in-process + exec (nettop/lsof/ps/codesign/sqlite3)",
  "interfaces": ["New", "Monitor.Sample", "Concern", "Exfil"],
  "dependencies": ["mod-model", "mod-collect", "macos-tools"],
  "dataHandled": ["process-list", "code-signatures", "tcc-grants"],
  "security": ["Observe-only; no blocking, no payload reading", "Exfil is INFERRED from capability, never confirmed content"],
  "observability": ["live TUI", "egress report / --json"],
  "relatedFlows": ["scan-pipeline"],
  "relatedDecisions": [],
  "knownRisks": [],
  "verification": ["go test ./internal/egress/"]
}
```

- [ ] **Step 3: roadmap + Release Truth**

In `roadmap.json`, set the `roadmap-egress-monitor` item `status` to `"in-progress"`. Create `docs/architext/data/releases/v0-4-0-egress.json` (mirror `v0-3-0-feedback.json` shape: workstream "egress", the parsers/aggregate/concern/exfil/TUI as complete items) and update `releases/index.json` (`currentReleaseId` → `v0-4-0-egress`). Then run `architext doctor --yes` to regenerate the index history and `architext validate`.

- [ ] **Step 4: Full gate + tag**

Run:
```bash
gofmt -l $(git ls-files '*.go' | grep -v '^vendor/')
go vet ./... && go test ./...
architext validate
```
Expected: fmt clean, vet clean, all tests PASS, architext valid.

```bash
git add README.md docs/
git commit -m "docs(v0.4.0): egress README, mod-egress node, roadmap in-progress, Release Truth"
git tag -a v0.4.0-rc1 -m "CounterSpy v0.4.0-rc1 — egress monitor"
```

---

## Self-Review

**Spec coverage:**
- Mechanism (nettop+lsof, no entitlements) → Tasks 3, 7. ✓
- Operating model (TTY→TUI, non-TTY→report/--json) → Task 11. ✓
- Data pipeline (parse → rate → group-by-app → concern → exfil) → Tasks 3–7. ✓
- Types (Endpoint/Conn/EgressGroup/ConcernLevel) → Task 1. ✓
- Concern heuristic + Background rule → Task 6 (`Concern`, `isBackground` in Task 5). ✓
- Exfil inference (capability × egress, candidates) → Task 6, capability join Task 7. ✓
- Live TUI (full-width table, concern tint, sparkline, expand/collapse, detail strip) → Tasks 9, 10. ✓
- Aggregate/collapse by app → Task 5 + Task 9 expand. ✓
- Cadence (session-window) → Task 4. ✓
- Reuse collect (proctree/codesign/TCC) → Task 2 (Ancestry), Task 7 joins. ✓
- Destination naming limit (IP:port) → report Task 8, view Task 10 (`topDest`). ✓
- Roadmap (pcap v0.4.1, payload inspection) → already in `roadmap.json`; Task 12 marks egress in-progress. ✓
- Testing (parsers/rate/cadence/aggregate/concern/exfil/TUI/report) → each task is TDD. ✓

**Placeholder scan:** Two intentional delete-me markers are called out explicitly (Task 5 dead `for` loop; Task 10 `st := ...` non-compiling line) so the implementer removes them — flagged, not hidden. No TBD/TODO. The nettop/lsof fixtures are representative with an explicit "capture real output first" instruction (exec-output parsing is inherently fixture-driven).

**Type consistency:** `EgressGroup`/`Conn`/`Endpoint`/`ConcernLevel` (Task 1) are used verbatim in 5–11. `Bytes` (Task 3) used in 4, 7. `Instance` (Task 5) produced in 7. `RateOut`/`Cadence` (Task 4) used in 5, 7. `Concern`/`Exfil` (Task 6) used in 7. `Monitor.Sample` (Task 7) satisfies `tui.Sampler` (Task 10) via the main adapter (Task 11). `egressUpdate`/`EgressModel`/`egressView`/`RunEgress` consistent across 9–11.
