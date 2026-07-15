# Phase 1 — Passive reveal: destination names + cleartext extraction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In the Exfiltration views, show the hostname an app actually resolved (via passive DNS) instead of a bare IP, gently raise concern for corroborated raw-IP contact, and deeply decode cleartext content for a flow the user inspects.

**Architecture:** A long-lived passive DNS capture (reusing a filter-generalized `/dev/bpf`) feeds a mutex-guarded IP→name cache exposed as a `netname.Resolver`. The egress `Monitor` annotates each `Endpoint.Name` from the resolver at sample time; `concern.go` treats a nameless endpoint as "raw IP" in the existing corroboration-gated bump. The on-demand inspector gains a structured cleartext decoder. The TUI renders `name (ip)` and the decoded structure; it still imports only `model` + `mark`.

**Tech Stack:** Go 1.26, macOS `/dev/bpf` (cgo build), `golang.org/x/net/bpf` (vendored), tcell TUI. No third-party deps beyond what's vendored.

## Global Constraints

- **No new CLI flags/options** without explicit maintainer approval. Phase 1 adds **none** — the DNS observer starts inside the existing `console` command; deep decode is the existing `i` key.
- **TUI decoupling invariant:** `internal/tui` imports ONLY `internal/model` + `internal/mark` (enforced by `TestDecouplingInvariant`). Names/decoded content reach the TUI as data on the model, never via a new import.
- **cgo required** for the darwin build (codesign path); capture is darwin-only behind the existing build tags.
- **Honesty (Rule 13):** never fabricate a name; a missing name shows the IP. A capture that can't start surfaces a stated gap, never a crash or a silent "clean".
- **Every package ≥80% coverage** (CI-gated). `gofmt`, `go vet`, `go test ./...` (incl. `-race` on `netname`) green. `architext validate` passes.
- **Gitflow:** feature branch `feat/egress-names` → develop → (release cut later). Commit per task.

---

## File Structure

- `internal/model/egress.go` — **modify**: add `Name string` to `Endpoint`.
- `internal/inspect/filter.go` — **modify**: add `buildPortFilter(linkHdrLen, port)` beside `buildFlowFilter`.
- `internal/inspect/bpf_darwin.go` — **modify**: add `OpenPortCapture(iface, port)` (long-lived, no deadline) reusing the open/bind/dlt/nonblock path.
- `internal/inspect/capture.go` — unchanged (`PacketSource` reused by the observer).
- `internal/netname/dns.go` — **create**: `ParseDNSResponse([]byte) ([]Record, bool)`.
- `internal/netname/cache.go` — **create**: `Cache` (bounded reverse map) implementing `Resolver`.
- `internal/netname/observer.go` — **create**: `Observer` long-lived loop feeding the cache; `iface` discovery.
- `internal/netname/resolver.go` — **create**: `Resolver` interface.
- `internal/egress/monitor.go` — **modify**: `resolve` field + `SetResolver`; annotate `Endpoint.Name` in `Sample`.
- `internal/egress/concern.go` — **modify**: `allRawIP` keys on `Endpoint.Name == ""`.
- `internal/inspect/cleartext.go` — **create**: `DecodeCleartext([]byte) Content` (structured HTTP + masking).
- `internal/inspect/inspect.go` — **modify**: attach decoded `Content` to `Result`.
- `internal/tui/egressview.go`, `egresszoom.go`, `inspect.go` — **modify**: render `name (ip)` + decoded structure.
- `main.go` — **modify**: build the observer, `SetResolver` on the monitor, start on console open / stop on exit (no flag).

---

## Task 1: `Endpoint.Name` on the model

**Files:** Modify `internal/model/egress.go`; Test `internal/model/egress_test.go` (create if absent).

**Interfaces:** Produces: `model.Endpoint{IP string; Port int; Name string}`.

- [ ] **Step 1: Write the failing test**
```go
func TestEndpoint_NameField(t *testing.T) {
	e := Endpoint{IP: "1.2.3.4", Port: 443, Name: "example.com"}
	if e.Name != "example.com" {
		t.Fatalf("Name not carried: %+v", e)
	}
}
```
- [ ] **Step 2: Run — expect compile failure** (`unknown field Name`). `go test ./internal/model/`
- [ ] **Step 3: Add the field**
```go
type Endpoint struct {
	IP   string
	Port int
	Name string // hostname the app resolved for this IP (passive DNS); "" = unresolved (#3)
}
```
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Commit** — `feat(model): Endpoint.Name for resolved destination hostnames (#3)`

## Task 2: port-scoped BPF filter

**Files:** Modify `internal/inspect/filter.go`; Test `internal/inspect/filter_test.go`.

**Interfaces:** Consumes: `buildFlowFilter(linkHdrLen int, remote netip.AddrPort)` pattern. Produces: `buildPortFilter(linkHdrLen, port int) ([]bpf.RawInstruction, error)` — matches IPv4/IPv6 UDP-or-TCP where src or dst port == port.

- [ ] **Step 1: Write the failing test** — assemble the filter and run it through `bpf.NewVM` against a hand-built UDP/53 IP packet (mirror the existing `buildFlowFilter` VM test in `filter_test.go`), asserting a DNS-response packet passes and an unrelated TCP/443 packet is dropped.
```go
func TestBuildPortFilter_MatchesDNS(t *testing.T) {
	prog, err := buildPortFilter(14 /*EN10MB*/, 53)
	if err != nil { t.Fatal(err) }
	vm, err := bpf.NewVM(rawToInstr(prog)); if err != nil { t.Fatal(err) }
	if n, _ := vm.Run(udp53Packet()); n == 0 { t.Fatal("DNS packet must pass the filter") }
	if n, _ := vm.Run(tcp443Packet()); n != 0 { t.Fatal("non-53 packet must be dropped") }
}
```
- [ ] **Step 2: Run — FAIL** (`undefined: buildPortFilter`).
- [ ] **Step 3: Implement `buildPortFilter`** — same structure as `buildFlowFilter` but the leaf comparison is `src port == p OR dst port == p` over UDP(17)/TCP(6), for both EtherType IPv4 (0x0800) and IPv6 (0x86DD). Reuse the link-header offset like `buildFlowFilter`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(inspect): port-scoped BPF filter builder (#3)`

## Task 3: long-lived port capture

**Files:** Modify `internal/inspect/bpf_darwin.go`; the darwin build path is exercised manually (CI has no `/dev/bpf`), so unit-test only the parts that don't need root.

**Interfaces:** Produces: `func OpenPortCapture(iface string, port int) (PacketSource, error)` — identical open/BIOCSETIF/immediate/nonblock/dlt path to `OpenLiveCapture`, installs `buildPortFilter` instead of `installFlowFilter`, and sets **no deadline** (`c.deadline` stays zero → `Next` blocks/EAGAIN-loops until `Close`).

- [ ] **Step 1: Refactor** the shared open sequence in `OpenLiveCapture` into `openBPF(iface) (fd int, dlt uint32, blen int, err error)`; have `OpenLiveCapture` call it, then install the flow filter + deadline. **Run existing `inspect` tests — expect unchanged PASS** (pure-refactor guard).
- [ ] **Step 2: Add `OpenPortCapture`** using `openBPF` + `installPortFilter(fd, dlt, port)` (a sibling of `installFlowFilter` that assembles `buildPortFilter`), no deadline.
- [ ] **Step 3: Test** the filter-install seam is best-effort (mirror how `installFlowFilter` degrades): a unit test that `installPortFilter` on an unknown dlt returns without panic (no root needed — it only assembles + would ioctl; guard the ioctl behind the dlt-known check exactly like `installFlowFilter`).
- [ ] **Step 4: Run — PASS** (`go test ./internal/inspect/`).
- [ ] **Step 5: Commit** — `feat(inspect): long-lived port-scoped /dev/bpf capture (#3)`

## Task 4: DNS response parser

**Files:** Create `internal/netname/dns.go`, `internal/netname/dns_test.go`.

**Interfaces:** Produces:
```go
type Record struct { Name string; IP netip.Addr }
// ParseDNSResponse extracts (queried-name → answer IP) pairs from a DNS message. Tolerant: returns
// ok=false on a non-response/garbage, skips answer RRs it can't parse. CNAME chains map A/AAAA IPs
// back to the ORIGINAL queried name.
func ParseDNSResponse(msg []byte) ([]Record, bool)
```

- [ ] **Step 1: Write failing tests** with hand-built DNS response fixtures (question + answers). Cover: single A, AAAA, multiple A answers, a CNAME chain (`www.x.com CNAME x.cdn.net A 1.2.3.4` → Record{Name:"www.x.com", IP:1.2.3.4}), a query (QR=0) → ok=false, truncated tail → parse what's valid.
```go
func TestParseDNSResponse_AandCNAME(t *testing.T) {
	recs, ok := ParseDNSResponse(dnsResp("www.x.com", cname("x.cdn.net"), a("x.cdn.net","1.2.3.4")))
	if !ok || len(recs) != 1 || recs[0].Name != "www.x.com" || recs[0].IP.String() != "1.2.3.4" {
		t.Fatalf("CNAME chain must map the A record to the queried name: %+v ok=%v", recs, ok)
	}
}
```
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** a minimal DNS message walker: header (check QR bit + ANCOUNT), skip QDCOUNT questions (name + 4 bytes), then read answers — decompress names (0xC0 pointer), collect CNAME (type 5) target→owner aliases and A(1)/AAAA(28) rdata, resolve each IP's owner name back through the alias map to the queried name. Bounds-check every read; on any overrun return what's collected so far with `ok=true` if the header was valid.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(netname): tolerant DNS-response parser (#3)`

## Task 5: bounded reverse cache (Resolver)

**Files:** Create `internal/netname/resolver.go`, `internal/netname/cache.go`, `internal/netname/cache_test.go`.

**Interfaces:**
```go
// resolver.go
type Resolver interface { Lookup(ip string) (name string, ok bool) }
// cache.go
type Cache struct { /* mu sync.Mutex; m map[string]string; order []string; cap int */ }
func NewCache(capacity int) *Cache
func (c *Cache) Put(ip, name string)          // last-seen-wins; evicts oldest past cap
func (c *Cache) Lookup(ip string) (string, bool) // implements Resolver
```

- [ ] **Step 1: Write failing tests**: `Put` then `Lookup` returns the name; last-seen-wins (re-Put updates); eviction past `cap` drops the oldest; `Lookup` of an unknown IP → `("", false)`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** a mutex-guarded map + insertion-order slice; on `Put` beyond `cap`, delete the front key. All methods lock.
- [ ] **Step 4: Write a race test** — N goroutines `Put` while N `Lookup`, asserting no panic/torn read. Run `go test -race ./internal/netname/`.
- [ ] **Step 5: Run — PASS (incl. `-race`).**
- [ ] **Step 6: Commit** — `feat(netname): bounded, race-safe IP→name cache + Resolver (#3)`

## Task 6: DNS observer loop

**Files:** Create `internal/netname/observer.go`, `internal/netname/observer_test.go`.

**Interfaces:** Consumes: `inspect.PacketSource` (via an injected `open func() (inspect.PacketSource, error)` so tests use a fixture source), `ParseDNSResponse`, `*Cache`. Produces:
```go
type Observer struct { /* cache *Cache; open func()(inspect.PacketSource,error); done chan struct{} */ }
func NewObserver(cache *Cache, open func() (inspect.PacketSource, error)) *Observer
func (o *Observer) Run()   // loops Next()→ParseDNSResponse→cache.Put until Close/EOF; safe to run in a goroutine
func (o *Observer) Close() // stops the loop and the source
```
Note: `inspect.PacketSource` is currently package-internal; export it (or add `inspect.OpenPortCapture` returning the interface value). Simplest: `inspect.OpenPortCapture` returns `inspect.PacketSource` and we export the interface. The observer strips IP/UDP headers to reach the DNS payload — reuse `inspect`'s IP/UDP parsing (export a helper `inspect.UDPPayload(ipPacket []byte) (payload []byte, srcPort, dstPort int, ok bool)` if not present).

- [ ] **Step 1: Write failing test** with a `fixtureSource` of one IP/UDP/53 packet wrapping a DNS response → after `Run` (drained to EOF), `cache.Lookup(answerIP)` returns the name.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement `Run`**: loop `Next()`; on a packet, extract the UDP payload for port 53, `ParseDNSResponse`, `cache.Put` each record; on `io.EOF` or after `Close`, return. `Close` closes `done` and the source.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(netname): passive DNS observer feeding the cache (#3)`

## Task 7: wire the resolver into the egress monitor + activate raw-IP concern

**Files:** Modify `internal/egress/monitor.go`, `internal/egress/concern.go`; Test `internal/egress/monitor_test.go`, `internal/egress/concern_test.go`.

**Interfaces:** Consumes: `netname.Resolver`. The monitor gains:
```go
// monitor.go — new field on Monitor, defaulting to a no-op so existing tests/behaviour are unchanged.
resolve func(ip string) (string, bool)
func (m *Monitor) SetResolver(r netname.Resolver) // sets m.resolve = r.Lookup
```
`Sample` — after building groups, walk each group's `Conns` and `Destinations` and set `Endpoint.Name`, e.g. `if m.resolve != nil { if n, ok := m.resolve(ep.IP); ok { ep.Name = n } }`. **NOTE:** `internal/egress` importing `internal/netname` must not create a cycle — `netname` imports `inspect`, not `egress`, so this is safe; keep the `Resolver` interface in `netname`.

- [ ] **Step 1 (names): failing test** — a `Monitor` with a fake resolver (`func(ip) => ("host.example", true)`) samples fake nettop/lsof fixtures; assert every `Destinations[i].Name == "host.example"`, and with no resolver set, `Name == ""`.
- [ ] **Step 2:** Run — FAIL. **Step 3:** implement `SetResolver` + the annotation pass in `Sample`. **Step 4:** Run — PASS.
- [ ] **Step 5 (concern): failing test** — `concern_test.go`: an unsigned + background + sustained-upload group whose destinations all have `Name == ""` scores one band higher than the same group with a named destination; a **notarized/quiet** group with a nameless destination is unchanged (light-touch corroboration).
- [ ] **Step 6:** Run — FAIL. **Step 7:** change `allRawIP(dests)` to `for _, d := range dests { if d.Name != "" { return false } }; return len(dests) > 0` and delete the neutral `isRawIP(ip)` stub (its `#3` cross-ref comment resolved). The existing `concernScore` gating (volume + background) already makes it corroborated — do not add weight elsewhere. **Step 8:** Run — PASS.
- [ ] **Step 9: Commit** — `feat(egress): resolve destination names + light-touch raw-IP concern (#3)`

## Task 8: structured cleartext decoder

**Files:** Create `internal/inspect/cleartext.go`, `internal/inspect/cleartext_test.go`; Modify `internal/inspect/inspect.go`.

**Interfaces:** Produces:
```go
type Content struct {
	Kind    string   // "http-request" | "http-response" | "text" | "binary"
	Start   string   // request line ("GET /p HTTP/1.1") or status line ("HTTP/1.1 200 OK"); "" if not HTTP
	Headers []Header // decoded headers, sensitive ones masked unless revealed
	Body    string   // decoded/needed-truncated body preview (text) — hex handled by the caller's fallback
	Truncated bool
}
type Header struct { Name, Value string; Sensitive bool }
func DecodeCleartext(b []byte, reveal bool) Content
```
Sensitive header set: `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and any header whose name contains `token`/`secret`/`key` (case-insensitive). When `!reveal`, `Value` is masked to `••••`.

- [ ] **Step 1: Write failing tests** — a raw `GET /p?q=1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer s\r\n\r\n` decodes to Kind `http-request`, Start line, a masked `Authorization` (reveal=false) and unmasked (reveal=true); a `POST` with a body previews the body; a non-HTTP text blob → Kind `text`; binary → Kind `binary`.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** using `net/http`'s `ReadRequest`/`ReadResponse` on a `bufio.Reader` over the bytes (they tolerate partial reads for our preview needs); on parse failure fall back to `text` (if `looksPlaintext`) or `binary`. Mask sensitive headers unless `reveal`.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Attach to `Result`** — add `OutboundContent, InboundContent Content` to `inspect.Result`, populated in `Inspect` from `DecodeCleartext(r.Outbound, false)` / `Inbound` when the direction is plaintext. Update the honest verdict unchanged. Existing `inspect` tests stay green.
- [ ] **Step 6: Commit** — `feat(inspect): structured cleartext (HTTP) decoder with secret masking (#3)`

## Task 9: TUI rendering — names + decoded content

**Files:** Modify `internal/tui/egressview.go`, `internal/tui/egresszoom.go`, `internal/tui/inspect.go`; Test the corresponding `_test.go`.

**Interfaces:** Consumes: `model.Endpoint.Name`, `inspect.Result.{Outbound,Inbound}Content` (already reaches the TUI as data via the existing inspect adapter — no new import).

- [ ] **Step 1 (dest name): failing test** — the destination cell for `Endpoint{IP:"1.2.3.4",Port:443,Name:"api.example.com"}` renders `api.example.com` (with the IP available on expand/detail), and a nameless endpoint renders `1.2.3.4`. Assert via the existing egress view test harness.
- [ ] **Step 2:** Run — FAIL. **Step 3:** in the destination-string builder (`egressview.go` ~`drawGroupRow`, and the zoom destinations table), prefer `Name` when non-empty, else `IP`. Keep the encryption glyph logic keyed on port. **Step 4:** Run — PASS.
- [ ] **Step 5 (inspect content): failing test** — the inspect view, given a `Result` with an `http-request` `OutboundContent`, renders the start line + headers with the sensitive one masked until `v`. **Step 6:** Run — FAIL. **Step 7:** render `Content` structurally in `internal/tui/inspect.go` (start line, headers with a mask marker, body preview), falling back to the current hexdump when `Kind == "binary"`. Wire `v` (existing reveal key) to re-decode with `reveal=true`. **Step 8:** Run — PASS.
- [ ] **Step 9:** Run `go test ./internal/tui/` incl. `TestDecouplingInvariant`. **Commit** — `feat(tui): render destination names + structured inspect content (#3)`

## Task 10: console lifecycle wiring (no flag)

**Files:** Modify `main.go`; Test `main_test.go`.

**Interfaces:** Consumes: `netname.NewCache`, `netname.NewObserver`, `inspect.OpenPortCapture`, `Monitor.SetResolver`.

- [ ] **Step 1: failing test** — a `runConsole` seam test: inject a fake observer/resolver (add a `newNameResolver` package var like `newEgressMonitor`) and assert the monitor gets a resolver set, and that a non-darwin / capture-open failure degrades to a nil resolver (names empty) without error. Assert **no new flag** is parsed (help text unchanged — reuse `TestRun_HelpFlags`).
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement** in the `console` live path (not `--from`): build `cache := netname.NewCache(4096)`; best-effort `src, err := inspect.OpenPortCapture(defaultIface(), 53)`; if ok, `obs := netname.NewObserver(cache, ...)`, `go obs.Run()`, `mon.SetResolver(cache)`, and `defer obs.Close()`; on err, log a one-line gap note and continue (names simply absent). Gate behind the same "live, not snapshot" branch. `defaultIface()` picks the default-route interface (best-effort; reuse the inspector's interface pick if it has one, else `en0`).
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** — `feat(console): start passive DNS name resolution in the live monitor (#3)`

## Task 11: Architext + docs

**Files:** `docs/architext/data/nodes.json` (new `mod-netname`; extend `mod-egress`/`mod-inspect`/`mod-tui`), `data-classification.json` (a `dns-observations` class), `flows.json` (name-resolution enrichment relationship), `roadmap.json` (mark `roadmap-egress-packet-capture` in-progress → done on ship), README egress section (names + honest DoH gap).

- [ ] **Step 1:** Add `mod-netname` node + data class + flow note; extend affected nodes' responsibilities/interfaces; run `architext validate` (+ `doctor --yes` for index refresh).
- [ ] **Step 2:** Update README's Exfiltration section: names now shown, honest note that pre-existing connections / encrypted DNS (DoH/DoT) stay as IPs.
- [ ] **Step 3: Commit** — `docs(architext): model netname + destination-name enrichment (#3)`

---

## Self-review

- **Spec coverage:** names (T4–7,9,10) · cleartext extraction (T8–9) · light-touch raw-IP concern (T7) · honest degradation (T7 no-resolver, T10 open-failure, T8 fallback) · testing behind seams (fake resolver T7, fixtureSource T6, fixtures T4/T8) · no new flag (T10 asserts help unchanged). All present.
- **Placeholder scan:** each code step shows real signatures/bodies or a precise edit; no "TBD/add error handling".
- **Type consistency:** `model.Endpoint.Name` (T1) used by monitor (T7), concern (T7), tui (T9). `Resolver.Lookup(ip)(string,bool)` (T5) matches `Monitor.resolve` (T7) and `Cache.Lookup` (T5). `inspect.Content` (T8) rendered in tui (T9). `OpenPortCapture` (T3) used by observer/console (T6/T10). Consistent.
- **Cycle check:** `egress → netname → inspect`; no `netname → egress` or `tui → netname` edges. Safe.
