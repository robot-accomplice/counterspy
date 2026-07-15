# Phase 2 — Transparent TLS-intercepting decrypt mirror — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. This plan is executed as a **swarm** cycle (single-writer + Antagonist/Audit fan-out per checkpoint), per `.swarm/`.

**Goal:** a consented, transparent, **read-only** TLS-intercepting proxy that decrypts this host's outbound HTTPS and surfaces the plaintext — `counterspy intercept` (root background daemon) publishes decrypted flows; `counterspy console` views them.

**Architecture:** pf `rdr` redirects TCP:443 → a local proxy; the proxy recovers the original dest (`/dev/pf` `DIOCNATLOOK`), terminates the client TLS with a per-SNI leaf minted from a local reversible CA, re-dials the real server, relays **unmodified**, and captures plaintext → `DecodeCleartext`+`Redact` → a publish sink (unix socket and/or rotating log). The crypto core is stdlib and CI-tested over loopback; the pf/keychain edges are darwin+root, compile-guarded.

**Tech Stack:** Go 1.26 stdlib (`crypto/tls`, `crypto/x509`, `net`), macOS pf (`/dev/pf` `DIOCNATLOOK`, `pfctl`), `security` CLI for keychain trust. No new third-party deps.

## Global Constraints

- **Read-only this cycle.** Relay bytes byte-for-byte; never modify. (Redact/block = Phase 3.)
- **Reliable teardown is the #1 requirement.** pf rules + CA trust reverted on EVERY exit path (defer + SIGINT/TERM/HUP + panic recovery), plus an idempotent `intercept --uninstall`. Never leave a user's TLS redirected or a CA trusted after a crash.
- **Control surface (maintainer-approved):** a new `counterspy intercept` command + its flags (`--stream`, `--log`, `--uninstall`). No OTHER new flags without approval.
- **Honesty:** pinned apps are bypassed (pf exception), reported `pinned · not decryptable`, never silently broken; upstream server certs are still verified; decrypted content is `Redact`-masked before show/log; the log lives at 0600 under the invoking user's home and expires.
- **TUI decoupling invariant** (`internal/tui` imports only `model` + `mark`) preserved: the console reads flow records as data.
- **Coverage/quality:** `go test ./... -race` green, total coverage ≥80%, `go vet`, `gofmt`, `GOOS=linux` build (non-darwin stubs), `architext validate`. cgo build unaffected.
- **Gitflow/swarm:** single-writer branch `feat/tls-intercept` off develop; a checkpoint per task, each fan-out-reviewed; PR → develop when green.

## File Structure

- `internal/intercept/flow.go` — `Flow` record (metadata + decoded, masked content); the proxy→console contract.
- `internal/intercept/ca/ca.go` — `CA` (self-signed root), `LeafFor(sni)`; PEM load/save.
- `internal/intercept/ca/trust_darwin.go` / `trust_other.go` — install/uninstall keychain trust (seam).
- `internal/intercept/proxy.go` — the accept loop + the terminate→re-dial→relay pump + capture.
- `internal/intercept/pf_darwin.go` / `pf_other.go` — `rdr` install/teardown + `DIOCNATLOOK` orig-dest.
- `internal/intercept/publish/sink.go` — `Sink` interface + fan-out.
- `internal/intercept/publish/socket.go` — unix-socket server (proxy) + reader (console).
- `internal/intercept/publish/logfile.go` — rotating/size-capped/expiring JSONL writer + reader.
- `main` — `intercept` command (`intercept.go`), consent + wiring + teardown; `console` intercepted-flows source.
- `internal/tui/` — an intercepted-flows view/source consuming `Flow` records.
- `docs/architext/data/**` — `mod-intercept`, `decrypted-flow` data class, roadmap.

---

## Task 1: the `Flow` record (proxy→console contract)

**Files:** Create `internal/intercept/flow.go`, `flow_test.go`.

**Interfaces:** Produces:
```go
type Flow struct {
	At       string   `json:"at"`        // RFC3339
	PID      int      `json:"pid,omitempty"`
	DestIP   string   `json:"dest_ip"`
	DestName string   `json:"dest_name,omitempty"` // SNI or resolved name
	SNI      string   `json:"sni,omitempty"`
	Status   string   `json:"status"`    // "decrypted" | "pinned" | "opaque" | "error"
	SentText string   `json:"sent_text,omitempty"` // decoded + Redact-masked request
	RecvText string   `json:"recv_text,omitempty"` // decoded + Redact-masked response
	SentBytes int     `json:"sent_bytes"`
	RecvBytes int     `json:"recv_bytes"`
}
```
- [ ] **Step 1: failing test** — a Flow round-trips through `encoding/json` (JSONL) preserving fields; `Status` values are the closed set.
- [ ] **Step 2:** run → FAIL. **Step 3:** define the struct. **Step 4:** run → PASS.
- [ ] **Step 5: Commit** — `feat(intercept): Flow record — the decrypt proxy→console contract`

## Task 2: local CA + per-SNI leaf minting

**Files:** Create `internal/intercept/ca/ca.go`, `ca_test.go`.

**Interfaces:** Produces:
```go
type CA struct{ cert *x509.Certificate; key crypto.Signer; certPEM []byte }
func NewCA() (*CA, error)                         // self-signed root, CA:true, 10y
func LoadCA(certPEM, keyPEM []byte) (*CA, error)
func (c *CA) PEM() (certPEM, keyPEM []byte)
func (c *CA) LeafFor(sni string) (*tls.Certificate, error) // minted leaf, SANs=[sni], signed by CA
```
- [ ] **Step 1: failing tests** — `NewCA` produces a CA cert (IsCA, KeyUsageCertSign); `LeafFor("example.com")` returns a leaf that (a) verifies against the CA via `x509.CertPool`, (b) has `example.com` in DNSNames, (c) is usable as a `tls.Certificate`. `LoadCA(PEM())` round-trips.
```go
func TestCA_MintsVerifiableLeaf(t *testing.T) {
	ca, _ := NewCA()
	leaf, err := ca.LeafFor("example.com"); if err != nil { t.Fatal(err) }
	pool := x509.NewCertPool(); pool.AddCert(caCert(ca))
	x, _ := x509.ParseCertificate(leaf.Certificate[0])
	if _, err := x.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatalf("leaf must chain to the CA: %v", err)
	}
}
```
- [ ] **Step 2:** run → FAIL. **Step 3:** implement with `crypto/ecdsa` (P-256) + `x509.CreateCertificate`; cache leaves per SNI (bounded map) to avoid re-minting. **Step 4:** run → PASS (incl. load round-trip).
- [ ] **Step 5: Commit** — `feat(intercept): local CA + per-SNI leaf minting (stdlib crypto)`

## Task 3: keychain trust install/uninstall (seam)

**Files:** Create `internal/intercept/ca/trust_darwin.go`, `trust_other.go`, `trust_test.go`.

**Interfaces:** Produces `InstallTrust(certPEM []byte) error` / `UninstallTrust() error`, each calling `security add-trusted-cert` / `remove-trusted-cert` via an injectable `runSecurity func(args ...string) error` package var (default = exec). Non-darwin stub returns an error.
- [ ] **Step 1: failing test** — with a fake `runSecurity` capturing args, `InstallTrust` invokes `add-trusted-cert` with the right flags (a temp cert file, `-r trustRoot`), and `UninstallTrust` invokes removal; a `runSecurity` error propagates (fail loud).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement (write certPEM to a temp file, exec `security`; darwin build tag). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** — `feat(intercept): reversible keychain trust for the local CA (seam-tested)`

## Task 4: the TLS terminate→re-dial→relay pump

**Files:** Create `internal/intercept/proxy.go` (pump), `proxy_test.go`.

**Interfaces:** Produces:
```go
// intercept terminates the client TLS with a CA leaf, dials dest with verified upstream TLS, relays
// both directions unmodified, and returns the captured Flow. dial is injected for tests.
func intercept(client net.Conn, dest netip.AddrPort, ca *ca.CA, dial dialFunc) Flow
type dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)
```
- [ ] **Step 1: failing loopback test** — stand up an in-process TLS server (its own cert) as "upstream"; a client dials the pump over a `net.Pipe`/loopback with SNI; assert the pump decrypts, the client sees the server's response, the captured `Flow.Status=="decrypted"` and `SentText`/`RecvText` contain the plaintext, relayed unmodified.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement: `tls.Server(client, &tls.Config{GetCertificate: ca.leaf})`; handshake; on client-handshake failure (a **pinned** client rejecting the leaf) return `Flow{Status:"pinned"}` and close; else `tls.Dial` upstream (normal verification), `io.Copy` both ways through a capturing `io.TeeReader`; decode+mask each direction via `inspect.DecodeCleartext`/`model.Redact`. **Step 4:** run → PASS.
- [ ] **Step 5: pinning test** — a client `tls.Config{RootCAs: <only-the-real-server's-CA>}` (rejects our leaf) → `Flow.Status=="pinned"`, no plaintext captured, connection closed cleanly (app not hung). **Step 6:** run → PASS.
- [ ] **Step 7: Commit** — `feat(intercept): TLS terminate/re-dial/relay pump with honest pinning handling`

## Task 5: proxy accept loop + original-dest seam

**Files:** Modify `internal/intercept/proxy.go`; `proxy_loop_test.go`.

**Interfaces:** Produces:
```go
type Proxy struct{ ca *ca.CA; origDest func(net.Conn) (netip.AddrPort, error); dial dialFunc; sink publish.Sink }
func (p *Proxy) Serve(l net.Listener) error   // accept → origDest → intercept → sink.Publish(flow)
```
- [ ] **Step 1: failing test** — a `Proxy` with an injected `origDest` (returns a fixed AddrPort) + a fake sink; drive one loopback client through `Serve`; assert the sink received a `decrypted` Flow. Injected seams mean no pf/root.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement the accept loop (goroutine per conn, panic-recover per conn so one bad flow can't kill the proxy). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** — `feat(intercept): proxy accept loop over injectable orig-dest + sink`

## Task 6: darwin pf edge (rdr + DIOCNATLOOK)

**Files:** Create `internal/intercept/pf_darwin.go`, `pf_other.go`.

**Interfaces:** Produces (darwin): `InstallRedirect(proxyPort int, bypass []netip.Addr) (teardown func() error, error)` (adds a pf anchor `rdr` rule for TCP:443 → 127.0.0.1:proxyPort with bypass exceptions; teardown flushes the anchor), and `OrigDest(conn net.Conn) (netip.AddrPort, error)` via `DIOCNATLOOK` on `/dev/pf`. Non-darwin: stubs that refuse (like `bpf_other.go`).
- [ ] **Step 1: refactor guard** — `go build ./...` (darwin) + `GOOS=linux go build ./...` compile; no unit test (needs root+pf). Document the manual smoke test in a comment.
- [ ] **Step 2:** implement the pf anchor rule text + `pfctl`/ioctl calls and the `DIOCNATLOOK` struct (mirror `bpf_darwin.go`'s raw-ioctl discipline: a compile-time size guard on the struct). **Step 3:** confirm both builds. **Step 4:** file a manual smoke-test checklist in the PR.
- [ ] **Step 5: Commit** — `feat(intercept): darwin pf rdr redirect + DIOCNATLOOK orig-dest (compile-guarded)`

## Task 7: publish sink — unix socket

**Files:** Create `internal/intercept/publish/sink.go`, `socket.go`, `socket_test.go`.

**Interfaces:**
```go
type Sink interface{ Publish(Flow) error; Close() error }
func Fanout(...Sink) Sink
func NewSocketSink(path string) (Sink, error)       // proxy side: serves connected readers
func ReadSocket(path string, fn func(Flow)) error   // console side: connect + stream
```
- [ ] **Step 1: failing test** — over a temp socket, a `SocketSink.Publish(flow)` is received by a concurrent `ReadSocket` reader (JSONL frames); multiple flows preserved in order; reader-absent Publish doesn't block/panic (buffered or dropped-with-count). Run `-race`.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement (a unix listener; each connected reader gets a channel; Publish fans out non-blocking with a bounded buffer, dropped-count logged). **Step 4:** run → PASS (`-race`).
- [ ] **Step 5: Commit** — `feat(intercept/publish): live unix-socket flow stream`

## Task 8: publish sink — rotating log file

**Files:** Create `internal/intercept/publish/logfile.go`, `logfile_test.go`.

**Interfaces:** `NewLogSink(path string, maxSize int64, keep int, maxAge time.Duration) (Sink, error)` — JSONL append at 0600; rotate at `maxSize` (`path.1`, …), keep `keep`, delete older than `maxAge`. `ReadLog(path, fn)` for the console.
- [ ] **Step 1: failing tests** — writes append JSONL; exceeding `maxSize` rotates and prunes to `keep`; an entry older than `maxAge` is expired on open; file mode 0600.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement (size-tracked writer + rotation; age prune on open). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** — `feat(intercept/publish): rotating, size-capped, expiring log sink`

## Task 8b: masking is applied before publish (defense-in-depth test)

**Files:** `internal/intercept/proxy_test.go`.
- [ ] **Step 1: test** — a decrypted flow carrying `Authorization: Bearer SECRET` and a Cookie is published with those values **masked** (the pump applied `model.Redact` before building the Flow), so no sink ever sees the raw secret. **Step 2:** if not already satisfied by Task 4, adjust the pump to mask at capture time. **Step 3:** run → PASS. **Commit** — `test(intercept): secrets are masked before any sink sees a flow`

## Task 9: the `intercept` command + teardown contract

**Files:** Create `main`'s `intercept.go`; modify command dispatch + usage; `intercept_test.go`.

**Interfaces:** `counterspy intercept [--stream[=sock]] [--log[=path,size,keep,age]] [--uninstall]`.
- [ ] **Step 1: failing tests (seam-driven)** — inject fakes for CA-trust, pf, listener, and the socket path; assert: (a) `--uninstall` calls pf-teardown + trust-uninstall idempotently and exits; (b) a normal run installs trust + pf **then** serves, and a simulated signal/defer runs teardown in the right order (trust + pf reverted) even on a mid-run panic; (c) with neither `--stream` nor `--log`, it defaults to stream; (d) help/usage lists `intercept` and NO other new flag.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement: consent prompt (skip on a `--yes`? no — always prompt unless non-interactive, then require an explicit env/arg the maintainer approves separately); build CA (load-or-create under home), `InstallTrust`, `InstallRedirect`, open the chosen sinks, `Proxy.Serve`; register teardown on defer + `signal.Notify(SIGINT/TERM/HUP)` + panic recovery (mirror runTUI's fini pattern). **Step 4:** run → PASS.
- [ ] **Step 5: Commit** — `feat(cli): counterspy intercept — consented TLS decrypt daemon with reliable teardown`

## Task 10: console views intercepted flows

**Files:** Modify `internal/tui/` (a source/view for `Flow` records) + `main` `console` wiring; tests.
- [ ] **Step 1: failing test** — the console, given a fake flow source yielding decrypted `Flow`s, renders them (dest name, status, masked content) via the existing inspect-style rendering; decoupling invariant holds (tui reads `Flow` as data — put `Flow` where tui can import it, i.e. `model` or a tui-visible type, mirroring `InspectView`).
- [ ] **Step 2:** run → FAIL. **Step 3:** implement: `console` detects a live socket / log (from flags or a default path) and streams `Flow`s into a new "Intercepted" view (or folds into Exfiltration); a `pinned`/`opaque` flow is shown honestly. **Step 4:** run → PASS + decoupling test.
- [ ] **Step 5: Commit** — `feat(console): view intercepted decrypted flows`

## Task 11: Architext + docs

**Files:** `docs/architext/data/**`, `README.md`.
- [ ] **Step 1:** add `mod-intercept` node (proxy/CA/publish + darwin pf edge, trust-boundary security notes), a `decrypted-flow` data class (sensitive; ephemeral socket or 0600 expiring log), extend `mod-tui`/`mod-inspect`; a data-flow relationship (redirect → decrypt → publish → console). `architext validate` (+ `doctor --yes`).
- [ ] **Step 2:** README — a new section on `counterspy intercept` (consent, reversibility/`--uninstall`, transparent coverage, honest pinning/QUIC gaps, the socket/log outputs); mark the roadmap Phase 2 item in-progress.
- [ ] **Step 3: Commit** — `docs(architext,readme): model the TLS-intercept proxy`

---

## Self-review

- **Spec coverage:** CA+trust (T2,T3) · transparent routing/orig-dest (T5,T6) · terminate/relay/decrypt (T4) · pinning honesty (T4,T10) · publish socket+log chosen at launch (T7,T8,T9) · two-process model (T9 daemon, T10 viewer) · teardown contract (T9) · masking (T8b) · read-only (T4 relays unmodified) · testing over loopback (T4,T5,T7,T8) · darwin edges guarded (T3,T6) · docs (T11). All present.
- **Placeholder scan:** each code step carries real signatures/tests; no "TBD/add error handling."
- **Type consistency:** `Flow` (T1) flows through pump (T4) → sink (T7/T8) → console (T10); `ca.CA.LeafFor` (T2) used by the pump's `GetCertificate` (T4); `dialFunc`/`origDest`/`Sink` seams (T4/T5) reused by the command (T9). Consistent.
- **Cycle check:** `intercept → {ca, publish, inspect, model, mark}`; `tui → model` only (Flow lives model-side). No back-edges.
- **Safety:** teardown ordering + idempotent `--uninstall` (T9) is the load-bearing checkpoint; the swarm must scrutinize it hardest (a leftover pf redirect is the worst-case failure).
