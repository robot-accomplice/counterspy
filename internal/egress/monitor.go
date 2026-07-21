// internal/egress/monitor.go
package egress

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"counterspy/internal/collect"
	"counterspy/internal/model"
)

const sparkLen = 60 // recent rate samples kept per ring (~1min at the 1s cadence) — wide enough for
// the zoom graph; the tree's small sparklines downsample this to their column width.

// Monitor holds the sampling state (previous cumulative bytes + per-app spark history) and
// the injectable exec/join seams. Sample() is called once per tick.
type Monitor struct {
	interval  float64
	prev      map[int]Bytes
	prevConn  map[string]Bytes    // previous cumulative bytes per connKey — for per-conn rates
	spark     map[string][]uint64 // per-app (path) out-rate history — app-header sparkline
	sparkPID  map[int][]uint64    // per-PID out-rate history — instance-row sparkline
	sparkConn map[string][]uint64 // per-connKey out-rate history — connection-row sparkline

	sparkIn     map[string][]uint64 // per-app in-rate history
	sparkInPID  map[int][]uint64    // per-PID in-rate history
	sparkInConn map[string][]uint64 // per-connKey in-rate history

	runNettop func() []byte
	runLsof   func() []byte
	procs     func() map[int]*collect.Proc
	exePaths  func() map[int]string // pid -> full executable path (spaces intact)
	trustOf   func(path string) string
	capsOf    func(path string) []string
	resolve   func(ip string) (name string, ok bool) // passive-DNS name lookup; nil = names unavailable (#3)

	// excludePID is dropped from every sample so counterspy never reports on its own traffic. It
	// matters most while the intercept proxy is armed, when counterspy re-dials every upstream under
	// this pid and would otherwise dominate the Exfiltration view (Self1). Set to os.Getpid() in New.
	excludePID int
}

// Resolver maps a destination IP to the hostname most recently observed resolving to it (passive
// DNS). Defined here, at the consumer, so the monitor stays testable with a fake and never imports
// the capture machinery; internal/netname.Cache satisfies it structurally (T-15).
type Resolver interface {
	Lookup(ip string) (name string, ok bool)
}

// SetResolver wires a name resolver into the monitor. Called once at console start with the live
// netname cache; left unset in tests / when capture is unavailable (destinations then show IPs).
func (m *Monitor) SetResolver(r Resolver) { m.resolve = r.Lookup }

func New(interval float64) *Monitor {
	return &Monitor{
		interval:  interval,
		prev:      map[int]Bytes{},
		prevConn:  map[string]Bytes{},
		spark:     map[string][]uint64{},
		sparkPID:  map[int][]uint64{},
		sparkConn: map[string][]uint64{},

		sparkIn:     map[string][]uint64{},
		sparkInPID:  map[int][]uint64{},
		sparkInConn: map[string][]uint64{},
		runNettop: func() []byte {
			// Hierarchical output (no -P): process rows carry per-PID totals AND connection
			// sub-rows carry per-connection bytes, so one call feeds both ParseNettop and
			// ParseNettopConns. ParseNettop skips the connection rows (no name.pid).
			// -n disables DNS/hostname resolution: WITHOUT it nettop blocks ~5s per sample (making
			// the live view/zoom graph crawl); WITH it a sample returns in ~10ms and endpoints stay
			// as IPs, which is exactly what the IP-based parser wants.
			b, _ := exec.Command("nettop", "-n", "-L", "1", "-x", "-J", "bytes_in,bytes_out").Output()
			return b
		},
		runLsof:    func() []byte { b, _ := exec.Command("lsof", "-i", "-nP").Output(); return b },
		procs:      defaultProcs,
		exePaths:   defaultExePaths,
		trustOf:    defaultTrust,
		capsOf:     defaultCaps,
		excludePID: os.Getpid(),
	}
}

// defaultExePaths resolves every pid's real executable path from `ps -o comm` (no argv, so
// spaces in the path are unambiguous — fixes the "Application" mislabel).
func defaultExePaths() map[int]string {
	b, _ := exec.Command("ps", "-axo", "pid=,comm=").Output()
	return ParsePidPaths(b)
}

// Sample runs one observation tick and returns the current aggregated, scored groups.
func (m *Monitor) Sample() []model.EgressGroup {
	raw := m.runNettop()
	cur := ParseNettop(raw)
	curConn := ParseNettopConns(raw)
	conns := ParseLsofConns(m.runLsof())
	// Never report on ourselves: while the intercept proxy is armed, counterspy re-dials every
	// upstream under this pid; those dials would otherwise dominate the Exfiltration view (Self1).
	delete(conns, m.excludePID)
	procs := m.procs()
	exe := m.exePaths()

	// Enrich each lsof-discovered connection with its per-connection out-rate (from nettop's
	// per-connection byte counts) and advance its own spark ring — so every connection leaf
	// row shows a real trend, not a flat line. Prune connKeys gone this tick.
	liveConn := make(map[string]bool, len(curConn))
	rateOf := make(map[string]uint64, len(curConn))
	rateInOf := make(map[string]uint64, len(curConn))
	// First pass: advance each UNIQUE connKey's ring exactly once (two lsof FDs to the same
	// remote share a key — advancing per-entry would grow the ring 2x/tick and desync rows).
	for pid, cs := range conns {
		for i := range cs {
			k := connKey(pid, cs[i].Endpoint.IP, cs[i].Endpoint.Port)
			liveConn[k] = true
			if _, done := rateOf[k]; done {
				continue
			}
			var rate uint64
			if prev, ok := m.prevConn[k]; ok {
				rate = RateOut(prev, curConn[k], m.interval)
			}
			rateOf[k] = rate
			s := append(m.sparkConn[k], rate)
			if len(s) > sparkLen {
				s = s[len(s)-sparkLen:]
			}
			m.sparkConn[k] = s

			var rin uint64
			if prev, ok := m.prevConn[k]; ok {
				rin = RateIn(prev, curConn[k], m.interval)
			}
			rateInOf[k] = rin
			si := append(m.sparkInConn[k], rin)
			if len(si) > sparkLen {
				si = si[len(si)-sparkLen:]
			}
			m.sparkInConn[k] = si
		}
	}
	// Second pass: assign the (once-advanced) rate + spark to every connection sharing a key.
	for pid, cs := range conns {
		for i := range cs {
			k := connKey(pid, cs[i].Endpoint.IP, cs[i].Endpoint.Port)
			cs[i].OutRate = rateOf[k]
			cs[i].Spark = m.sparkConn[k]
			cs[i].InRate = rateInOf[k]
			cs[i].InSpark = m.sparkInConn[k]
		}
	}
	m.prevConn = curConn
	for k := range m.sparkConn {
		if !liveConn[k] {
			delete(m.sparkConn, k)
		}
	}
	for k := range m.sparkInConn {
		if !liveConn[k] {
			delete(m.sparkInConn, k)
		}
	}

	insts := make([]Instance, 0, len(conns))
	// Sorted pid iteration → deterministic output order (Go map iteration is randomized),
	// satisfying the Sample()-deterministic-given-injected-seams contract.
	pids := make([]int, 0, len(conns))
	for pid := range conns {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		p := procs[pid]
		// Prefer the real executable path from `ps -o comm` (spaces intact); fall back to
		// the argv[0] token only when comm is unavailable for a pid.
		path := exe[pid]
		if path == "" {
			path = binaryPath(p)
		}
		app := appName(path, pid)
		// First sighting of a pid has no prior cumulative baseline; rate is 0 rather than
		// attributing the process's entire historical cumulative output to a single tick.
		var rate, rateIn uint64
		if prev, ok := m.prev[pid]; ok {
			rate = RateOut(prev, cur[pid], m.interval)
			rateIn = RateIn(prev, cur[pid], m.interval)
		}
		// Clean the attacker-influenced identity strings (process name / path / ancestry) at the
		// source: a crafted argv[0] can't carry ANSI/newlines/RTLO into storage or the terminal.
		// Defense-in-depth over the JSON encoder + the TUI's render-time Clean (issue #9).
		insts = append(insts, Instance{
			PID: pid, App: model.Clean(app), Path: model.Clean(path), Ancestry: model.Clean(collect.Ancestry(procs, pid)),
			Trust: m.trustOf(path), OutRate: rate, OutTotal: cur[pid].Out, InRate: rateIn,
			Conns: conns[pid], Capabilities: m.capsOf(path),
		})
	}
	// Advance per-binary spark ring buffers from this tick's summed rate. Key by path to
	// match Aggregate's grouping (so sparklines attach to the right group).
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
	summedIn := map[string]uint64{}
	for _, in := range insts {
		k := in.Path
		if k == "" {
			k = in.App
		}
		summedIn[k] += in.InRate
	}
	for k, r := range summedIn {
		s := append(m.sparkIn[k], r)
		if len(s) > sparkLen {
			s = s[len(s)-sparkLen:]
		}
		m.sparkIn[k] = s
	}
	// Prune app keys gone this tick (every live instance seeds `summed`), so the app-level maps
	// stay bounded like the per-PID/conn rings instead of growing per distinct app-path ever seen (T-14).
	for k := range m.spark {
		if _, live := summed[k]; !live {
			delete(m.spark, k)
		}
	}
	for k := range m.sparkIn {
		if _, live := summed[k]; !live {
			delete(m.sparkIn, k)
		}
	}
	// Advance per-PID spark ring buffers so each instance row has its own sparkline. Prune
	// PIDs absent this tick (process gone / no established connections) to keep the map bounded.
	livePID := make(map[int]bool, len(insts))
	for _, in := range insts {
		livePID[in.PID] = true
		s := append(m.sparkPID[in.PID], in.OutRate)
		if len(s) > sparkLen {
			s = s[len(s)-sparkLen:]
		}
		m.sparkPID[in.PID] = s

		si := append(m.sparkInPID[in.PID], in.InRate)
		if len(si) > sparkLen {
			si = si[len(si)-sparkLen:]
		}
		m.sparkInPID[in.PID] = si
	}
	for pid := range m.sparkPID {
		if !livePID[pid] {
			delete(m.sparkPID, pid)
		}
	}
	for pid := range m.sparkInPID {
		if !livePID[pid] {
			delete(m.sparkInPID, pid)
		}
	}
	m.prev = cur

	groups := Aggregate(insts, m.spark, m.sparkIn)
	for i := range groups {
		// Attach each instance's own history (Aggregate stays per-app; per-PID lives here).
		for j := range groups[i].Members {
			groups[i].Members[j].Spark = m.sparkPID[groups[i].Members[j].PID]
			groups[i].Members[j].InSpark = m.sparkInPID[groups[i].Members[j].PID]
		}
		// Resolve destination names BEFORE scoring, so a nameless (raw-IP) destination can feed the
		// light-touch concern signal (#3). No resolver → names stay "" and the signal is inert.
		m.resolveNames(&groups[i])
		groups[i].Concern = Concern(groups[i])
		groups[i].ExfilRisk, groups[i].Candidate = Exfil(groups[i])
	}
	return groups
}

// resolveNames annotates every Endpoint (destinations + per-connection) of a group with the hostname
// the app resolved for its IP, if one was passively observed. A missing name stays "" (show the IP);
// never fabricated.
func (m *Monitor) resolveNames(g *model.EgressGroup) {
	if m.resolve == nil {
		return
	}
	name := func(e *model.Endpoint) {
		if n, ok := m.resolve(e.IP); ok {
			e.Name = n
		}
	}
	for i := range g.Destinations {
		name(&g.Destinations[i])
	}
	for i := range g.Conns {
		name(&g.Conns[i].Endpoint)
	}
	for mi := range g.Members {
		for ci := range g.Members[mi].Conns {
			name(&g.Members[mi].Conns[ci].Endpoint)
		}
	}
}

func binaryPath(p *collect.Proc) string {
	if p == nil {
		return ""
	}
	return firstToken(p.Cmd)
}

// appName is the display name: the executable's base name, or "pid:N" when no path resolved.
func appName(path string, pid int) string {
	if path == "" {
		return "pid:" + itoa(pid)
	}
	return filepath.Base(path)
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
	return trustFromCodesign(collect.CollectCodesign(path))
}

// trustFromCodesign maps codesign evidence to a trust label. Pure and unit-tested; the exec
// (CollectCodesign) stays in defaultTrust so the mapping can be tested without shelling out.
func trustFromCodesign(ev []model.Evidence) string {
	for _, e := range ev {
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
	ev, _ := collect.CollectTCC()
	return capsFromTCC(ev, path)
}

// capsFromTCC maps TCC grant evidence to capability names for a given binary path. Pure and
// unit-tested; the exec (CollectTCC) stays in defaultCaps.
func capsFromTCC(ev []model.Evidence, path string) []string {
	if path == "" {
		return nil
	}
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
	return strings.HasPrefix(binary, client) ||
		filepath.Base(binary) == filepath.Base(client)
}
