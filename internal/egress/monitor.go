// internal/egress/monitor.go
package egress

import (
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

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
		interval: interval,
		prev:     map[int]Bytes{},
		spark:    map[string][]uint64{},
		runNettop: func() []byte {
			b, _ := exec.Command("nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out").Output()
			return b
		},
		runLsof: func() []byte { b, _ := exec.Command("lsof", "-i", "-nP").Output(); return b },
		procs:   defaultProcs,
		trustOf: defaultTrust,
		capsOf:  defaultCaps,
	}
}

// Sample runs one observation tick and returns the current aggregated, scored groups.
func (m *Monitor) Sample() []model.EgressGroup {
	cur := ParseNettop(m.runNettop())
	conns := ParseLsofConns(m.runLsof())
	procs := m.procs()

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
		path, app := binaryPath(p), displayName(p, pid)
		// First sighting of a pid has no prior cumulative baseline; rate is 0 rather than
		// attributing the process's entire historical cumulative output to a single tick.
		var rate uint64
		if prev, ok := m.prev[pid]; ok {
			rate = RateOut(prev, cur[pid], m.interval)
		}
		insts = append(insts, Instance{
			PID: pid, App: app, Path: path, Ancestry: collect.Ancestry(procs, pid),
			Trust: m.trustOf(path), OutRate: rate, OutTotal: cur[pid].Out, InRate: 0,
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
