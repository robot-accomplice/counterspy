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

// Aggregate collapses instances into one EgressGroup per application (keyed by process
// NAME), summing rates/volume, unioning destinations/conns/capabilities, and taking the
// worst-case trust. Each input Instance also becomes an EgressGroup.Member so the TUI can
// render the binary → instance → connection tree. Grouping is by binary PATH (not name) so
// two distinct binaries that happen to share a process name stay separate rows; the App name
// is only the display label. `spark` maps the group key (path) → recent summed out-rate history.
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
			g = &model.EgressGroup{App: in.App, Path: in.Path, Ancestry: in.Ancestry, Trust: in.Trust}
			byKey[key] = g
			order = append(order, key)
			dests[key] = map[string]bool{}
			caps[key] = map[string]bool{}
		}
		g.Instances++
		g.Members = append(g.Members, model.EgressInstance{
			PID: in.PID, Path: in.Path, Trust: in.Trust,
			OutRate: in.OutRate, InRate: in.InRate, OutTotal: in.OutTotal, Conns: in.Conns,
		})
		g.OutRate += in.OutRate
		g.InRate += in.InRate
		g.OutTotal += in.OutTotal
		g.Conns = append(g.Conns, in.Conns...)
		g.Trust = worseTrust(g.Trust, in.Trust)
		g.Background = g.Background || isBackground(in.Path)
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
