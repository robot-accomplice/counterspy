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
	// Spark is keyed by binary PATH now (grouping is path-based).
	groups := Aggregate(insts, map[string][]uint64{"/x/backuptool": {600, 650, 620}}, nil)
	var bt *model.EgressGroup
	for i := range groups {
		if groups[i].App == "backuptool" {
			bt = &groups[i]
		}
	}
	if bt == nil {
		t.Fatal("backuptool group missing")
	}
	if bt.Instances != 2 { // same PATH → collapse
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

// Two distinct binaries that share a process name ("node") must stay SEPARATE groups —
// grouping is by binary path, so a rogue "node" can't hide inside a trusted one's row.
func TestAggregate_DifferentPathsStaySeparate(t *testing.T) {
	insts := []Instance{
		{PID: 111, App: "node", Path: "/usr/local/bin/node", Trust: "unsigned", OutRate: 100, OutTotal: 1000,
			Conns: []model.Conn{{PID: 111, Endpoint: model.Endpoint{IP: "10.0.0.1", Port: 443}, Proto: "tcp", OutRate: 100}}},
		{PID: 222, App: "node", Path: "/opt/x/node", Trust: "notarized", OutRate: 50, OutTotal: 500,
			Conns: []model.Conn{{PID: 222, Endpoint: model.Endpoint{IP: "10.0.0.2", Port: 8080}, Proto: "tcp", OutRate: 50}}},
	}
	groups := Aggregate(insts, map[string][]uint64{"/usr/local/bin/node": {100}, "/opt/x/node": {50}}, nil)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (different binary paths must NOT collapse)", len(groups))
	}
	byPath := map[string]model.EgressGroup{}
	for _, g := range groups {
		byPath[g.Path] = g
	}
	a, okA := byPath["/usr/local/bin/node"]
	b, okB := byPath["/opt/x/node"]
	if !okA || !okB {
		t.Fatalf("expected one group per distinct path, got %+v", groups)
	}
	if a.Instances != 1 || b.Instances != 1 {
		t.Fatalf("each distinct-path group should hold one instance: %d / %d", a.Instances, b.Instances)
	}
	if a.Trust != "unsigned" || b.Trust != "notarized" {
		t.Fatalf("per-group trust wrong: %q / %q", a.Trust, b.Trust)
	}
	if a.OutRate != 100 || b.OutRate != 50 {
		t.Fatalf("per-group rate wrong: %d / %d", a.OutRate, b.OutRate)
	}
	if a.Members[0].PID != 111 || b.Members[0].PID != 222 {
		t.Fatalf("members not attributed to the right path-group: %+v", groups)
	}
}

func TestAggregate_InSpark(t *testing.T) {
	insts := []Instance{{PID: 1, App: "x", Path: "/x", OutRate: 10, InRate: 40}}
	spark := map[string][]uint64{"/x": {1, 2, 3}}
	inSpark := map[string][]uint64{"/x": {7, 8, 9}}
	g := Aggregate(insts, spark, inSpark)[0]
	if g.InRate != 40 {
		t.Fatalf("in-rate must aggregate, got %d", g.InRate)
	}
	if len(g.InSpark) != 3 || g.InSpark[2] != 9 {
		t.Fatalf("in-history must attach to the group, got %v", g.InSpark)
	}
}
