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
	groups := Aggregate(insts, map[string][]uint64{"backuptool": {600, 650, 620}})
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

func TestAggregate_CollapsesSameNameDifferentPaths(t *testing.T) {
	insts := []Instance{
		{PID: 111, App: "node", Path: "/usr/local/bin/node", Trust: "unsigned", OutRate: 100, OutTotal: 1000,
			Conns: []model.Conn{{PID: 111, Endpoint: model.Endpoint{IP: "10.0.0.1", Port: 443}, Proto: "tcp", OutRate: 100}}},
		{PID: 222, App: "node", Path: "/opt/x/node", Trust: "notarized", OutRate: 50, OutTotal: 500,
			Conns: []model.Conn{{PID: 222, Endpoint: model.Endpoint{IP: "10.0.0.2", Port: 8080}, Proto: "tcp", OutRate: 50}}},
	}
	groups := Aggregate(insts, map[string][]uint64{"node": {150}})
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (same App name must collapse)", len(groups))
	}
	g := groups[0]
	if g.Instances != 2 {
		t.Fatalf("Instances = %d, want 2", g.Instances)
	}
	if len(g.Members) != 2 {
		t.Fatalf("Members = %d, want 2", len(g.Members))
	}
	if g.OutRate != 150 {
		t.Fatalf("summed OutRate = %d, want 150", g.OutRate)
	}
	if g.Trust != "unsigned" {
		t.Fatalf("worst-case Trust = %q, want %q", g.Trust, "unsigned")
	}
	var byPID = map[int]model.EgressInstance{}
	for _, m := range g.Members {
		byPID[m.PID] = m
	}
	m1, ok1 := byPID[111]
	m2, ok2 := byPID[222]
	if !ok1 || !ok2 {
		t.Fatalf("Members missing expected PIDs: %+v", g.Members)
	}
	if m1.Path != "/usr/local/bin/node" || m2.Path != "/opt/x/node" {
		t.Fatalf("Members did not preserve distinct Paths: %+v", g.Members)
	}
	if len(m1.Conns) != 1 || m1.Conns[0].Endpoint.Port != 443 {
		t.Fatalf("Member 111 Conns wrong: %+v", m1.Conns)
	}
	if len(m2.Conns) != 1 || m2.Conns[0].Endpoint.Port != 8080 {
		t.Fatalf("Member 222 Conns wrong: %+v", m2.Conns)
	}
}
