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
