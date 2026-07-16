//go:build darwin

package intercept

import (
	"testing"
	"time"
)

// Real `lsof -Fpcn` shape: p/c set the current process, each n line is one of its sockets. We key on the
// LOCAL side (before ->) — the client's ephemeral port, which is what conn.RemoteAddr() reports to us.
const lsofFixture = `p73722
cSafari
n127.0.0.1:54321->127.0.0.1:62443
n192.168.1.9:51000->93.184.216.34:443
p85908
ccounterspy
n127.0.0.1:62443->127.0.0.1:54321
p600
cmDNSResponder
n*:5353
`

func TestParseLsofPorts_AttributesTheClientSide(t *testing.T) {
	m := parseLsofPorts(lsofFixture, 85908) // 85908 = "us"
	e, ok := m[54321]
	if !ok {
		t.Fatalf("client ephemeral port not attributed: %v", m)
	}
	if e.pid != 73722 || e.name != "Safari" {
		t.Fatalf("expected Safari/73722, got %+v", e)
	}
	if _, ok := m[51000]; !ok {
		t.Fatal("a process's other sockets should also map by local port")
	}
}

// The proxy holds the OTHER end of every client socket, so an unfiltered sweep would attribute half the
// flows to counterspy itself. Our own pid must be excluded.
func TestParseLsofPorts_ExcludesOurselves(t *testing.T) {
	m := parseLsofPorts(lsofFixture, 85908)
	for port, e := range m {
		if e.pid == 85908 || e.name == "counterspy" {
			t.Fatalf("our own socket must not be attributed (port %d -> %+v)", port, e)
		}
	}
	if _, ok := m[62443]; ok {
		t.Fatal("our listening port must not appear as a client")
	}
}

// A listening socket (no ->) is not a connection and must not be mapped.
func TestParseLsofPorts_SkipsListeners(t *testing.T) {
	if _, ok := parseLsofPorts(lsofFixture, 0)[5353]; ok {
		t.Fatal("a listening socket must not be attributed as a connection")
	}
}

// portOwner reports ok=false for an unknown port so the caller publishes the flow unattributed rather
// than dropping it.
func TestPortOwner_UnknownPortIsNotFatal(t *testing.T) {
	orig := runLsof
	t.Cleanup(func() { runLsof = orig; ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{} })
	runLsof = func() (string, error) { return lsofFixture, nil }
	ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}

	if pid, name, ok := portOwner(54321); !ok || pid != 73722 || name != "Safari" {
		t.Fatalf("known port: got %d/%q/%v", pid, name, ok)
	}
	if _, _, ok := portOwner(9999); ok {
		t.Fatal("an unknown port must report ok=false, not a wrong attribution")
	}
}

// The sweep is cached: a burst of lookups must not fork lsof per flow.
func TestPortOwner_SweepIsCached(t *testing.T) {
	orig := runLsof
	t.Cleanup(func() { runLsof = orig; ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{} })
	sweeps := 0
	runLsof = func() (string, error) { sweeps++; return lsofFixture, nil }
	ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}
	for i := 0; i < 20; i++ {
		portOwner(54321) // all hits
	}
	if sweeps != 1 {
		t.Fatalf("a hit must reuse the snapshot; swept %d times", sweeps)
	}
}
