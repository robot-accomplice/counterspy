//go:build darwin

package intercept

import (
	"testing"
	"time"
)

// Real `lsof -Fpcn` shape: p/c set the current process, each n line is one of its sockets. We key on the
// LOCAL side (before ->), the client's ephemeral port, which is what conn.RemoteAddr() reports to us.
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
// IPv6 attribution regression: the CONNECT pivot replaced the IPv4-only pf `OrigDest`/DIOCNATLOOK path,
// and owner attribution is now purely port-based. portOf reads the port after the FINAL colon, so a
// bracketed IPv6 lsof line attributes correctly and a v6 flow is NOT left unattributed. This locks in
// that the stale v0.7.0 "IPv6 original-destination" deferral is obsolete, not an open gap.
func TestParseLsofPorts_AttributesIPv6ClientSide(t *testing.T) {
	fixture := "p42000\ncchrome\nn[2001:db8::1]:55555->[2001:db8::2]:443\n"
	m := parseLsofPorts(fixture, 85908)
	e, ok := m[55555]
	if !ok {
		t.Fatalf("IPv6 client port not attributed (v6 flows would show unattributed): %v", m)
	}
	if e.pid != 42000 || e.name != "chrome" {
		t.Fatalf("expected chrome/42000 for the v6 flow, got %+v", e)
	}
}

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
	origProcPidPath := procPidPath
	t.Cleanup(func() {
		runLsof = orig
		procPidPath = origProcPidPath
		ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}
	})
	runLsof = func() (string, error) { return lsofFixture, nil }
	procPidPath = func(pid int) (string, bool) {
		if pid == 73722 {
			return "/Applications/Safari.app/Contents/MacOS/Safari", true
		}
		return "", false
	}
	ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}

	pid, name, path, ok := portOwner(54321)
	if !ok || pid != 73722 || name != "Safari" || path != "/Applications/Safari.app/Contents/MacOS/Safari" {
		t.Fatalf("known port: got %d/%q/%q/%v", pid, name, path, ok)
	}
	if _, _, _, ok := portOwner(9999); ok {
		t.Fatal("an unknown port must report ok=false, not a wrong attribution")
	}
}

// The sweep is cached: a burst of lookups must not fork lsof per flow.
func TestPortOwner_SweepIsCached(t *testing.T) {
	orig := runLsof
	origProcPidPath := procPidPath
	t.Cleanup(func() {
		runLsof = orig
		procPidPath = origProcPidPath
		ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}
	})
	sweeps := 0
	runLsof = func() (string, error) { sweeps++; return lsofFixture, nil }
	procPidPath = func(pid int) (string, bool) { return "/some/path", true }
	ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}
	for i := 0; i < 20; i++ {
		portOwner(54321) // all hits
	}
	if sweeps != 1 {
		t.Fatalf("a hit must reuse the snapshot; swept %d times", sweeps)
	}
}

// procPidPath failures degrade to path="" rather than losing the attribution.
func TestPortOwner_PathFallback(t *testing.T) {
	orig := runLsof
	origProcPidPath := procPidPath
	t.Cleanup(func() {
		runLsof = orig
		procPidPath = origProcPidPath
		ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}
	})
	runLsof = func() (string, error) { return lsofFixture, nil }
	procPidPath = func(int) (string, bool) { return "", false }
	ownerMap, ownerAt, ownerLast = nil, time.Time{}, time.Time{}

	pid, name, path, ok := portOwner(54321)
	if !ok || pid != 73722 || name != "Safari" || path != "" {
		t.Fatalf("expected pid/name with empty path fallback, got %d/%q/%q/%v", pid, name, path, ok)
	}
}
