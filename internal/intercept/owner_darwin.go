//go:build darwin

package intercept

/*
#include <libproc.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// procPidPath resolves the executable path of pid using proc_pidpath(3).
// It is a package var so tests can inject a fake.
var procPidPath = func(pid int) (string, bool) {
	var buf [4096]byte
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return "", false
	}
	end := int(n)
	for i := 0; i < end; i++ {
		if buf[i] == 0 {
			end = i
			break
		}
	}
	return string(buf[:end]), true
}

// Attribution: which APP made this request?
//
// A CONNECT arrives from 127.0.0.1:<ephemeral>. That local port belongs to the client process, so a
// port→process map answers "who sent this" — the question the whole tool is organised around ("this app
// is trusted; what is it sending?"). Without it an intercepted flow names a destination but not an
// originator, and model.InterceptedFlow.PID stays the dead field it has been since cp-p2a.
//
// lsof is the mechanism because internal/egress already attributes flows that way (Rule 12: match the
// codebase). It is a subprocess, so it is SNAPSHOT-CACHED rather than run per connection: a busy machine
// opens many flows a second and a fork per flow would dominate the proxy's cost.

const (
	// ownerTTL is how long a port→process snapshot is reused before a sweep is considered stale.
	ownerTTL = 2 * time.Second
	// ownerMinRefresh throttles miss-driven sweeps: a brand-new connection legitimately postdates the
	// snapshot, but a burst of them must not fork lsof once per flow.
	ownerMinRefresh = 250 * time.Millisecond
	// lsofTimeout bounds the sweep so a wedged lsof can't stall the proxy's accept path.
	lsofTimeout = 5 * time.Second
)

type ownerEntry struct {
	pid  int
	name string
	path string // executable path from proc_pidpath
}

var (
	ownerMu   sync.Mutex
	ownerMap  map[int]ownerEntry
	ownerAt   time.Time
	ownerLast time.Time // last sweep attempt, for the miss throttle
)

// runLsof is the seam over the lsof sweep, so attribution is unit-testable without the real tool.
// -n/-P skip DNS/port-name resolution (fast, and no lookups of the user's traffic); -FpcnT is the
// machine-readable field format; ESTABLISHED-only keeps the sweep to live connections.
var runLsof = func() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lsofTimeout)
	defer cancel()
	// lsof exits non-zero when it finds nothing; treat output as authoritative and ignore that.
	out, _ := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-Fpcn").Output()
	return string(out), nil
}

// selfPID is our own pid, excluded from the map: the proxy holds the OTHER end of every client socket,
// so an unfiltered sweep would attribute half the flows to counterspy itself.
var selfPID = os.Getpid()

// parseLsofPorts turns `lsof -Fpcn` output into a local-port → process map.
//
// The format is a stream of records: `p<pid>` and `c<command>` set the current process, then each
// `n<local>-><remote>` line is one of its sockets. We key on the LOCAL side, which for a client
// connecting to us is its ephemeral port — the value conn.RemoteAddr() reports to the proxy.
func parseLsofPorts(out string, self int) map[int]ownerEntry {
	m := map[int]ownerEntry{}
	cur := ownerEntry{}
	for _, ln := range strings.Split(out, "\n") {
		if len(ln) < 2 {
			continue
		}
		switch ln[0] {
		case 'p':
			cur = ownerEntry{}
			if pid, err := strconv.Atoi(ln[1:]); err == nil {
				cur.pid = pid
			}
		case 'c':
			cur.name = ln[1:]
		case 'n':
			if cur.pid == 0 || cur.pid == self {
				continue // unattributed, or our own end of the client's socket
			}
			local, _, ok := strings.Cut(ln[1:], "->")
			if !ok {
				continue // a listening socket, not a connection
			}
			if port, ok := portOf(local); ok {
				m[port] = cur
			}
		}
	}
	return m
}

// portOf extracts the port from an lsof address ("127.0.0.1:54321", "[::1]:54321", "*:443").
func portOf(addr string) (int, bool) {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0, false
	}
	p, err := strconv.Atoi(addr[i+1:])
	if err != nil || p <= 0 {
		return 0, false
	}
	return p, true
}

// portOwner reports the process owning local TCP port `port`. ok=false when it can't be attributed —
// the caller must show the flow anyway, unattributed, rather than drop it (Rule 13: a flow we can't
// name is still a flow the user needs to see).
func portOwner(port int) (pid int, name string, path string, ok bool) {
	ownerMu.Lock()
	defer ownerMu.Unlock()
	if ownerMap == nil || time.Since(ownerAt) > ownerTTL {
		sweepOwners()
	}
	if e, ok := ownerMap[port]; ok {
		return e.pid, e.name, e.path, true
	}
	// A miss is expected for a connection newer than the snapshot — re-sweep, but throttled so a burst
	// of new flows can't fork lsof per flow.
	if time.Since(ownerLast) > ownerMinRefresh {
		sweepOwners()
		if e, ok := ownerMap[port]; ok {
			return e.pid, e.name, e.path, true
		}
	}
	return 0, "", "", false
}

// sweepOwners refreshes the snapshot. Caller holds ownerMu. A failed sweep keeps the previous map
// (stale attribution beats none) and still stamps ownerLast so the throttle holds.
func sweepOwners() {
	ownerLast = time.Now()
	out, err := runLsof()
	if err != nil {
		return
	}
	if m := parseLsofPorts(out, selfPID); len(m) > 0 || ownerMap == nil {
		for port, e := range m {
			if p, ok := procPidPath(e.pid); ok {
				e.path = p
			}
			m[port] = e
		}
		ownerMap, ownerAt = m, time.Now()
	}
}
