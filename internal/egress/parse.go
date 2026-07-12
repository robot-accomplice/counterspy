// Package egress observes per-application outbound traffic via sudo-CLI polling (nettop +
// lsof), joins trust/provenance/capability from internal/collect, and scores concern and
// exfiltration-risk — all pure given inputs. Observe-only; no payloads are read.
package egress

import (
	"net/netip"
	"strconv"
	"strings"

	"counterspy/internal/model"
)

// Bytes is a cumulative byte counter pair from nettop.
type Bytes struct{ Out, In uint64 }

// ParseNettop parses `nettop -P -L 1 -x -J bytes_in,bytes_out` CSV into per-PID cumulative
// bytes. The process column is "name.pid"; byte columns are located by header name so a
// column-order change doesn't silently misread.
func ParseNettop(b []byte) map[int]Bytes {
	out := map[int]Bytes{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	header := strings.Split(lines[0], ",")
	inCol, outCol := -1, -1
	for i, h := range header {
		switch strings.TrimSpace(h) {
		case "bytes_in":
			inCol = i
		case "bytes_out":
			outCol = i
		}
	}
	for _, ln := range lines[1:] {
		f := strings.Split(ln, ",")
		if len(f) <= outCol || len(f) <= inCol || outCol < 0 || inCol < 0 {
			continue
		}
		pid := pidFromNameDotPid(f)
		if pid == 0 {
			continue
		}
		o, _ := strconv.ParseUint(strings.TrimSpace(f[outCol]), 10, 64)
		in, _ := strconv.ParseUint(strings.TrimSpace(f[inCol]), 10, 64)
		g := out[pid]
		g.Out += o
		g.In += in
		out[pid] = g
	}
	return out
}

// pidFromNameDotPid finds the "name.pid" field and returns the trailing pid. A timestamp
// column (e.g. "15:04:05.123456") also ends in ".<int>", so fields whose pre-dot portion
// contains a ':' are skipped — otherwise the microseconds would be misread as a PID.
func pidFromNameDotPid(fields []string) int {
	for _, f := range fields {
		f = strings.TrimSpace(f)
		dot := strings.LastIndex(f, ".")
		if dot <= 0 {
			continue
		}
		if strings.ContainsRune(f[:dot], ':') {
			continue // a timestamp, not name.pid
		}
		if pid, err := strconv.Atoi(f[dot+1:]); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

// ParseLsofConns parses `lsof -i -nP` into per-PID ESTABLISHED outbound connections. A row
// is egress only if its NAME has a "->remote" peer; LISTEN sockets (no "->") are skipped.
func ParseLsofConns(b []byte) map[int][]model.Conn {
	out := map[int][]model.Conn{}
	seen := map[string]bool{} // (proto+pid+remote) → dedup FDs to the same destination
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(ln)
		if len(f) < 9 {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		proto := strings.ToLower(f[7]) // NODE column: TCP/UDP
		if proto != "tcp" && proto != "udp" {
			continue
		}
		name := f[8]
		arrow := strings.Index(name, "->")
		if arrow < 0 {
			continue // LISTEN / no remote peer — not egress
		}
		remote := name[arrow+2:]
		if sp := strings.IndexByte(remote, ' '); sp >= 0 {
			remote = remote[:sp] // strip " (ESTABLISHED)"
		}
		ip, port := splitHostPort(remote)
		if ip == "" {
			continue
		}
		ip = canonIP(ip)
		// Collapse the several TCP FDs a process may hold to the SAME remote endpoint into one
		// logical "connection to R" — the exfil view cares about the destination, and nettop
		// aggregates per-destination bytes anyway (avoids duplicate rows sharing one rate).
		k := proto + "|" + connKey(pid, ip, port)
		if seen[k] {
			continue
		}
		seen[k] = true
		out[pid] = append(out[pid], model.Conn{PID: pid, Endpoint: model.Endpoint{IP: ip, Port: port}, Proto: proto})
	}
	return out
}

// ParsePidPaths parses `ps -axo pid=,comm=` — one "PID /full/executable path" per line — into
// a pid→path map. `comm` is the executable path with NO argv, so the path (which on macOS is
// riddled with spaces, e.g. ".../Application Support/...") is everything after the leading pid;
// this avoids the space-splitting that collapsed spaced paths to "Application".
func ParsePidPaths(b []byte) map[int]string {
	out := map[int]string{}
	for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		ln = strings.TrimLeft(ln, " ")
		sp := strings.IndexByte(ln, ' ')
		if sp <= 0 {
			continue
		}
		pid, err := strconv.Atoi(ln[:sp])
		if err != nil {
			continue
		}
		if path := strings.TrimSpace(ln[sp+1:]); path != "" {
			out[pid] = path
		}
	}
	return out
}

// splitHostPort splits "IP:port" from the right so IPv6 (which contains colons) keeps its host.
func splitHostPort(s string) (string, int) {
	c := strings.LastIndex(s, ":")
	if c < 0 {
		return "", 0
	}
	port, _ := strconv.Atoi(s[c+1:])
	return s[:c], port
}

// connKey identifies a connection by owning PID + remote endpoint, used to correlate nettop's
// per-connection byte counts with the lsof-discovered connection list (and to key per-conn
// rate/spark history in the Monitor). The IP is canonicalized (canonIP) so nettop's and lsof's
// differing IPv6 spellings key the same.
func connKey(pid int, ip string, port int) string {
	return strconv.Itoa(pid) + "|" + canonIP(ip) + "|" + strconv.Itoa(port)
}

// canonIP normalizes an IP so the same address keys identically regardless of tool spelling —
// lsof's bracketed "[fe80::1]" vs nettop's zoned "fe80::1%en0". net/netip does the real work:
// parse, drop the %zone scope id, and re-render canonically. A non-IP (e.g. a hostname) passes
// through untouched.
func canonIP(ip string) string {
	ip = strings.Trim(ip, "[]")
	if a, err := netip.ParseAddr(ip); err == nil {
		return a.WithZone("").String()
	}
	return ip
}

// parseNettopEndpoint splits a nettop endpoint into (canonical ip, port). nettop spells IPv4 as
// "a.b.c.d:port" (which netip.ParseAddrPort reads directly) but IPv6 as "addr%zone.port" — a DOT
// before the port — which no standard parser accepts, so we peel the port and hand the address
// to netip.ParseAddr (which understands the %zone). Returns ("",0) for a non-endpoint (e.g. "*:*").
func parseNettopEndpoint(s string) (string, int) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil { // IPv4 "ip:port" (and bracketed IPv6)
		return ap.Addr().WithZone("").String(), int(ap.Port())
	}
	dot := strings.LastIndex(s, ".") // IPv6 "addr[%zone].port"
	if dot < 0 {
		return "", 0
	}
	port, err := strconv.Atoi(s[dot+1:])
	if err != nil {
		return "", 0
	}
	a, err := netip.ParseAddr(s[:dot])
	if err != nil {
		return "", 0
	}
	return a.WithZone("").String(), port
}

// ParseNettopConns parses the hierarchical (non -P) `nettop -x -J bytes_in,bytes_out` output
// into per-connection cumulative bytes keyed by connKey. A process row ("name.pid,...") sets
// the current PID; the connection sub-rows that follow ("proto src<->dst,in,out") are
// attributed to it. Only rows with a real remote endpoint (a "<->" with a numeric host, not
// "*:*") are kept. Byte columns are located by header name.
func ParseNettopConns(b []byte) map[string]Bytes {
	out := map[string]Bytes{}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) < 2 {
		return out
	}
	header := strings.Split(lines[0], ",")
	inCol, outCol := -1, -1
	for i, h := range header {
		switch strings.TrimSpace(h) {
		case "bytes_in":
			inCol = i
		case "bytes_out":
			outCol = i
		}
	}
	if inCol < 0 || outCol < 0 {
		return out
	}
	curPID := 0
	for _, ln := range lines[1:] {
		f := strings.Split(ln, ",")
		if len(f) <= outCol || len(f) <= inCol {
			continue
		}
		if pid := pidFromNameDotPid(f); pid != 0 {
			curPID = pid // process row — establishes the owner for the sub-rows that follow
			continue
		}
		if curPID == 0 {
			continue // a connection row before any process row — unattributable
		}
		// Find the connection descriptor ("proto src<->dst") by scanning fields, not assuming
		// f[0] — some nettop invocations prepend a timestamp column (matches ParseNettop).
		name := ""
		for _, fld := range f {
			if strings.Contains(fld, "<->") {
				name = strings.TrimSpace(fld)
				break
			}
		}
		arrow := strings.Index(name, "<->")
		if arrow < 0 {
			continue
		}
		ip, port := parseNettopEndpoint(name[arrow+3:])
		if ip == "" || ip == "*" {
			continue // no real remote (e.g. a listener "*:*")
		}
		o, _ := strconv.ParseUint(strings.TrimSpace(f[outCol]), 10, 64)
		in, _ := strconv.ParseUint(strings.TrimSpace(f[inCol]), 10, 64)
		k := connKey(curPID, ip, port)
		g := out[k]
		g.Out += o
		g.In += in
		out[k] = g
	}
	return out
}
