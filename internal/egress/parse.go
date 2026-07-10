// Package egress observes per-application outbound traffic via sudo-CLI polling (nettop +
// lsof), joins trust/provenance/capability from internal/collect, and scores concern and
// exfiltration-risk — all pure given inputs. Observe-only; no payloads are read.
package egress

import (
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
	if len(lines) == 0 {
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

// pidFromNameDotPid finds the "name.pid" field and returns the trailing pid, else 0.
func pidFromNameDotPid(fields []string) int {
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if dot := strings.LastIndex(f, "."); dot > 0 {
			if pid, err := strconv.Atoi(f[dot+1:]); err == nil {
				return pid
			}
		}
	}
	return 0
}

// ParseLsofConns parses `lsof -i -nP` into per-PID ESTABLISHED outbound connections. A row
// is egress only if its NAME has a "->remote" peer; LISTEN sockets (no "->") are skipped.
func ParseLsofConns(b []byte) map[int][]model.Conn {
	out := map[int][]model.Conn{}
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
		out[pid] = append(out[pid], model.Conn{PID: pid, Endpoint: model.Endpoint{IP: ip, Port: port}, Proto: proto})
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
