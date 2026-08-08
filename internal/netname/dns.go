// Package netname turns passively-observed DNS into a destination IP→hostname map, so the egress
// monitor can show the name an app actually resolved instead of a bare cloud IP (issue #3). It does
// no active lookups: it only parses DNS RESPONSES seen on the wire, and is deliberately tolerant of
// truncation/garbage (a hostile or partial packet must never panic or block the observer).
package netname

import (
	"encoding/binary"
	"net/netip"
)

// Record is one resolved answer: an address the response returned, attributed to the QUERIED name
// (not the answer RR's owner). Attributing to the question name is what the caller wants ("this IP
// is the app's `analytics.example.com`") and it transparently handles CNAME chains without walking
// them (the A/AAAA at the end of a chain still belongs, for our purposes, to the queried name).
type Record struct {
	Name string
	IP   netip.Addr
}

const (
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	maxNameJumps = 32 // bound compression-pointer following so a crafted loop can't spin forever
	maxLabels    = 128
)

// ParseDNSResponse extracts (queried name → answer IP) records from a DNS message. ok is false for a
// query (QR=0), a message too short to hold a header, or one that doesn't have exactly one question.
// It never returns an error: an answer RR it can't parse is skipped, and it returns whatever valid
// records it gathered.
//
// Trust model (Audit cp-p1a F-1): this is PASSIVE observation of whatever DNS crosses the wire. It
// issues no queries, so it cannot correlate a response to a request (there is no request of ours to
// match). A party able to inject DNS responses onto the host's own network could therefore poison the
// name shown for an IP. That is accepted: the name is a display hint and a light-touch, corroborated
// concern nudge only (never a security decision) and anyone forging the victim's DNS is already
// on-path. Names are honest hints, not attestations.
func ParseDNSResponse(msg []byte) ([]Record, bool) {
	if len(msg) < 12 {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 { // QR bit clear → this is a query, not a response
		return nil, false
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	// Require exactly one question. We attribute every answer to THE queried name; with two questions
	// we couldn't know which answer belongs to which, so we refuse rather than mislabel an IP (Audit
	// cp-p1a F-3). Multi-question DNS is unused in practice, so this costs nothing real.
	if qd != 1 {
		return nil, false
	}

	off := 12
	queried, next, ok := parseName(msg, off)
	if !ok {
		return nil, false
	}
	off = next + 4 // skip QTYPE(2) + QCLASS(2)

	var out []Record
	for i := 0; i < an; i++ {
		_, next, ok := parseName(msg, off) // answer owner name (unused; we attribute to `queried`)
		if !ok {
			break
		}
		off = next
		if off+10 > len(msg) { // TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)
			break
		}
		rrType := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdata := off + 10
		if rdata+rdlen > len(msg) {
			break
		}
		switch rrType {
		case dnsTypeA:
			if rdlen == 4 {
				out = append(out, Record{Name: queried, IP: netip.AddrFrom4([4]byte(msg[rdata : rdata+4]))})
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				out = append(out, Record{Name: queried, IP: netip.AddrFrom16([16]byte(msg[rdata : rdata+16]))})
			}
		}
		off = rdata + rdlen
	}
	return out, true
}

// parseName decodes a DNS name starting at off, following compression pointers (0xC0). It returns
// the dotted name, the offset of the byte AFTER the name IN THE ORIGINAL STREAM (i.e. past the first
// pointer or the terminating zero), and ok. Bounds and jump/label counts are capped so a crafted
// message can't loop or read out of range.
func parseName(msg []byte, off int) (string, int, bool) {
	var name []byte
	next := -1 // offset after the name in the original stream; set once, when we first jump or end
	jumps, labels := 0, 0
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, false
		}
		b := int(msg[off])
		switch {
		case b == 0: // root label, end of name
			if next < 0 {
				next = off + 1
			}
			return string(name), next, true
		case b&0xc0 == 0xc0: // compression pointer (2 bytes)
			if off+1 >= len(msg) {
				return "", 0, false
			}
			if next < 0 {
				next = off + 2 // the stream continues after the 2-byte pointer
			}
			jumps++
			if jumps > maxNameJumps {
				return "", 0, false
			}
			off = (b&0x3f)<<8 | int(msg[off+1])
		case b&0xc0 == 0: // a label of length b
			labels++
			if labels > maxLabels || off+1+b > len(msg) {
				return "", 0, false
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, msg[off+1:off+1+b]...)
			off += 1 + b
		default: // 0x40/0x80 are reserved label types we don't handle
			return "", 0, false
		}
	}
}
