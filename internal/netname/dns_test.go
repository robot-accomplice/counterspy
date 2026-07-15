package netname

import (
	"encoding/binary"
	"testing"
)

// --- DNS message builders (hand-rolled so the fixtures are unambiguous) ---

func encodeName(s string) []byte {
	var b []byte
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, s[start:i]...)
			start = i + 1
		}
	}
	return append(b, 0) // root label
}

// dnsMsg builds a response (QR=1) with one question and the given answer records. `answers` are raw
// RR bytes built by aRec/cnameRec (owner is a compression pointer to the question at offset 12).
func dnsMsg(qname string, qr bool, answers ...[]byte) []byte {
	var h [12]byte
	if qr {
		binary.BigEndian.PutUint16(h[2:4], 0x8180)
	}
	binary.BigEndian.PutUint16(h[4:6], 1)                    // QDCOUNT
	binary.BigEndian.PutUint16(h[6:8], uint16(len(answers))) // ANCOUNT
	msg := append([]byte{}, h[:]...)
	msg = append(msg, encodeName(qname)...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE=A QCLASS=IN
	for _, a := range answers {
		msg = append(msg, a...)
	}
	return msg
}

func rr(rrType uint16, rdata []byte) []byte {
	b := []byte{0xC0, 0x0C} // owner = pointer to the question name at offset 12
	var t [10]byte
	binary.BigEndian.PutUint16(t[0:2], rrType)
	binary.BigEndian.PutUint16(t[2:4], 1)   // CLASS IN
	binary.BigEndian.PutUint32(t[4:8], 300) // TTL
	binary.BigEndian.PutUint16(t[8:10], uint16(len(rdata)))
	return append(append(b, t[:]...), rdata...)
}

func aRec(ip [4]byte) []byte        { return rr(1, ip[:]) }
func aaaaRec(ip [16]byte) []byte    { return rr(28, ip[:]) }
func cnameRec(target string) []byte { return rr(5, encodeName(target)) }

func TestParseDNSResponse_SingleA(t *testing.T) {
	recs, ok := ParseDNSResponse(dnsMsg("example.com", true, aRec([4]byte{93, 184, 216, 34})))
	if !ok || len(recs) != 1 || recs[0].Name != "example.com" || recs[0].IP.String() != "93.184.216.34" {
		t.Fatalf("single A: %+v ok=%v", recs, ok)
	}
}

func TestParseDNSResponse_MultiAandAAAA(t *testing.T) {
	msg := dnsMsg("cdn.example.com", true,
		aRec([4]byte{1, 1, 1, 1}), aRec([4]byte{1, 1, 1, 2}),
		aaaaRec([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}))
	recs, ok := ParseDNSResponse(msg)
	if !ok || len(recs) != 3 {
		t.Fatalf("expected 3 records, got %+v ok=%v", recs, ok)
	}
	for _, r := range recs {
		if r.Name != "cdn.example.com" {
			t.Fatalf("every answer attributes to the queried name, got %q", r.Name)
		}
	}
	if recs[2].IP.String() != "2001:db8::1" {
		t.Fatalf("AAAA decode wrong: %v", recs[2].IP)
	}
}

func TestParseDNSResponse_CNAMEChainAttributesToQueriedName(t *testing.T) {
	// query www.x.com → CNAME x.cdn.net → A 203.0.113.5. The A must be attributed to www.x.com.
	msg := dnsMsg("www.x.com", true, cnameRec("x.cdn.net"), aRec([4]byte{203, 0, 113, 5}))
	recs, ok := ParseDNSResponse(msg)
	if !ok || len(recs) != 1 || recs[0].Name != "www.x.com" || recs[0].IP.String() != "203.0.113.5" {
		t.Fatalf("CNAME chain must map the A to the queried name: %+v ok=%v", recs, ok)
	}
}

func TestParseDNSResponse_Rejects(t *testing.T) {
	if _, ok := ParseDNSResponse(dnsMsg("x.com", false, aRec([4]byte{1, 2, 3, 4}))); ok {
		t.Fatal("a query (QR=0) must be rejected")
	}
	if _, ok := ParseDNSResponse([]byte{1, 2, 3}); ok {
		t.Fatal("a message shorter than the header must be rejected")
	}
}

func TestParseDNSResponse_ToleratesTruncation(t *testing.T) {
	full := dnsMsg("x.com", true, aRec([4]byte{9, 9, 9, 9}), aRec([4]byte{8, 8, 8, 8}))
	// Chop mid-second-answer: header + question + first answer valid, tail garbage.
	recs, ok := ParseDNSResponse(full[:len(full)-3])
	if !ok {
		t.Fatal("a valid header + first answer should still parse")
	}
	if len(recs) != 1 || recs[0].IP.String() != "9.9.9.9" {
		t.Fatalf("should return the parseable prefix, got %+v", recs)
	}
}

func TestParseName_PointerLoopIsBounded(t *testing.T) {
	// A name at offset 12 that points to itself must not spin forever.
	msg := make([]byte, 14)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg[12], msg[13] = 0xC0, 0x0C // pointer → offset 12 (itself)
	if _, ok := ParseDNSResponse(msg); ok {
		// ok may be false; the point is it returns, not hangs. Reaching here = no infinite loop.
	}
}
