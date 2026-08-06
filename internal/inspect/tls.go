// Package inspect is the "what is it sending?" layer above the Exfiltration view: it
// captures a single selected outbound flow and surfaces what's visible per the tiered
// interceptor (spec docs/superpowers/specs/2026-07-12-exfil-inspect-interceptor.md).
// The parsers here are PURE (fixture-tested); packet capture is the injected I/O edge.
// Observe-only; nothing here changes scoring or verdicts.
package inspect

import "encoding/binary"

// ClientHelloSNI extracts the Server Name Indication (the plaintext hostname) from a TLS
// ClientHello handshake record. On an otherwise-encrypted flow this is the single most useful
// field: it names WHICH server the connection is talking to. Returns ("", false) when the bytes
// are not a ClientHello carrying an SNI extension. Deliberately tolerant of truncation/garbage
// (attacker-influenced bytes): every length is bounds-checked before use.
func ClientHelloSNI(rec []byte) (string, bool) {
	// TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
	if len(rec) < 5 || rec[0] != 0x16 {
		return "", false
	}
	body := rec[5:]
	// Handshake header: msg_type(1)=0x01 client_hello, length(3).
	if len(body) < 4 || body[0] != 0x01 {
		return "", false
	}
	hs := body[4:]
	// client_version(2) + random(32).
	if len(hs) < 34 {
		return "", false
	}
	p := 34
	// session_id: len(1) + bytes.
	if p >= len(hs) {
		return "", false
	}
	p += 1 + int(hs[p])
	// cipher_suites: len(2) + bytes.
	if p+2 > len(hs) {
		return "", false
	}
	p += 2 + int(binary.BigEndian.Uint16(hs[p:]))
	// compression_methods: len(1) + bytes.
	if p+1 > len(hs) {
		return "", false
	}
	p += 1 + int(hs[p])
	// extensions: total_len(2) + extensions.
	if p+2 > len(hs) {
		return "", false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(hs[p:]))
	p += 2
	if end > len(hs) {
		end = len(hs)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(hs[p:])
		elen := int(binary.BigEndian.Uint16(hs[p+2:]))
		p += 4
		if p+elen > end {
			return "", false
		}
		if etype == 0x0000 { // server_name
			return parseSNIExtension(hs[p : p+elen])
		}
		p += elen
	}
	return "", false
}

// parseSNIExtension reads the first host_name (name_type 0) from a server_name extension body:
// server_name_list_len(2), then entries of name_type(1) + name_len(2) + name.
func parseSNIExtension(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	p := 2
	for p+3 <= len(b) {
		nameType := b[p]
		nameLen := int(binary.BigEndian.Uint16(b[p+1:]))
		p += 3
		if p+nameLen > len(b) {
			return "", false
		}
		if nameType == 0x00 {
			return string(b[p : p+nameLen]), true
		}
		p += nameLen
	}
	return "", false
}

// ClientHelloALPN extracts the Application-Layer Protocol Negotiation list from
// a TLS ClientHello handshake record. Returns the ordered protocol names and
// true when the ClientHello carries an ALPN extension. Like ClientHelloSNI, it
// is deliberately tolerant of truncation/garbage.
func ClientHelloALPN(rec []byte) ([]string, bool) {
	// Walk to the extensions block using the same parser as ClientHelloSNI.
	if len(rec) < 5 || rec[0] != 0x16 {
		return nil, false
	}
	body := rec[5:]
	if len(body) < 4 || body[0] != 0x01 {
		return nil, false
	}
	hs := body[4:]
	if len(hs) < 34 {
		return nil, false
	}
	p := 34
	if p >= len(hs) {
		return nil, false
	}
	p += 1 + int(hs[p])
	if p+2 > len(hs) {
		return nil, false
	}
	p += 2 + int(binary.BigEndian.Uint16(hs[p:]))
	if p+1 > len(hs) {
		return nil, false
	}
	p += 1 + int(hs[p])
	if p+2 > len(hs) {
		return nil, false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(hs[p:]))
	p += 2
	if end > len(hs) {
		end = len(hs)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(hs[p:])
		elen := int(binary.BigEndian.Uint16(hs[p+2:]))
		p += 4
		if p+elen > end {
			return nil, false
		}
		if etype == 0x0010 { // application_layer_protocol_negotiation
			return parseALPNExtension(hs[p : p+elen])
		}
		p += elen
	}
	return nil, false
}

// parseALPNExtension reads protocol names from an ALPN extension body:
// protocol_list_len(2), then entries of len(1) + protocol.
func parseALPNExtension(b []byte) ([]string, bool) {
	if len(b) < 2 {
		return nil, false
	}
	listLen := int(binary.BigEndian.Uint16(b))
	if listLen > len(b)-2 {
		return nil, false
	}
	p := 2
	var out []string
	for p+1 <= 2+listLen {
		plen := int(b[p])
		p++
		if p+plen > 2+listLen {
			return nil, false
		}
		out = append(out, string(b[p:p+plen]))
		p += plen
	}
	return out, len(out) > 0
}
