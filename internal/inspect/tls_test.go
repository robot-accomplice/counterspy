package inspect

import (
	"encoding/binary"
	"testing"
)

func u16(n int) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(n)); return b }
func u24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }

// buildClientHello assembles a minimal valid TLS ClientHello record carrying an SNI extension.
func buildClientHello(sni string) []byte {
	name := []byte(sni)
	entry := append([]byte{0x00}, u16(len(name))...) // name_type host_name + name_len
	entry = append(entry, name...)
	sniBody := append(u16(len(entry)), entry...)            // server_name_list_len + entry
	ext := append([]byte{0x00, 0x00}, u16(len(sniBody))...) // ext type 0 + ext_len
	ext = append(ext, sniBody...)

	hs := append([]byte{0x03, 0x03}, make([]byte, 32)...) // version + random
	hs = append(hs, 0x00)                                 // session_id len 0
	hs = append(hs, 0x00, 0x02, 0x13, 0x01)               // cipher_suites len 2 + one suite
	hs = append(hs, 0x01, 0x00)                           // compression len 1 + null
	hs = append(hs, u16(len(ext))...)                     // extensions total len
	hs = append(hs, ext...)

	body := append([]byte{0x01}, u24(len(hs))...) // handshake type client_hello + len
	body = append(body, hs...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(body))...) // record: handshake + version + len
	return append(rec, body...)
}

func TestClientHelloSNI_Extracts(t *testing.T) {
	rec := buildClientHello("api.evil.example.com")
	got, ok := ClientHelloSNI(rec)
	if !ok || got != "api.evil.example.com" {
		t.Fatalf("SNI: got (%q,%v), want (api.evil.example.com,true)", got, ok)
	}
}

func TestClientHelloSNI_RejectsNonClientHello(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x17, 0x03, 0x03, 0x00, 0x05}, // application_data record, not handshake
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0, 0, 0}, // handshake but msg_type 0x02 (server_hello)
		buildClientHello("x")[:8],                     // truncated mid-handshake
	}
	for i, c := range cases {
		if _, ok := ClientHelloSNI(c); ok {
			t.Errorf("case %d: expected no SNI from non-ClientHello/truncated input", i)
		}
	}
}

// A ClientHello with no SNI extension (e.g. an IP-literal connection) yields no host.
func TestClientHelloSNI_NoExtension(t *testing.T) {
	hs := append([]byte{0x03, 0x03}, make([]byte, 32)...)
	hs = append(hs, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	hs = append(hs, 0x00, 0x00) // extensions len 0
	body := append([]byte{0x01}, u24(len(hs))...)
	body = append(body, hs...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(body))...)
	rec = append(rec, body...)
	if host, ok := ClientHelloSNI(rec); ok {
		t.Fatalf("no-SNI ClientHello should return false, got %q", host)
	}
}
