package model

import "strings"

import "testing"

func TestRedact_MasksObviousSecrets(t *testing.T) {
	cases := []struct {
		name, in, mustNotContain string
	}{
		{"bearer", "GET /v1 HTTP/1.1\r\nAuthorization: Bearer ya29.a0AfH6SMB-secretTOKEN_value\r\n", "ya29.a0AfH6SMB-secretTOKEN_value"},
		{"aws", "creds AKIAIOSFODNN7EXAMPLE end", "AKIAIOSFODNN7EXAMPLE"},
		{"pem", "key=-----BEGIN RSA PRIVATE KEY-----\nMIIabc123\n-----END RSA PRIVATE KEY-----;", "MIIabc123"},
		// A partial capture that has the BEGIN header but not yet the END must STILL mask the key
		// material after it — otherwise a segmented/partial flow leaks the secret (cp-insC Audit F-1).
		{"pem-partial", "-----BEGIN EC PRIVATE KEY-----\nMIIdanglingKEYbytes", "MIIdanglingKEYbytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			if strings.Contains(got, c.mustNotContain) {
				t.Fatalf("secret leaked through Redact: %q", got)
			}
			if !strings.Contains(got, redactMark) {
				t.Fatalf("expected a %s marker, got %q", redactMark, got)
			}
		})
	}
}

// Redaction must not chew up ordinary payload text (a masked-everything view is useless).
func TestRedact_LeavesOrdinaryTextAlone(t *testing.T) {
	in := "POST /upload HTTP/1.1\r\nHost: drop.example\r\n\r\nname=alice&file=report.pdf"
	if got := Redact(in); got != in {
		t.Fatalf("ordinary payload altered:\n in=%q\nout=%q", in, got)
	}
}

// Idempotent: masking an already-masked string changes nothing (the view may Redact repeatedly).
func TestRedact_Idempotent(t *testing.T) {
	once := Redact("Authorization: Bearer abc.def.ghi")
	if twice := Redact(once); twice != once {
		t.Fatalf("Redact not idempotent: %q -> %q", once, twice)
	}
}
