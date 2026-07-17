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

// #3: sensitive HTTP header VALUES (Authorization/Cookie/API-key/*-token) are masked just like a
// bearer token — inspecting a cleartext HTTP flow must not itself spill session credentials.
func TestRedact_MasksSensitiveHeaders(t *testing.T) {
	in := "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\nCookie: session=deadbeef; a=b\r\n" +
		"X-Auth-Token: t0psecret\r\nContent-Type: application/json\r\n\r\n"
	out := Redact(in)
	for _, leak := range []string{"dXNlcjpwYXNz", "session=deadbeef", "t0psecret"} {
		if strings.Contains(out, leak) {
			t.Fatalf("secret %q leaked through Redact:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "Content-Type: application/json") {
		t.Fatalf("a non-sensitive header must NOT be masked:\n%s", out)
	}
	if !strings.Contains(out, "Host: x") {
		t.Fatalf("Host must survive:\n%s", out)
	}
}

// cp-p2c F-3: common credential FIELDS in a decoded body are masked (form + JSON), pattern-exact on
// known names — decrypted bodies flow through Redact via the intercept proxy.
func TestRedact_MasksBodyCredentialFields(t *testing.T) {
	for _, in := range []string{
		"username=alice&password=hunter2&remember=1",
		`{"user":"alice","api_key":"sk-live-ABCDEF","ok":true}`,
		`{"access_token": "ya29.SECRET", "expires": 3600}`,
	} {
		out := Redact(in)
		for _, leak := range []string{"hunter2", "sk-live-ABCDEF", "ya29.SECRET"} {
			if contains(out, leak) {
				t.Fatalf("body secret %q leaked: %s", leak, out)
			}
		}
	}
	// a non-credential field is untouched
	if out := Redact("username=alice&remember=1"); !contains(out, "alice") {
		t.Fatalf("non-secret field must survive: %s", out)
	}
}

// A BOUNDED capture cuts bodies mid-value, so masking must survive truncation. Before the dangling
// open-quote alternative, `"api_key":"sk_live_ABC` (no closing quote) matched NEITHER value branch —
// the quoted one needs a close quote, the unquoted one excludes `"` — so the whole match failed and the
// partial secret was published in the clear, to the socket and the 0600 log. This shipped, and the
// daemon writes exactly these truncated bodies. Reproduced against the live pipeline before the fix.
func TestRedact_TruncatedQuotedBodySecretIsMasked(t *testing.T) {
	full := `{"user":"jon","api_key":"sk_live_51H8xN2eKq9zTg_NOT_A_REAL_KEY"}`
	if got := Redact(full); strings.Contains(got, "sk_live") {
		t.Fatalf("baseline: a complete body must mask: %s", got)
	}
	// Cut mid-value, exactly as the capture bound does on a larger body.
	for _, cut := range []string{
		`{"user":"jon","api_key":"sk_live_51H8xN2eKq9zTg`,
		`{"user":"jon","api_key":"`,
		`{"password":"hunter2`,
		`{"access_token":"ya29.a0AfH6SM`,
	} {
		got := Redact(cut)
		if strings.Contains(got, "sk_live") || strings.Contains(got, "hunter2") || strings.Contains(got, "ya29.a0") {
			t.Fatalf("truncated secret leaked: %q -> %q", cut, got)
		}
	}
}

// The fix must not over-mask: a COMPLETE quoted value followed by more JSON still masks only the value,
// and later fields survive.
func TestRedact_DanglingRuleDoesNotSwallowLaterFields(t *testing.T) {
	got := Redact(`{"api_key":"sk_live_ABC","user":"jon","host":"example.com"}`)
	if strings.Contains(got, "sk_live_ABC") {
		t.Fatalf("secret leaked: %s", got)
	}
	for _, keep := range []string{`"user":"jon"`, `"host":"example.com"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("the dangling rule must not swallow later fields (%s missing): %s", keep, got)
		}
	}
}
