package feedback

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEgressOnly enforces the push-only invariant as CI, not memory: the feedback
// package's ONLY legitimate handling of an HTTP response body is the discard drain in
// http.go. Any non-test file that both reads a response body AND decodes something is
// letting the network speak back into program state. This keys on the dangerous
// COMBINATION rather than a specific decode spelling, so it catches both the one-line
// NewDecoder(resp.Body).Decode(...) chain and the two-step io.ReadAll(resp.Body) +
// json.Unmarshal(data, &x) idiom regardless of the intermediate variable's name
// (Egress-Only Invariant, layers 2/3).
func TestEgressOnly(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		touchesResponseBody := strings.Contains(src, "resp.Body") || strings.Contains(src, "Response.Body")
		decodes := strings.Contains(src, "json.Unmarshal(") ||
			strings.Contains(src, "NewDecoder(") ||
			strings.Contains(src, ".Decode(")
		if touchesResponseBody && decodes {
			t.Errorf("%s reads an HTTP response body AND decodes — egress-only forbids reading a reply into program state", f)
		}
	}
	// Positive assertion: http.go actually drains the body to io.Discard — the exact call,
	// not merely the words appearing in a comment.
	b, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "io.Copy(io.Discard, resp.Body)") {
		t.Error("http.go must drain the response body via io.Copy(io.Discard, resp.Body) (egress-only)")
	}
}
