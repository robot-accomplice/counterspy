package feedback

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEgressOnly enforces the push-only invariant as CI, not memory: no file in the
// feedback package may decode an HTTP response body into program state, and the only
// place a response is touched is the drain-and-discard in http.go. Any future refactor
// that reads resp.Body back into a value fails here (Egress-Only Invariant, layer 2/3).
func TestEgressOnly(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	// Patterns that would mean "the network spoke back into the program".
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`Decode\(\s*&?\w*[rR]esp`),           // json.NewDecoder(resp.Body).Decode(&x)
		regexp.MustCompile(`Unmarshal\([^)]*[rR]esp`),           // json.Unmarshal(respBody, &x)
		regexp.MustCompile(`NewDecoder\(\s*\w*[rR]esp\.Body\s*\)\.Decode`),
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, re := range forbidden {
			if re.MatchString(src) {
				t.Errorf("%s decodes an HTTP response — egress-only invariant forbids reading a reply into program state", f)
			}
		}
	}
	// Positive assertion: the http transmitter drains-and-discards.
	b, err := os.ReadFile("http.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "io.Discard") {
		t.Error("http.go must drain the response body to io.Discard (egress-only)")
	}
}
