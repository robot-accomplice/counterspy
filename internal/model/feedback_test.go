// internal/model/feedback_test.go
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFeedbackRecordJSON(t *testing.T) {
	r := FeedbackRecord{
		Schema: FeedbackSchema, Tool: Version, Nonce: "n1",
		Label: LabelFalsePositive, Recommendation: "quarantine",
		Category: "surveillance-capable", ScoreBand: "10-14",
		Signals: []string{"persistence", "codesign"}, Codesign: "unsigned",
		PathClass: "user-library", Tripwire: true, Identity: "com.docker.docker",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"schema":"1"`, `"score_band":"10-14"`, `"path_class":"user-library"`, `"identity":"com.docker.docker"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	// Empty identity/extra must be omitted (public default carries neither).
	var empty FeedbackRecord
	b2, _ := json.Marshal(empty)
	if strings.Contains(string(b2), "identity") || strings.Contains(string(b2), "extra") {
		t.Fatalf("empty identity/extra must be omitted: %s", b2)
	}
	if Version != "v0.3.0-rc1" {
		t.Fatalf("Version = %s, want v0.3.0-rc1", Version)
	}
}
