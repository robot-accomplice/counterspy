package collect

import (
	"os/exec"
	"strings"

	"counterspy/internal/model"
)

// TCC service → weight + summary (only grants that matter to spyware).
var tccWeights = map[string]struct {
	weight  int
	summary string
}{
	"kTCCServiceAccessibility":        {3, "holds Accessibility"},
	"kTCCServiceListenEvent":          {3, "holds Input Monitoring"},
	"kTCCServiceScreenCapture":        {2, "holds Screen Recording"},
	"kTCCServiceSystemPolicyAllFiles": {2, "holds Full Disk Access"},
}

// ParseTCC turns `service|client|auth_value` rows into evidence (auth_value 2 = allowed).
func ParseTCC(rows []byte) []model.Evidence {
	var ev []model.Evidence
	for _, ln := range strings.Split(strings.TrimSpace(string(rows)), "\n") {
		parts := strings.Split(ln, "|")
		if len(parts) < 3 || parts[2] != "2" {
			continue
		}
		w, ok := tccWeights[parts[0]]
		if !ok {
			continue
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{Path: parts[1]},
			Kind:    model.KindTCC,
			Summary: w.summary,
			Weight:  w.weight,
			Facts:   map[string]string{"service": parts[0]},
		})
	}
	return ev
}

// CollectTCC reads the user + system TCC databases (I/O edge; system db needs sudo).
func CollectTCC() ([]model.Evidence, error) {
	const q = "SELECT service, client, auth_value FROM access;"
	dbs := []string{
		expand("~/Library/Application Support/com.apple.TCC/TCC.db"),
		"/Library/Application Support/com.apple.TCC/TCC.db",
	}
	var all []model.Evidence
	for _, db := range dbs {
		out, err := exec.Command("sqlite3", "-separator", "|", db, q).Output()
		if err != nil {
			continue
		}
		all = append(all, ParseTCC(out)...)
	}
	return all, nil
}
