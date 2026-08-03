package collect

import (
	"errors"
	"fmt"
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
// service is the first field and auth_value the LAST, so a client path containing a
// pipe is preserved by re-joining the middle fields (cp-7 QA F-3).
func ParseTCC(rows []byte) []model.Evidence {
	var ev []model.Evidence
	for _, ln := range strings.Split(strings.TrimSpace(string(rows)), "\n") {
		parts := strings.Split(ln, "|")
		if len(parts) < 3 || parts[len(parts)-1] != "2" {
			continue
		}
		service := parts[0]
		client := strings.Join(parts[1:len(parts)-1], "|")
		w, ok := tccWeights[service]
		if !ok {
			continue
		}
		ev = append(ev, model.Evidence{
			Subject: model.Subject{Path: client},
			Kind:    model.KindTCC,
			Summary: w.summary,
			Weight:  w.weight,
			Facts:   map[string]string{"service": service},
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
	var errs []error
	readOK := 0
	for _, db := range dbs {
		out, err := execOutput(sqlite3Bin, "-separator", "|", db, q)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		readOK++
		all = append(all, ParseTCC(out)...)
	}
	// §9 fail-loud: if NO TCC database was readable, that's a gap — the most
	// spyware-relevant signal must never read as "clean" (cp-7 Audit F-2).
	if readOK == 0 {
		return all, fmt.Errorf("no TCC database readable: %w", errors.Join(errs...))
	}
	return all, nil
}
