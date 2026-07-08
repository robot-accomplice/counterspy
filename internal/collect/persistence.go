package collect

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// Persistence signal weights (local to the collector so `collect` never imports `score`).
const (
	wHiddenPath = 2
	wUserAgent  = 1
	wMissingTgt = 2
)

// ParsePersistencePlist turns one launchd plist (already `plutil -convert xml1`)
// into evidence. Pure over its byte input except a stat() existence check.
func ParsePersistencePlist(xmlBytes []byte, path string) ([]model.Evidence, error) {
	label, target := extractLabelAndTarget(xmlBytes)
	sub := model.Subject{Path: target, Label: label}
	if target == "" {
		sub.Path = path
	}
	var ev []model.Evidence
	facts := map[string]string{"plist": path, "target": target}

	if strings.Contains(target, "/.") || strings.HasPrefix(filepath.Base(target), ".") {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence targets a hidden path", Weight: wHiddenPath, Facts: facts})
	}
	if strings.Contains(path, "/Users/") {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "user-level LaunchAgent", Weight: wUserAgent, Facts: facts})
	}
	if target != "" && !statExists(target) {
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence target is missing/renamed", Weight: wMissingTgt, Facts: facts})
	}
	return ev, nil
}

// extractLabelAndTarget tolerantly scans the xml1 dict for Label and the first
// ProgramArguments entry.
func extractLabelAndTarget(b []byte) (label, target string) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	var lastKey string
	var inArgs bool
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s == "" {
				continue
			}
			if lastKey == "Label" && label == "" {
				label = s
			}
			if inArgs && target == "" {
				target = s
			}
			lastKey = s
		case xml.StartElement:
			if t.Name.Local == "array" {
				inArgs = lastKey == "ProgramArguments"
			}
		}
	}
	return label, target
}

func statExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// CollectPersistence walks the launchd search paths and returns evidence.
// I/O edge — exercised via integration, not unit tests.
func CollectPersistence() ([]model.Evidence, error) {
	dirs := []string{
		expand("~/Library/LaunchAgents"),
		"/Library/LaunchAgents", "/Library/LaunchDaemons",
	}
	var all []model.Evidence
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue // reported as a gap by the caller if the whole phase fails
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			xmlBytes, err := exec.Command("plutil", "-convert", "xml1", "-o", "-", p).Output()
			if err != nil {
				continue
			}
			ev, _ := ParsePersistencePlist(xmlBytes, p)
			all = append(all, ev...)
		}
	}
	return all, nil
}

func expand(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
