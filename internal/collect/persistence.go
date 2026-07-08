package collect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"counterspy/internal/model"
)

// Persistence signal weights (local to the collector so `collect` never imports `score`).
const (
	// hidden-path is down-weighted: dev tools legitimately live in dot-dirs
	// (~/.cargo, ~/go, ~/.local), so it's a noisy signal on its own (tuning tick 8).
	wHiddenPath = 1
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

// extractLabelAndTarget scans the xml1 dict for Label and the persistence target.
// It distinguishes <key> from <string> elements (so a string VALUE equal to "Label"
// cannot poison key detection — cp-5 F-3), and picks the target as the last
// absolute-path ProgramArguments entry so interpreter wrappers like
// `/usr/bin/env <payload>` resolve to the real payload, not the wrapper (cp-5 F-1).
func extractLabelAndTarget(b []byte) (label, target string) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	var curElem, pendingKey string
	var inArgs bool
	var args []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			curElem = t.Name.Local
			if curElem == "array" && pendingKey == "ProgramArguments" {
				inArgs = true
			}
		case xml.EndElement:
			if t.Name.Local == "array" {
				inArgs = false
			}
			curElem = ""
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if s == "" {
				continue
			}
			switch curElem {
			case "key":
				pendingKey = s
			case "string":
				if pendingKey == "Label" && label == "" {
					label = s
				}
				if inArgs {
					args = append(args, s)
				}
			}
		}
	}
	return label, pickTarget(args)
}

// pickTarget returns the last absolute-path argument (defeating interpreter
// wrappers such as `/usr/bin/env /real/payload`), falling back to the first arg.
func pickTarget(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if strings.HasPrefix(args[i], "/") {
			return args[i]
		}
	}
	if len(args) > 0 {
		return args[0]
	}
	return ""
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
	// /System/Library is OBSERVED for visibility (§6); the actor still never ACTS
	// on it (§9). Observing != acting.
	dirs := []string{
		expand("~/Library/LaunchAgents"),
		"/Library/LaunchAgents", "/Library/LaunchDaemons",
		"/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
	}
	var all []model.Evidence
	var errs []error
	readOK := 0
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		readOK++
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			xmlBytes, err := execOutput("plutil", "-convert", "xml1", "-o", "-", p)
			if err != nil || len(xmlBytes) > 2<<20 { // cap at 2 MiB — skip plist bombs (ABORT C1)
				continue
			}
			ev, _ := ParsePersistencePlist(xmlBytes, p)
			all = append(all, ev...)
		}
	}
	// §9 fail-loud: if NOT ONE directory was readable, that's a gap, not "clean".
	if readOK == 0 {
		return all, fmt.Errorf("no launchd directory readable: %w", errors.Join(errs...))
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
