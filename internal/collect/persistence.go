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
	// inline interpreter code in a LaunchAgent is a recognised LOLBin persistence technique
	// (`osascript -e` / `python3 -c`): the payload never touches disk and argv[0] is an
	// Apple-signed interpreter, so the entry reads trusted. Weighted like a missing target — the
	// payload is not a verifiable on-disk binary (T-7; tuning tick).
	wInlineCode = 2
)

// inlineInterpreters are argv[0] binaries whose inline-code flag turns an Apple-signed
// interpreter into an arbitrary-code LOLBin (T-7). inlineCodeFlags are the flags whose
// following token is inline source rather than a file path.
var inlineInterpreters = map[string]bool{
	"osascript": true, "python": true, "python2": true, "python3": true,
	"bash": true, "sh": true, "zsh": true, "ruby": true, "perl": true, "node": true, "php": true,
}
var inlineCodeFlags = map[string]bool{"-e": true, "-c": true, "-r": true, "--eval": true, "-p": true}

// inlineInterpreterPayload reports whether args invoke a known interpreter with an inline-code
// flag, returning the inline source. argv[0] resolves to the interpreter (e.g. /usr/bin/osascript),
// so persistence scoring must treat the source — not the trusted interpreter — as the payload.
func inlineInterpreterPayload(args []string) (src string, ok bool) {
	if len(args) == 0 || !inlineInterpreters[filepath.Base(args[0])] {
		return "", false
	}
	for i := 1; i < len(args); i++ {
		if inlineCodeFlags[args[i]] {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true // flag present but no following token — still inline execution
		}
	}
	return "", false
}

// ParsePersistencePlist turns one launchd plist (already `plutil -convert xml1`)
// into evidence. Pure over its byte input except a stat() existence check.
func ParsePersistencePlist(xmlBytes []byte, path string) ([]model.Evidence, error) {
	label, args := extractLabelAndArgs(xmlBytes)
	target := pickTarget(args)
	sub := model.Subject{Path: target, Label: label}
	var ev []model.Evidence
	facts := map[string]string{"plist": path, "target": target}

	// Interpreter-wrapped inline code (T-7): argv[0] is an Apple-signed interpreter, so keeping it
	// as Subject.Path would let codesign whitewash the entry as trusted. Treat the inline source as
	// the payload — fall back to the plist as the subject (so the trusted interpreter is not
	// codesigned) and emit a dedicated finding carrying the interpreter + source for RCA.
	src, inline := inlineInterpreterPayload(args)
	if target == "" || inline {
		sub.Path = path
	}
	if inline {
		f := map[string]string{"plist": path, "interpreter": filepath.Base(args[0]), "inline_code": src}
		ev = append(ev, model.Evidence{Subject: sub, Kind: model.KindPersistence,
			Summary: "persistence runs inline interpreter code", Weight: wInlineCode, Facts: f})
	}

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
	label, args := extractLabelAndArgs(b)
	return label, pickTarget(args)
}

// extractLabelAndArgs scans the xml1 dict for the Label and the raw ProgramArguments, so callers
// can both pick a payload target and inspect the argv (interpreter-awareness — T-7).
func extractLabelAndArgs(b []byte) (label string, args []string) {
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	var curElem, pendingKey string
	var inArgs bool
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
	return label, args
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
