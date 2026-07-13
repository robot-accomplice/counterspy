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
	// (`osascript -e` / `python3 -c`): the payload never touches disk and argv[0] is an Apple-signed
	// interpreter, so the entry reads trusted. Weighted to reach ShowThreshold (5) on its own — a
	// stealth inline payload is at least as notable as a plain unsigned binary (wUnsigned=3), and at
	// 2 the persistence-only "weak" gate (interpret.recommend) would bury the flagship case at
	// Monitor-tier (cp-t7 Audit F-2). Weak-category cap still prevents auto-Quarantine (T-7).
	wInlineCode = 5
)

// inlineInterpreters maps an interpreter (argv[0] basename, lowercased) to the flags whose
// FOLLOWING token is inline source rather than a file path. Scoped per interpreter because flag
// semantics differ: `node -r`/`ruby -r` is require (a module path, not code), while `php -r` is
// inline eval (cp-t7 Audit F-3). An interpreter's inline-code flag turns an Apple-signed binary
// into an arbitrary-code LOLBin (T-7).
var inlineInterpreters = map[string][]string{
	"osascript": {"-e"},
	"python":    {"-c"}, "python2": {"-c"}, "python3": {"-c"},
	"bash": {"-c"}, "sh": {"-c"}, "zsh": {"-c"},
	"ruby": {"-e"},
	"perl": {"-e"},
	"node": {"-e", "--eval", "-p", "--print"},
	"php":  {"-r"},
}

// isTrustedShim reports whether a resolved target is itself an Apple-signed exec shim — an
// interpreter or `env`. When pickTarget resolves to one of these, no real on-disk payload was
// found, so the shim must NOT become Subject.Path: codesign would attach the shim's trusted Apple
// authority to attacker-supplied code (the whitewash T-7 closes — for the inline-flag shape AND the
// relative/no-payload shape, cp-t7 Audit F-1).
func isTrustedShim(path string) bool {
	if path == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	_, ok := inlineInterpreters[base]
	return ok || base == "env"
}

// stripEnv drops a leading `/usr/bin/env` and its own option/assignment tokens so the real command
// is seen (cp-t7 Antagonist A1). Best-effort: `-u NAME` style option-arguments aren't specially
// consumed, but the security whitewash is closed regardless by isTrustedShim catching env itself.
func stripEnv(args []string) []string {
	if len(args) == 0 || strings.ToLower(filepath.Base(args[0])) != "env" {
		return args
	}
	i := 1
	for i < len(args) {
		a := args[i]
		if strings.HasPrefix(a, "-") || (strings.Contains(a, "=") && !strings.HasPrefix(a, "/")) {
			i++ // env option flag or VAR=value assignment
			continue
		}
		break // first bare token is the command
	}
	return args[i:]
}

// inlineInterpreterPayload reports whether args (after stripping an env wrapper) invoke a known
// interpreter with its inline-code flag, returning the interpreter basename and the inline source.
// Persistence scoring treats the source — not the trusted interpreter — as the payload (T-7).
func inlineInterpreterPayload(args []string) (interp, src string, ok bool) {
	args = stripEnv(args)
	if len(args) == 0 {
		return "", "", false
	}
	interp = strings.ToLower(filepath.Base(args[0]))
	flags, isInterp := inlineInterpreters[interp]
	if !isInterp {
		return "", "", false
	}
	for i := 1; i < len(args); i++ {
		for _, f := range flags {
			if args[i] == f {
				if i+1 < len(args) {
					return interp, args[i+1], true
				}
				return interp, "", true // flag present but no following token — still inline execution
			}
		}
	}
	return "", "", false
}

// ParsePersistencePlist turns one launchd plist (already `plutil -convert xml1`)
// into evidence. Pure over its byte input except a stat() existence check.
func ParsePersistencePlist(xmlBytes []byte, path string) ([]model.Evidence, error) {
	label, args := extractLabelAndArgs(xmlBytes)
	target := pickTarget(args)
	sub := model.Subject{Path: target, Label: label}
	var ev []model.Evidence
	facts := map[string]string{"plist": path, "target": target}

	// Interpreter-wrapped persistence (T-7): argv[0] (or an env wrapper) is an Apple-signed shim, so
	// keeping it as Subject.Path would let codesign whitewash the entry as trusted. Never let a
	// trusted shim be the subject — fall back to the plist — whether the shim leaked in via an
	// inline-code flag OR because pickTarget found no real on-disk payload (isTrustedShim).
	interp, src, inline := inlineInterpreterPayload(args)
	if target == "" || inline || isTrustedShim(target) {
		sub.Path = path
	}
	if inline {
		// Treat the inline source as the real payload and record it for RCA (Rule 14).
		f := map[string]string{"plist": path, "interpreter": interp, "inline_code": src}
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
