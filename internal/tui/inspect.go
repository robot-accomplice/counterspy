package tui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"

	"counterspy/internal/mark"
	"counterspy/internal/model"
)

// Inspector captures and inspects a single outbound flow, returning the honest per-flow view
// (spec §4). It is a seam: the tui defines it (importing only the pure model vocabulary), and a
// main adapter satisfies it with the native /dev/bpf capture + tier-0/1 engine — so the root I/O
// stays out of the decoupled UI, mirroring the Sampler/Actor seams. A nil Inspector means
// inspection is disabled (the --no-inspect posture); the overlay says so instead of capturing.
type Inspector interface {
	Inspect(conn model.Conn) model.InspectView
}

const inspectFooter = "r reveal · esc/i back · Q quit"

// drawInspect renders the full-screen inspection pane for one flow: header, the honest coverage
// verdict, metadata (SNI), and — when a tier surfaced plaintext — the content pane, masked by
// default (§6). It replaces the tree while open.
func drawInspect(s tcell.Screen, insp *inspection, reveal bool) {
	s.Clear()
	w, h := s.Size()
	if w < 24 || h < 6 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	def := tcell.StyleDefault
	t, v := insp.target, insp.view
	inner := w - 2*marginX

	drawText(s, marginX, 0, def.Foreground(colAccent).Bold(true), "CounterSpy · Inspect")

	glyph := ""
	if tg := mark.TrustLabel(t.trust); tg != 0 {
		glyph = " " + string(tg)
	}
	header := fmt.Sprintf("%s · pid %d · → %s %s:%d%s",
		t.app, t.pid, strings.ToUpper(t.conn.Proto), t.conn.Endpoint.IP, t.conn.Endpoint.Port, glyph)
	y := 2
	drawWrapped(s, marginX, &y, def.Foreground(colAccent), header, inner)
	y++ // blank line

	// The coverage verdict is the honest headline: plaintext leaving in the clear reads as alarm
	// (red), an encrypted flow we could only fingerprint reads amber ("this is itself a finding"
	// per §4), a capture failure reads amber, and a clean no-data reads dim.
	vcolor := colDim
	switch {
	case v.Err != "":
		vcolor = colWarn
	case v.Coverage == model.InspectPlaintext:
		vcolor = colQuarantine
	case v.Coverage == model.InspectMetadata:
		vcolor = colInvestigate
	}
	drawWrapped(s, marginX, &y, def.Foreground(vcolor).Bold(true), v.Verdict, inner)
	y++ // blank line

	if v.SNI != "" {
		drawWrapped(s, marginX, &y, def.Foreground(colDim), "SNI   "+v.SNI, inner)
	}

	if v.Content != "" {
		y++
		label := "CONTENT · masked — r to reveal"
		content := model.Redact(v.Content)
		if reveal {
			label, content = "CONTENT · revealed — r to mask", v.Content
		}
		drawText(s, marginX, y, def.Foreground(colDim).Bold(true), label)
		y++
		drawContentPane(s, marginX, y, h-1, inner, content)
	}

	drawText(s, marginX, h-1, def.Foreground(colDim), truncate(inspectFooter, inner))
}

// drawContentPane draws the payload from y up to (but not including) maxY: each source line is
// cleaned (so a crafted payload can't inject ANSI/newlines — defense in depth over the adapter's
// sanitize) then word-wrapped to width so nothing runs off the edge. A payload taller than the
// pane ends in a truncation marker.
func drawContentPane(s tcell.Screen, x, y, maxY, width int, content string) {
	for _, raw := range strings.Split(content, "\n") {
		for _, ln := range wrapText(model.Clean(raw), width) {
			if y >= maxY {
				drawText(s, x, maxY-1, tcell.StyleDefault.Foreground(colDim), "… (payload truncated)")
				return
			}
			drawText(s, x, y, tcell.StyleDefault.Foreground(colText), ln)
			y++
		}
	}
}

// wrapText word-wraps s to at most width display cells per line, rune-aware: it breaks at the last
// space that fits, and hard-breaks a token longer than width. Existing newlines start new lines.
// Prevents long verdicts/payload lines from running off the pane instead of silently truncating.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		r := []rune(line)
		for len(r) > width {
			cut := -1
			for i := width - 1; i > 0; i-- {
				if r[i] == ' ' {
					cut = i
					break
				}
			}
			if cut < 1 { // no interior space — hard-break the token
				out = append(out, string(r[:width]))
				r = r[width:]
			} else {
				out = append(out, string(r[:cut]))
				r = r[cut+1:] // drop the breaking space
			}
		}
		out = append(out, string(r))
	}
	return out
}

// drawWrapped draws text word-wrapped to width at (x, *y), cleaning it first and advancing *y past
// the rendered lines so the caller lays out the next block below.
func drawWrapped(s tcell.Screen, x int, y *int, style tcell.Style, text string, width int) {
	for _, ln := range wrapText(model.Clean(text), width) {
		drawText(s, x, *y, style, ln)
		*y++
	}
}
