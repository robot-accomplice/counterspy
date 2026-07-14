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

// drawInspect renders the full-screen inspection pane for one flow, split into rule-separated
// sections: the identity header, the honest coverage verdict + metadata (SNI, byte volume), and a
// content pane — either the plaintext (masked by default, §6) or, when the flow is encrypted, a
// plain explanation of why there is nothing to view. It replaces the tree while open.
func drawInspect(s tcell.Screen, insp *inspection, reveal bool) {
	s.Clear()
	w, h := s.Size()
	if w < 24 || h < 6 {
		drawText(s, 0, 0, tcell.StyleDefault.Foreground(colWarn), "terminal too small")
		return
	}
	def := tcell.StyleDefault
	t, v := insp.target, insp.view
	inner := w - marginX - marginR

	// Title band.
	drawText(s, marginX, 0, def.Foreground(colAccent).Bold(true), "CounterSpy · Inspect")
	drawHRule(s, 1, w)

	// Identity: which process, to where.
	glyph := ""
	if tg := mark.TrustLabel(t.trust); tg != 0 {
		glyph = " " + string(tg)
	}
	header := fmt.Sprintf("%s · pid %d · → %s %s:%d%s",
		t.app, t.pid, strings.ToUpper(t.conn.Proto), t.conn.Endpoint.IP, t.conn.Endpoint.Port, glyph)
	y := 2
	drawWrapped(s, marginX, &y, def.Foreground(colAccent), header, inner)
	drawHRule(s, y, w)
	y++

	// Assessment: the coverage verdict is the honest headline — plaintext leaving in the clear reads
	// as alarm (red), an encrypted flow we could only fingerprint reads amber ("this is itself a
	// finding" per §4), a capture failure reads amber, a clean no-data reads dim — plus metadata.
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
	if v.SNI != "" {
		drawWrapped(s, marginX, &y, def.Foreground(colDim), "SNI   "+v.SNI, inner)
	}
	// Byte volume each direction, shown for ANY coverage so an encrypted flow still conveys its
	// shape (e.g. a mostly-inbound response stream).
	if v.SentBytes > 0 || v.RecvBytes > 0 {
		drawWrapped(s, marginX, &y, def.Foreground(colDim),
			fmt.Sprintf("↑ %s sent   ↓ %s received", human(uint64(v.SentBytes)), human(uint64(v.RecvBytes))), inner)
	}

	// Content section: a rule opens it, the footer (with its own rule) closes it; the payload lives
	// between. Whether there is anything to view is the reader's core question, so answer it here.
	hasContent := v.Sent != "" || v.Received != ""
	footer := "esc/i back · Q quit"
	if hasContent {
		footer = "v view · esc/i back · Q quit"
	}
	footerY := h - 1
	footerRuleY := footerY - 1
	drawText(s, marginX, footerY, def.Foreground(colDim), truncate(footer, inner))
	drawHRule(s, footerRuleY, w)

	contentTop := y + 1
	if contentTop >= footerRuleY {
		return // no room for a content pane on a short terminal (footer already drawn)
	}
	drawHRule(s, y, w) // separate the assessment from the content

	if hasContent {
		hint := "masked — v to view"
		if reveal {
			hint = "shown — v to hide"
		}
		// When both directions have content, split the region so a long SENT can't swallow the pane
		// and silently hide RECEIVED (T-15); each pane truncates within its budget.
		sentMaxY := footerRuleY
		if v.Sent != "" && v.Received != "" {
			sentMaxY = (contentTop + footerRuleY) / 2
			if sentMaxY < contentTop+2 {
				sentMaxY = contentTop + 2
			}
			if sentMaxY > footerRuleY {
				sentMaxY = footerRuleY
			}
		}
		ny := drawDirection(s, marginX, contentTop, sentMaxY, inner, "SENT →", hint, v.Sent, !reveal)
		drawDirection(s, marginX, ny, footerRuleY, inner, "RECEIVED ←", hint, v.Received, !reveal)
		return
	}

	// No plaintext to show — say so, and why, so the byte volume above isn't a silent mystery.
	cy := contentTop
	if why := noContentReason(v); why != "" {
		drawWrapped(s, marginX, &cy, def.Foreground(colText), why, inner)
	}
}

// noContentReason explains, in plain language, why an inspected flow has no viewable payload — the
// reader's implicit question when they see byte volume but no content. Empty when the verdict itself
// already carries the reason (a capture error).
func noContentReason(v model.InspectView) string {
	switch {
	case v.Err != "":
		return "" // the verdict line already states the capture failure
	case v.Coverage == model.InspectMetadata && v.Encrypted:
		return string(mark.GlyphEncrypted) + " Encrypted (TLS): the payload is ciphertext. CounterSpy can measure this flow — " +
			"how much left and where it went, shown above — but it cannot read the contents, so there is nothing to view."
	case v.Coverage == model.InspectMetadata:
		return "Captured only non-readable bytes for this flow (nothing to render)."
	default:
		return "No application data was captured for this flow."
	}
}

// drawContentPane draws the payload from y up to (but not including) maxY: each source line is
// cleaned (so a crafted payload can't inject ANSI/newlines — defense in depth over the adapter's
// sanitize) then word-wrapped to width so nothing runs off the edge. A payload taller than the
// pane ends in a truncation marker.
func drawContentPane(s tcell.Screen, x, y, maxY, width int, content string) int {
	for _, raw := range strings.Split(content, "\n") {
		for _, ln := range wrapText(model.Clean(raw), width) {
			if y >= maxY {
				drawText(s, x, maxY-1, tcell.StyleDefault.Foreground(colDim), "… (payload truncated)")
				return maxY
			}
			drawText(s, x, y, tcell.StyleDefault.Foreground(colText), ln)
			y++
		}
	}
	return y
}

// drawDirection draws a labelled content pane for one direction (masked unless revealed) starting
// at y, and returns the y below it so a second direction can stack beneath. A no-op for empty
// content or when there's no room left above the footer.
func drawDirection(s tcell.Screen, x, y, maxY, width int, label, hint, content string, masked bool) int {
	if content == "" {
		return y
	}
	if y >= maxY-1 { // no room for a pane — still tell the user this direction has data (T-15)
		if y < maxY {
			drawText(s, x, y, tcell.StyleDefault.Foreground(colDim), truncate(label+" · hidden — resize", width))
		}
		return y
	}
	if masked {
		content = model.Redact(content)
	}
	drawText(s, x, y, tcell.StyleDefault.Foreground(colDim).Bold(true), label+" · "+hint)
	return drawContentPane(s, x, y+1, maxY, width, content)
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
