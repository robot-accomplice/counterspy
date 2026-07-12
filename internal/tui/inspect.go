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
	drawText(s, marginX, 2, def.Foreground(colAccent), model.Clean(truncate(header, inner)))

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
	y := 4
	drawText(s, marginX, y, def.Foreground(vcolor).Bold(true), model.Clean(truncate(v.Verdict, inner)))
	y += 2

	if v.SNI != "" {
		drawText(s, marginX, y, def.Foreground(colDim), model.Clean(truncate("SNI   "+v.SNI, inner)))
		y++
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

// drawContentPane draws the payload line-by-line from y up to (but not including) maxY, cleaning
// each line so a crafted payload can't inject ANSI/newlines into the terminal (defense in depth
// over the adapter's sanitize). A payload taller than the pane ends in a truncation marker.
func drawContentPane(s tcell.Screen, x, y, maxY, width int, content string) {
	for _, ln := range strings.Split(content, "\n") {
		if y >= maxY {
			drawText(s, x, maxY-1, tcell.StyleDefault.Foreground(colDim), "… (payload truncated)")
			return
		}
		drawText(s, x, y, tcell.StyleDefault.Foreground(colText), model.Clean(truncate(ln, width)))
		y++
	}
}

// drawConsentPrompt overlays the §5 consent gate over the tree: nothing is captured until the
// user answers y. Centered and clamped to the screen (the cp-T7 off-screen-overlay lesson).
func drawConsentPrompt(s tcell.Screen, t *inspectTarget) {
	lines := []string{
		"Inspect this flow?",
		model.Clean(fmt.Sprintf("%s · pid %d · → %s:%d", t.app, t.pid, t.conn.Endpoint.IP, t.conn.Endpoint.Port)),
		"",
		"Captures THIS flow's packets on your own",
		"machine, for this view only.",
		"",
		"[y] inspect    [N] cancel",
	}
	drawCenteredBox(s, lines)
}

// drawCenteredBox draws a bordered box of text lines centered on screen, clamped so it never
// draws off-screen on a small terminal (per cp-T7). Lines are assumed already cleaned.
func drawCenteredBox(s tcell.Screen, lines []string) {
	w, h := s.Size()
	boxW := 0
	for _, ln := range lines {
		if n := len([]rune(ln)); n > boxW {
			boxW = n
		}
	}
	boxW += 4 // padding + borders
	boxH := len(lines) + 2
	if boxW > w {
		boxW = w
	}
	if boxH > h {
		boxH = h
	}
	x0 := (w - boxW) / 2
	y0 := (h - boxH) / 2
	if x0 < 0 {
		x0 = 0
	}
	if y0 < 0 {
		y0 = 0
	}
	border := tcell.StyleDefault.Foreground(colAccent).Background(colSelBg)
	body := tcell.StyleDefault.Foreground(colText).Background(colSelBg)
	for yy := 0; yy < boxH; yy++ {
		for xx := 0; xx < boxW; xx++ {
			ch := ' '
			style := body
			switch {
			case yy == 0 || yy == boxH-1:
				ch, style = '─', border
			case xx == 0 || xx == boxW-1:
				ch, style = '│', border
			}
			s.SetContent(x0+xx, y0+yy, ch, nil, style)
		}
	}
	for i, ln := range lines {
		yy := y0 + 1 + i
		if yy >= y0+boxH-1 {
			break
		}
		drawText(s, x0+2, yy, body, truncate(ln, boxW-4))
	}
}
