package tui

import "github.com/gdamore/tcell/v2"

// A braille cell (U+2800 base) is a 2×4 dot grid; brailleBit[col][row] is the dot bit for the
// sub-pixel at (col∈{0,1}, row∈{0,1,2,3}): the standard Unicode braille numbering.
var brailleBit = [2][4]byte{
	{0x01, 0x02, 0x04, 0x40}, // left column, top→bottom
	{0x08, 0x10, 0x20, 0x80}, // right column, top→bottom
}

type graphSeries struct {
	values     []uint64
	color      tcell.Color
	emphasized bool
}

type graphCell struct {
	r     rune
	color tcell.Color
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// plotSeries rasterizes each series as a connected braille LINE into a rows×cols grid sharing one
// Y-axis scaled to maxY (0 = auto = the max value across all series). Sub-resolution is 2×cols wide
// and 4×rows tall. Consecutive samples are joined by straight line segments (Bresenham), spread to
// fill the full width (sample 0 at the left edge, the newest at the right) so a short history
// still spans the panel. Emphasized series are plotted last so a selected line wins a shared cell's
// color (btm's overlap rule).
func plotSeries(series []graphSeries, cols, rows int, maxY uint64) [][]graphCell {
	subCols, subRows := cols*2, rows*4
	bits := make([][]byte, rows)
	colr := make([][]tcell.Color, rows)
	for r := range bits {
		bits[r] = make([]byte, cols)
		colr[r] = make([]tcell.Color, cols)
	}

	if maxY == 0 {
		for _, s := range series {
			for _, v := range s.values {
				if v > maxY {
					maxY = v
				}
			}
		}
	}

	// non-emphasized first, emphasized last (draws on top)
	ordered := make([]graphSeries, 0, len(series))
	for _, s := range series {
		if !s.emphasized {
			ordered = append(ordered, s)
		}
	}
	for _, s := range series {
		if s.emphasized {
			ordered = append(ordered, s)
		}
	}

	// height in sub-rows for a value, measured from the bottom (0..subRows-1).
	height := func(v uint64) int {
		if maxY == 0 {
			return 0
		}
		h := int(v * uint64(subRows-1) / maxY)
		if h > subRows-1 {
			h = subRows - 1
		}
		return h
	}
	set := func(sx, sy int, c tcell.Color) { // light sub-pixel (sx,sy); sy measured from the TOP
		if sx < 0 || sx >= subCols || sy < 0 || sy >= subRows {
			return
		}
		bits[sy/4][sx/2] |= brailleBit[sx%2][sy%4]
		colr[sy/4][sx/2] = c
	}
	// line draws a straight braille line between two sub-pixels (Bresenham); this is what makes the
	// graph read as clean connected lines (btm-style) instead of a filled/dotty band.
	line := func(x0, y0, x1, y1 int, c tcell.Color) {
		dx, dy := abs(x1-x0), -abs(y1-y0)
		sxStep, syStep := 1, 1
		if x0 > x1 {
			sxStep = -1
		}
		if y0 > y1 {
			syStep = -1
		}
		e := dx + dy
		for {
			set(x0, y0, c)
			if x0 == x1 && y0 == y1 {
				break
			}
			e2 := 2 * e
			if e2 >= dy { // independent of the next: a diagonal step advances BOTH
				e += dy
				x0 += sxStep
			}
			if e2 <= dx {
				e += dx
				y0 += syStep
			}
		}
	}

	for _, s := range ordered {
		vals := s.values
		if len(vals) == 0 {
			continue
		}
		if len(vals) > subCols { // more samples than sub-columns: average down to fit
			vals = downsample(vals, subCols)
		}
		n := len(vals)
		// Spread the samples across the FULL width (sample 0 at the left, newest at the right) and
		// connect consecutive samples with straight line segments: a line graph, not a fill.
		col := func(i int) int {
			if n <= 1 {
				return subCols - 1
			}
			return i * (subCols - 1) / (n - 1)
		}
		if n == 1 {
			set(subCols-1, subRows-1-height(vals[0]), s.color)
			continue
		}
		px, py := col(0), subRows-1-height(vals[0])
		for i := 1; i < n; i++ {
			cx, cy := col(i), subRows-1-height(vals[i])
			line(px, py, cx, cy, s.color)
			px, py = cx, cy
		}
	}

	grid := make([][]graphCell, rows)
	for r := 0; r < rows; r++ {
		grid[r] = make([]graphCell, cols)
		for c := 0; c < cols; c++ {
			if b := bits[r][c]; b != 0 {
				grid[r][c] = graphCell{r: rune(0x2800 + int(b)), color: colr[r][c]}
			} else {
				grid[r][c] = graphCell{r: ' '}
			}
		}
	}
	return grid
}
