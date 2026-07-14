package tui

import (
	"testing"

	"github.com/gdamore/tcell/v2"
)

func gridHasBraille(grid [][]graphCell) bool {
	for _, rowCells := range grid {
		for _, c := range rowCells {
			if c.r > 0x2800 && c.r <= 0x28FF {
				return true
			}
		}
	}
	return false
}

// topLit returns the topmost row index with a lit cell in a column, or len(grid) if none — a proxy
// for "how high the line reaches" in that column.
func topLit(grid [][]graphCell, col int) int {
	for r := 0; r < len(grid); r++ {
		if grid[r][col].r > 0x2800 {
			return r
		}
	}
	return len(grid)
}

// A rising series must reach higher (smaller top-row index) on the right than on the left — the
// graph's whole job is to make a climbing talker read as climbing.
func TestPlotSeries_RisingLineClimbs(t *testing.T) {
	vals := []uint64{0, 1, 2, 3, 4, 5, 6, 7}
	grid := plotSeries([]graphSeries{{values: vals, color: tcell.ColorRed}}, 4, 3, 0)
	if len(grid) != 3 || len(grid[0]) != 4 {
		t.Fatalf("grid must be rows×cols = 3×4, got %dx%d", len(grid), len(grid[0]))
	}
	if !gridHasBraille(grid) {
		t.Fatal("a non-empty series must light braille dots")
	}
	if topLit(grid, 3) > topLit(grid, 0) {
		t.Fatalf("rising series must reach higher on the right: left top=%d right top=%d",
			topLit(grid, 0), topLit(grid, 3))
	}
}

// Two series sharing a cell: the emphasized one is drawn last and must win the cell's color, so the
// selected PID's line stays readable over the others.
func TestPlotSeries_EmphasizedWinsColor(t *testing.T) {
	flat := []uint64{5, 5, 5, 5}
	grid := plotSeries([]graphSeries{
		{values: flat, color: tcell.ColorGray},
		{values: flat, color: tcell.ColorRed, emphasized: true},
	}, 2, 2, 10)
	sawRed := false
	for _, rowCells := range grid {
		for _, c := range rowCells {
			if c.r > 0x2800 && c.color == tcell.ColorRed {
				sawRed = true
			}
		}
	}
	if !sawRed {
		t.Fatal("emphasized series must win the shared cell color")
	}
}

// A series shorter than the plot width must still span the full width (the left column is lit) —
// otherwise the graph can only ever fill a fraction of the panel (observed: ~45% cap).
func TestPlotSeries_ShortSeriesFillsFullWidth(t *testing.T) {
	// 3 samples into an 8-column (16 sub-column) plot must reach the leftmost cell.
	grid := plotSeries([]graphSeries{{values: []uint64{2, 5, 8}, color: tcell.ColorRed}}, 8, 3, 0)
	lit := func(col int) bool {
		for r := 0; r < len(grid); r++ {
			if grid[r][col].r > 0x2800 {
				return true
			}
		}
		return false
	}
	if !lit(0) {
		t.Fatal("a short series must still light the leftmost column (stretch to full width)")
	}
	if !lit(7) {
		t.Fatal("the newest sample must reach the rightmost column")
	}
}

func TestPlotSeries_EmptyIsBlankNoPanic(t *testing.T) {
	grid := plotSeries(nil, 3, 2, 0)
	if len(grid) != 2 || len(grid[0]) != 3 {
		t.Fatalf("empty input must still return a 2×3 grid, got %dx%d", len(grid), len(grid[0]))
	}
	if gridHasBraille(grid) {
		t.Fatal("no series → no lit dots")
	}
}
