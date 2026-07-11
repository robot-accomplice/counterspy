// internal/egress/rate.go
package egress

// RateOut returns bytes/sec of OUTbound traffic between two cumulative samples. A counter
// reset (cur < prev, e.g. the process restarted) yields 0 rather than an underflow.
func RateOut(prev, cur Bytes, intervalSec float64) uint64 {
	if intervalSec <= 0 || cur.Out < prev.Out {
		return 0
	}
	return uint64(float64(cur.Out-prev.Out) / intervalSec)
}

// Cadence classifies an out-rate history (oldest→newest) into a coarse pattern:
//
//	one-off  — sent in exactly one sample, silent otherwise
//	periodic — multiple separated bursts with silent gaps between
//	bursty   — highly variable, no steady floor
//	steady   — consistently active with low relative variance
func Cadence(history []uint64) string {
	active := 0
	var max, sum uint64
	transitions := 0 // silent→active edges
	prevActive := false
	for _, v := range history {
		a := v > 0
		if a {
			active++
			sum += v
			if v > max {
				max = v
			}
			if !prevActive {
				transitions++
			}
		}
		prevActive = a
	}
	if active == 0 {
		return "steady" // nothing sent this window; not interesting — treat as calm
	}
	if active == 1 {
		return "one-off"
	}
	if transitions >= 2 {
		return "periodic" // repeated bursts separated by silence
	}
	mean := sum / uint64(active)
	if mean > 0 && max > mean*2 {
		return "bursty"
	}
	return "steady"
}
