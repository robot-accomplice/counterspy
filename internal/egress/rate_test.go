// internal/egress/rate_test.go
package egress

import "testing"

func TestRateOut(t *testing.T) {
	if got := RateOut(Bytes{Out: 1000}, Bytes{Out: 3000}, 2); got != 1000 {
		t.Fatalf("RateOut = %d, want 1000 (2000 bytes / 2s)", got)
	}
	// Counter reset / process restart (cur < prev) → 0, not a huge underflow.
	if got := RateOut(Bytes{Out: 5000}, Bytes{Out: 100}, 2); got != 0 {
		t.Fatalf("RateOut on counter reset = %d, want 0", got)
	}
}

func TestCadence(t *testing.T) {
	for _, c := range []struct {
		name string
		h    []uint64
		want string
	}{
		{"one-off", []uint64{9000, 0, 0, 0, 0}, "one-off"},
		{"steady", []uint64{1000, 1100, 950, 1050, 1000}, "steady"},
		{"periodic", []uint64{0, 5000, 0, 0, 5000}, "periodic"},
		{"bursty", []uint64{200, 9000, 300, 8000, 250}, "bursty"},
	} {
		if got := Cadence(c.h); got != c.want {
			t.Fatalf("Cadence(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRateIn(t *testing.T) {
	// 2000 inbound bytes over 2s = 1000 B/s.
	if got := RateIn(Bytes{In: 100}, Bytes{In: 2100}, 2.0); got != 1000 {
		t.Fatalf("RateIn = %d, want 1000", got)
	}
	// A counter reset (cur < prev) yields 0, never a huge spike (mirrors RateOut).
	if got := RateIn(Bytes{In: 5000}, Bytes{In: 10}, 1.0); got != 0 {
		t.Fatalf("RateIn on reset = %d, want 0", got)
	}
}
