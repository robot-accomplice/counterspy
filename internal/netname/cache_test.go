package netname

import (
	"strconv"
	"sync"
	"testing"
)

func TestCache_PutLookupAndLastSeenWins(t *testing.T) {
	c := NewCache(8)
	if _, ok := c.Lookup("1.2.3.4"); ok {
		t.Fatal("empty cache must miss")
	}
	c.Put("1.2.3.4", "a.example.com")
	if n, ok := c.Lookup("1.2.3.4"); !ok || n != "a.example.com" {
		t.Fatalf("lookup after put: %q ok=%v", n, ok)
	}
	c.Put("1.2.3.4", "b.example.com") // re-resolved → last-seen-wins
	if n, _ := c.Lookup("1.2.3.4"); n != "b.example.com" {
		t.Fatalf("last-seen-wins failed: %q", n)
	}
	c.Put("", "x")       // empty ip ignored
	c.Put("5.6.7.8", "") // empty name ignored
	if _, ok := c.Lookup("5.6.7.8"); ok {
		t.Fatal("empty name must not be stored")
	}
}

func TestCache_EvictsOldestPastCap(t *testing.T) {
	c := NewCache(2)
	c.Put("ip1", "one")
	c.Put("ip2", "two")
	c.Put("ip3", "three") // evicts ip1 (oldest)
	if _, ok := c.Lookup("ip1"); ok {
		t.Fatal("ip1 should have been evicted")
	}
	if n, ok := c.Lookup("ip2"); !ok || n != "two" {
		t.Fatalf("ip2 should survive: %q ok=%v", n, ok)
	}
	if n, ok := c.Lookup("ip3"); !ok || n != "three" {
		t.Fatalf("ip3 should be present: %q ok=%v", n, ok)
	}
	// Re-putting an existing key must NOT change its eviction position (it's not a new key).
	c.Put("ip2", "two-again")
	c.Put("ip4", "four") // evicts ip3 (the oldest DISTINCT key), not ip2
	if _, ok := c.Lookup("ip2"); !ok {
		t.Fatal("re-put key must not be treated as newest/oldest churn")
	}
}

// The observer writes while the sampler reads; run under -race to prove the guard holds.
func TestCache_ConcurrentPutLookup(t *testing.T) {
	c := NewCache(64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(2)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.Put("ip"+strconv.Itoa((g*500+i)%128), "name"+strconv.Itoa(i))
			}
		}(g)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.Lookup("ip" + strconv.Itoa(i%128))
			}
		}(g)
	}
	wg.Wait()
}
