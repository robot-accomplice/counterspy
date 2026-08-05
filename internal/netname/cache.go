package netname

import "sync"

// Cache is a bounded, concurrency-safe reverse map IP→hostname. The passive DNS observer writes it
// from its capture goroutine while the egress sampler reads it each tick, so every access is guarded.
// It is last-seen-wins (a fresh answer overwrites the name) and LRU-by-write: a re-observed IP is
// refreshed to newest, and eviction drops the least-recently-observed key. LRU (not FIFO) matters
// here because the IPs an app keeps connecting to are exactly the ones it keeps re-resolving. FIFO
// would evict an active destination's name right when a flow to it needs it.
type Cache struct {
	mu    sync.Mutex
	m     map[string]string
	order []string // least-recently-written first; last element is newest
	cap   int
}

// NewCache returns a cache holding at most capacity distinct IPs (<=0 is treated as 1).
func NewCache(capacity int) *Cache {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache{m: make(map[string]string, capacity), cap: capacity}
}

// Put records that ip currently resolves to name (last-seen-wins). A re-observed ip is refreshed to
// newest; a genuinely new ip may evict the least-recently-observed one.
func (c *Cache) Put(ip, name string) {
	if ip == "" || name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[ip]; exists {
		c.m[ip] = name
		c.touch(ip) // re-resolution refreshes recency (LRU)
		return
	}
	if len(c.order) >= c.cap {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.m, oldest)
	}
	c.order = append(c.order, ip)
	c.m[ip] = name
}

// touch moves an existing key to the newest position. O(n) in the (bounded) key count, called only
// on re-resolution, negligible at DNS-response rates.
func (c *Cache) touch(ip string) {
	for i, k := range c.order {
		if k == ip {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, ip)
}

// Lookup implements Resolver.
func (c *Cache) Lookup(ip string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name, ok := c.m[ip]
	return name, ok
}
