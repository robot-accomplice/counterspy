package netname

// Resolver maps a destination IP (string form, as the egress monitor holds it) to the hostname most
// recently observed resolving to it. ok is false when no name has been seen — the caller then shows
// the bare IP (never a fabricated name). The egress monitor depends on this interface, not the
// concrete Cache, so it stays testable with a fake and never imports the capture machinery.
type Resolver interface {
	Lookup(ip string) (name string, ok bool)
}
