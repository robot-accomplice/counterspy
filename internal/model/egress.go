package model

// Endpoint is a remote network peer.
type Endpoint struct {
	IP   string
	Port int
}

// Conn is one established outbound connection — a constituent of an EgressGroup, revealed
// when the group is expanded in the TUI.
type Conn struct {
	PID      int
	Endpoint Endpoint
	Proto    string // "tcp" | "udp"
	OutRate  uint64 // bytes/sec (may be 0 if per-connection rate is unavailable)
}

// ConcernLevel is the coarse concern/exfil band used for coloring and sorting.
type ConcernLevel int

const (
	Minimal ConcernLevel = iota
	Low
	Notable
	Elevated
)

func (l ConcernLevel) String() string {
	switch l {
	case Elevated:
		return "elevated"
	case Notable:
		return "notable"
	case Low:
		return "low"
	default:
		return "minimal"
	}
}

// EgressInstance is one process (PID) within an EgressGroup — the middle tier of the
// name → instance → connection tree.
type EgressInstance struct {
	PID      int
	Path     string
	Trust    string
	OutRate  uint64
	InRate   uint64
	OutTotal uint64
	Conns    []Conn
}

// EgressGroup aggregates ALL instances (PIDs) and connections (ports/protocols/destinations)
// of one application into a single collapsible row.
type EgressGroup struct {
	App          string
	Path         string
	Ancestry     string
	Trust        string // "apple" | "notarized" | "signed" | "unsigned" | "unknown"
	Instances    int
	Members      []EgressInstance
	OutRate      uint64
	InRate       uint64
	OutTotal     uint64
	Spark        []uint64
	Cadence      string // "one-off" | "bursty" | "steady" | "periodic"
	Destinations []Endpoint
	Conns        []Conn
	Background   bool
	Capabilities []string // "screen" "keystrokes" "contacts" "full-disk" ...
	Concern      ConcernLevel
	ExfilRisk    ConcernLevel
	Candidate    []string // inferred candidate exfiltrated categories (never payloads)
}
