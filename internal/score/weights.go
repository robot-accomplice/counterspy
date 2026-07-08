package score

// Signal weights (points added per observation). Tunable — this is the ONLY
// place numeric policy lives.
const (
	WeightUnsigned        = 3 // binary is unsigned or ad-hoc
	WeightRevokedCert     = 5 // signature present but revoked
	WeightHiddenPath      = 2 // lives in a dot-dir or hidden location
	WeightUserLaunchAgent = 1 // ~/Library LaunchAgent (common but noteworthy)
	WeightMissingTarget   = 2 // persistence points at a missing/renamed binary
	WeightInputMonitoring = 3 // holds Input Monitoring (keylogger shape)
	WeightAccessibility   = 3 // holds Accessibility
	WeightScreenRecording = 2 // holds Screen Recording
	WeightFullDiskAccess  = 2 // holds Full Disk Access
	WeightListener        = 2 // process listens on a socket
	WeightRawIPEgress     = 2 // established connection to a raw IP (no DNS name)
	WeightSpawnedByAgent  = 2 // parent chain includes a LaunchAgent-spawned proc
)

// Correlation: when >= CorrelationMinKinds DISTINCT signal kinds hit the same
// subject, multiply the summed weight by CorrelationFactor (scaled x100 to stay
// integer-only in the scorer).
const (
	CorrelationMinKinds = 2
	// CorrelationFactorX100 scales the summed weight by 1.5x (x100 to stay
	// integer-only). Applied as sum*150/100, which TRUNCATES toward zero (floor):
	// e.g. sum 5 -> 7 (7.5 floored). Rounding down is intentional — the multiplier
	// only ever raises a score, so flooring keeps it conservative.
	CorrelationFactorX100 = 150
	ShowThreshold         = 5 // findings at/above this are surfaced for quarantine
)
