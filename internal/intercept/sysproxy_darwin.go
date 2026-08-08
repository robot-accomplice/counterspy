//go:build darwin

package intercept

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// This file replaces the Phase 2 pf `rdr` redirect, which a root smoke test proved cannot work: pf
// translates only INBOUND packets, so a maximally permissive rdr rule matched 0 of the machine's own
// outbound packets (27828 Evaluations, 0 Packets). Instead we register as macOS's system secure-web
// (HTTPS) proxy, and clients CONNECT to us and name their destination.
//
// UNVERIFIED: requires a root smoke test (see the README). What must be confirmed: that a CFNetwork
// app (Safari/Chrome) actually routes through the proxy while armed, and that teardown restores the
// prior setting exactly. Note `curl` does NOT honor the macOS system proxy (it reads https_proxy), so
// probe with `curl -x 127.0.0.1:62443` or a real browser, not a bare curl.
//
// COOPERATIVE BY CONSTRUCTION: software that ignores the system proxy is not seen here. That gap is
// honest and visible (the Exfiltration monitor still shows those flows via nettop), and closing it
// needs a NetworkExtension transparent proxy (a later phase).

// networksetupBin is absolute because arm/disarm runs privileged: resolving the tool through PATH
// would let any writable PATH entry substitute it (go:S4036).
const networksetupBin = "/usr/sbin/networksetup"

// networksetupTimeout bounds each networksetup call so a wedged prefs daemon can't hang arm/disarm.
const networksetupTimeout = 15 * time.Second

// runNetworksetup is the seam over the macOS `networksetup` CLI (mirrors ca.runSecurity), so install/
// teardown is unit-testable with a fake. Fail loud: the tool's output is folded into the error.
var runNetworksetup = func(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), networksetupTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, networksetupBin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// proxyState is one network service's prior secure-web-proxy setting, captured so teardown restores
// exactly what was there; the user may already run a proxy (Charles/Proxyman/a corporate one) and we
// must not clobber it (the non-destructive lesson from the pf ruleset).
type proxyState struct {
	service string
	enabled bool
	server  string
	port    string
}

// networkServices lists the configurable network services. A leading '*' marks a DISABLED service,
// which we skip. The first line is a human-readable preamble, not a service.
func networkServices() ([]string, error) {
	out, err := runNetworksetup("-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		ln = strings.TrimSpace(ln)
		if i == 0 || ln == "" || strings.HasPrefix(ln, "*") {
			continue // preamble, blank, or a disabled service
		}
		svcs = append(svcs, ln)
	}
	if len(svcs) == 0 {
		return nil, fmt.Errorf("no enabled network services found")
	}
	return svcs, nil
}

// getProxyState reads a service's current secure-web-proxy setting so it can be restored verbatim.
func getProxyState(service string) (proxyState, error) {
	out, err := runNetworksetup("-getsecurewebproxy", service)
	if err != nil {
		return proxyState{}, err
	}
	st := proxyState{service: service}
	for _, ln := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			st.enabled = strings.EqualFold(v, "Yes")
		case "Server":
			st.server = v
		case "Port":
			st.port = v
		}
	}
	return st, nil
}

// restore puts a service's secure-web proxy back to its captured state.
//
// When the user HAD a proxy, it is put back exactly. When they had none, turning the state off is not
// enough: `-setsecurewebproxy` also records the server/port, so a bare state-off leaves 127.0.0.1:62443
// sitting in their config (disabled). That is a real trap (flipping "Web Proxy" on in System Settings
// later would point at a dead port), so we also clear the fields back to empty, restoring the config
// they actually had rather than merely a disabled version of ours.
func (s proxyState) restore() error {
	if s.enabled && s.server != "" {
		if _, err := runNetworksetup("-setsecurewebproxy", s.service, s.server, s.port); err != nil {
			return err
		}
		_, err := runNetworksetup("-setsecurewebproxystate", s.service, "on")
		return err
	}
	// No prior proxy. Restoring the (empty) server/port is COSMETIC and deliberately BEST-EFFORT: the
	// man page does not define -setsecurewebproxy's behaviour for empty values, and if it errors we must
	// NOT bail out before the disable below; that would leave the user's traffic pointed at a dead
	// proxy, turning a cosmetic nit into an outage. The disable is the load-bearing step.
	//
	// Order matters: -setsecurewebproxy "Turns proxy on" (its man page), so the state-off MUST come last.
	runNetworksetup("-setsecurewebproxy", s.service, s.server, s.port)
	_, err := runNetworksetup("-setsecurewebproxystate", s.service, "off")
	return err
}

// InstallProxy points every enabled network service's secure-web (HTTPS) proxy at the local decrypt
// proxy on 127.0.0.1:port, and returns a teardown that restores each service's PRIOR setting exactly.
// Requires root (networksetup writes system config). Replaces the non-viable pf rdr redirect.
//
// Signature mirrors the old InstallRedirect so the command's arm/teardown contract is unchanged; the
// bypass list is gone (a CONNECT proxy has no rule to except: a client either uses us or does not).
func InstallProxy(port int) (func() error, error) {
	svcs, err := networkServices()
	if err != nil {
		return nil, err
	}
	var prior []proxyState
	// undo restores whatever we already changed; no partial-arm can escape without a teardown.
	undo := func() {
		for _, st := range prior {
			st.restore()
		}
	}
	for _, svc := range svcs {
		st, err := getProxyState(svc)
		if err != nil {
			undo()
			return nil, err
		}
		if _, err := runNetworksetup("-setsecurewebproxy", svc, "127.0.0.1", fmt.Sprint(port)); err != nil {
			undo()
			return nil, err
		}
		prior = append(prior, st) // only after the set succeeded; this service now needs restoring
	}
	teardown := func() error {
		var firstErr error
		for _, st := range prior {
			if err := st.restore(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return teardown, nil
}
