//go:build darwin

package intercept

import (
	"errors"
	"strings"
	"testing"
)

type nsCall struct{ args []string }

// withFakeNetworksetup swaps the networksetup seam, returning the call log.
func withFakeNetworksetup(t *testing.T, respond func(args []string) (string, error)) *[]nsCall {
	t.Helper()
	calls := &[]nsCall{}
	orig := runNetworksetup
	t.Cleanup(func() { runNetworksetup = orig })
	runNetworksetup = func(args ...string) (string, error) {
		*calls = append(*calls, nsCall{args: args})
		return respond(args)
	}
	return calls
}

func argsHave(args []string, want ...string) bool {
	joined := strings.Join(args, " ")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			return false
		}
	}
	return true
}

const twoServices = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bridge\nProtonVPN\n"

// networkServices skips the preamble and DISABLED (*) services.
func TestNetworkServices_SkipsPreambleAndDisabled(t *testing.T) {
	withFakeNetworksetup(t, func([]string) (string, error) { return twoServices, nil })
	svcs, err := networkServices()
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 || svcs[0] != "Wi-Fi" || svcs[1] != "ProtonVPN" {
		t.Fatalf("expected [Wi-Fi ProtonVPN], got %v", svcs)
	}
}

// A user who ALREADY runs a proxy (Charles, a corporate one) must get it back byte-for-byte.
func TestInstallProxy_RestoresAPriorProxyExactly(t *testing.T) {
	calls := withFakeNetworksetup(t, func(args []string) (string, error) {
		switch {
		case argsHave(args, "-listallnetworkservices"):
			return "preamble\nWi-Fi\n", nil
		case argsHave(args, "-getsecurewebproxy"):
			return "Enabled: Yes\nServer: 10.0.0.9\nPort: 8888\n", nil
		}
		return "", nil
	})
	teardown, err := InstallProxy(62443)
	if err != nil {
		t.Fatal(err)
	}
	if err := teardown(); err != nil {
		t.Fatal(err)
	}
	restored := false
	for _, c := range *calls {
		if argsHave(c.args, "-setsecurewebproxy", "Wi-Fi", "10.0.0.9", "8888") {
			restored = true
		}
	}
	if !restored {
		t.Fatalf("a prior proxy must be restored exactly; calls=%v", *calls)
	}
}

// With no prior proxy, teardown clears our recorded server/port AND disables — and the disable must be
// LAST, because -setsecurewebproxy "Turns proxy on" (man networksetup).
func TestInstallProxy_TeardownClearsThenDisablesInOrder(t *testing.T) {
	calls := withFakeNetworksetup(t, func(args []string) (string, error) {
		switch {
		case argsHave(args, "-listallnetworkservices"):
			return "preamble\nWi-Fi\n", nil
		case argsHave(args, "-getsecurewebproxy"):
			return "Enabled: No\nServer:\nPort: 0\n", nil
		}
		return "", nil
	})
	teardown, err := InstallProxy(62443)
	if err != nil {
		t.Fatal(err)
	}
	if err := teardown(); err != nil {
		t.Fatal(err)
	}
	clearIdx, offIdx := -1, -1
	for i, c := range *calls {
		if argsHave(c.args, "-setsecurewebproxy", "Wi-Fi") && !argsHave(c.args, "127.0.0.1") {
			clearIdx = i
		}
		if argsHave(c.args, "-setsecurewebproxystate", "Wi-Fi", "off") {
			offIdx = i
		}
	}
	if clearIdx == -1 || offIdx == -1 {
		t.Fatalf("teardown must clear the fields and disable; calls=%v", *calls)
	}
	if offIdx < clearIdx {
		t.Fatalf("the disable must come LAST (-setsecurewebproxy turns the proxy back on); calls=%v", *calls)
	}
}

// The load-bearing guarantee: if clearing the fields FAILS (empty values are undocumented), the DISABLE
// must still run. Bailing out early would leave the user's traffic pointed at a dead proxy — a cosmetic
// nit turned into an outage.
func TestInstallProxy_DisableSurvivesAFailingClear(t *testing.T) {
	calls := withFakeNetworksetup(t, func(args []string) (string, error) {
		switch {
		case argsHave(args, "-listallnetworkservices"):
			return "preamble\nWi-Fi\n", nil
		case argsHave(args, "-getsecurewebproxy"):
			return "Enabled: No\nServer:\nPort: 0\n", nil
		case argsHave(args, "-setsecurewebproxy", "Wi-Fi") && !argsHave(args, "127.0.0.1"):
			return "", errors.New("networksetup: empty domain rejected")
		}
		return "", nil
	})
	teardown, err := InstallProxy(62443)
	if err != nil {
		t.Fatal(err)
	}
	teardown()
	for _, c := range *calls {
		if argsHave(c.args, "-setsecurewebproxystate", "Wi-Fi", "off") {
			return // disabled despite the failing clear — the guarantee holds
		}
	}
	t.Fatalf("the proxy MUST be disabled even when clearing the fields fails; calls=%v", *calls)
}

// A partial arm must not escape without a teardown: if setting a later service fails, the ones already
// pointed at us are restored before the error returns.
func TestInstallProxy_PartialFailureUndoesWhatItSet(t *testing.T) {
	calls := withFakeNetworksetup(t, func(args []string) (string, error) {
		switch {
		case argsHave(args, "-listallnetworkservices"):
			return "preamble\nWi-Fi\nProtonVPN\n", nil
		case argsHave(args, "-getsecurewebproxy"):
			return "Enabled: No\nServer:\nPort: 0\n", nil
		case argsHave(args, "-setsecurewebproxy", "ProtonVPN", "127.0.0.1"):
			return "", errors.New("nope")
		}
		return "", nil
	})
	if _, err := InstallProxy(62443); err == nil {
		t.Fatal("a failed set must fail loud")
	}
	for _, c := range *calls {
		if argsHave(c.args, "-setsecurewebproxystate", "Wi-Fi", "off") {
			return // Wi-Fi (already pointed at us) was undone
		}
	}
	t.Fatalf("a partial arm must undo the services it already set; calls=%v", *calls)
}
