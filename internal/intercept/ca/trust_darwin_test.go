//go:build darwin

package ca

import (
	"strings"
	"testing"
)

func TestTrust_InstallUninstallArgs(t *testing.T) {
	var got [][]string
	orig := runSecurity
	runSecurity = func(args ...string) error { got = append(got, args); return nil }
	defer func() { runSecurity = orig }()

	ca, _ := NewCA()
	if err := InstallTrust(ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	if err := UninstallTrust(ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 security calls, got %d", len(got))
	}
	if got[0][0] != "add-trusted-cert" || !contains(got[0], "trustRoot") || !contains(got[0], "-d") {
		t.Fatalf("install args wrong: %v", got[0])
	}
	if got[1][0] != "remove-trusted-cert" {
		t.Fatalf("uninstall args wrong: %v", got[1])
	}
	// the last arg is a real temp file path (written + present at call time)
	if !strings.HasSuffix(got[0][len(got[0])-1], ".pem") {
		t.Fatalf("install should pass a .pem path: %v", got[0])
	}
}

// a security failure must propagate (fail loud), not be swallowed.
func TestTrust_ErrorPropagates(t *testing.T) {
	orig := runSecurity
	runSecurity = func(args ...string) error { return errTest }
	defer func() { runSecurity = orig }()
	if err := InstallTrust([]byte("x")); err == nil {
		t.Fatal("a security failure must propagate")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var errTest = &trustErr{}

type trustErr struct{}

func (*trustErr) Error() string { return "boom" }
