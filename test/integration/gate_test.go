//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An app that deliberately relies on forward auth turns the gate off: nothing
// is protected, none of the gate's routes exist, and it says so in the log.
func TestAuthDisabledLeavesTheAppOpen(t *testing.T) {
	s := Up(t, "gate/auth-disabled")
	s.WaitReady()
	b := s.Browser()

	if r := b.Get("/", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("page: %d", r.Status)
	}
	if r := b.Get("/api/x", FetchAPI); r.Status != 200 {
		t.Errorf("api: %d", r.Status)
	}
	// client.js is a 404 here, which is what keeps an app's Sign out button hidden.
	if r := b.Get("/auth/client.js", nil); r.Status == 200 && strings.Contains(r.Body, "authy") {
		t.Errorf("client.js must not exist with the gate off: %d", r.Status)
	}
	if !strings.Contains(s.Logs("subject"), "auth: disabled") {
		t.Errorf("turning the gate off must be logged:\n%s", s.Logs("subject"))
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "data", "auth")); err == nil {
		t.Error("a disabled gate must not write anything to the data directory")
	}
}

// Half the required OIDC settings: refuse to start, and name the missing ones.
func TestMisconfiguredOIDCRefusesToStart(t *testing.T) {
	s := Up(t, "gate/misconfigured")
	var code string
	waitFor(t, "the subject to exit", 20*time.Second, func() bool {
		var done bool
		done, code = s.Exited("subject")
		return done
	}, func() string { return s.Logs("subject") })

	if code == "0" {
		t.Errorf("exit code %s: a misconfigured gate must fail, not exit cleanly", code)
	}
	logs := s.Logs("subject")
	for _, v := range []string{"DEMO_OIDC_CLIENT_ID", "DEMO_OIDC_CLIENT_SECRET", "DEMO_OIDC_BASE_URL"} {
		if !strings.Contains(logs, v) {
			t.Errorf("the error should name %s:\n%s", v, logs)
		}
	}
}

// A data directory the process cannot write: refuse to start, pointing at it,
// rather than run and lose every session at the first restart.
func TestUnwritableDataDirectoryRefusesToStart(t *testing.T) {
	s := Up(t, "gate/unwritable-data")
	var code string
	waitFor(t, "the subject to exit", 20*time.Second, func() bool {
		var done bool
		done, code = s.Exited("subject")
		return done
	}, func() string { return s.Logs("subject") })

	if code == "0" {
		t.Errorf("exit code %s: must fail", code)
	}
	if logs := s.Logs("subject"); !strings.Contains(logs, "/app/data/auth") || !strings.Contains(logs, "writable") {
		t.Errorf("the error should point at the directory and say why:\n%s", logs)
	}
}
