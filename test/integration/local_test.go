//go:build integration

package integration

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	user = "alice"
	pass = "correct horse battery"
)

// First launch, with no IdP: the first visitor is sent to account creation,
// the setup form validates, and what lands on disk is a hash in a private file.
func TestFirstLaunchCreatesTheAccount(t *testing.T) {
	s := Up(t, "local/first-launch")
	s.WaitReady()
	b := s.Browser()

	// Page loads go to setup; scripts and API clients get 401; /healthz stays public.
	r := b.Still().Get("/page?x=1", Nav)
	if r.Status != 302 || r.Header.Get("Location") != "/auth/setup?next=%2Fpage%3Fx%3D1" {
		t.Errorf("page load: %d -> %s", r.Status, r.Header.Get("Location"))
	}
	if r := b.Get("/api/x", FetchAPI); r.Status != 401 || !strings.Contains(r.Body, "unauthorized") {
		t.Errorf("fetch: %d %q", r.Status, r.Body)
	}

	// The contract an app's Sign out button relies on.
	js := b.Get("/auth/client.js", nil)
	if js.Status != 200 || !strings.HasPrefix(js.Header.Get("Content-Type"), "application/javascript") ||
		!strings.Contains(js.Body, `dataset.oidcgate="on"`) {
		t.Errorf("client.js: %d %s %q", js.Status, js.Header.Get("Content-Type"), js.Body)
	}

	tok := b.Token("/auth/setup")
	if r := b.Post("/auth/setup", url.Values{"csrf": {tok}, "username": {user}, "password": {"short"}, "confirm": {"short"}}); r.Status != 400 || !strings.Contains(r.Body, "at least 8") {
		t.Errorf("weak password: %d", r.Status)
	}
	r = b.Post("/auth/setup", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}, "confirm": {pass}, "next": {"/page"}})
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") || r.URL.Path != "/page" {
		t.Fatalf("setup should sign in and return to the page: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}

	// On disk, as the process wrote it: a private directory, a private file,
	// the password only as a bcrypt hash.
	dir := filepath.Join(s.CopyOut("subject", "/app/data/auth"), "auth")
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Errorf("modes: dir %v file %v, want 0700/0600", di.Mode().Perm(), fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "auth.json"))
	if !strings.Contains(string(raw), "$2a$") || strings.Contains(string(raw), pass) {
		t.Errorf("the password must be stored only as a bcrypt hash")
	}

	// Setup is closed: a second visitor cannot take the app over.
	other := s.Browser()
	otok := other.Token("/auth/login")
	if r := other.Still().Post("/auth/setup", url.Values{"csrf": {otok}, "username": {"mallory"}, "password": {"hunter2hunter2"}, "confirm": {"hunter2hunter2"}}); r.Status != 302 {
		t.Errorf("setup must be closed once an account exists: %d", r.Status)
	}
	if r := other.Post("/auth/login", url.Values{"csrf": {otok}, "username": {"mallory"}, "password": {"hunter2hunter2"}}); r.Status != 401 {
		t.Errorf("a second account must not exist: %d", r.Status)
	}
}

// The account and the session key live in the volume, so a restarted
// container still knows who you are, and nobody gets a second setup page.
func TestSessionAndAccountSurviveARestart(t *testing.T) {
	s := Up(t, "local/first-launch")
	s.WaitReady()
	b := s.Browser()
	tok := b.Token("/auth/setup")
	if r := b.Post("/auth/setup", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}, "confirm": {pass}}); r.Status != 200 {
		t.Fatalf("setup: %d", r.Status)
	}

	s.Restart("subject")
	s.WaitReady()

	if r := b.Get("/", FetchAPI); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("the session did not survive a restart: %d", r.Status)
	}
	if r := s.Browser().Still().Get("/", Nav); r.Status != 302 || strings.HasPrefix(r.Header.Get("Location"), "/auth/setup") {
		t.Errorf("after a restart a new visitor must get the login page, not setup: %d -> %s", r.Status, r.Header.Get("Location"))
	}

	// Sign out ends the session; the account still works.
	if r := b.Get("/auth/logout", Nav); r.URL.Path != "/auth/logged-out" || !strings.Contains(r.Body, "signed out") {
		t.Errorf("logout: %s", r.URL)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("still signed in after logout: %d", r.Status)
	}
	tok = b.Token("/auth/login")
	if r := b.Post("/auth/login", url.Values{"csrf": {tok}, "username": {user}, "password": {"wrong wrong wrong"}}); r.Status != 401 {
		t.Errorf("wrong password: %d", r.Status)
	}
	if r := b.Post("/auth/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}}); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("login after restart: %d", r.Status)
	}
}

// An app that deliberately relies on forward auth turns the gate off: nothing
// is protected, none of the gate's routes exist, and it says so in the log.
func TestAuthDisabledLeavesTheAppOpen(t *testing.T) {
	s := Up(t, "local/auth-disabled")
	s.WaitReady()
	b := s.Browser()

	if r := b.Get("/", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("page: %d", r.Status)
	}
	if r := b.Get("/api/x", FetchAPI); r.Status != 200 {
		t.Errorf("api: %d", r.Status)
	}
	// client.js is a 404 here, which is what keeps an app's Sign out button hidden.
	if r := b.Get("/auth/client.js", nil); r.Status == 200 && strings.Contains(r.Body, "oidcgate") {
		t.Errorf("client.js must not exist with the gate off: %d", r.Status)
	}
	if r := b.Get("/auth/setup", Nav); strings.Contains(r.Body, "Create your account") {
		t.Error("the setup page must not exist with the gate off")
	}
	if !strings.Contains(s.Logs("subject"), "auth: disabled") {
		t.Errorf("turning the gate off must be logged:\n%s", s.Logs("subject"))
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "data", "auth")); err == nil {
		t.Error("a disabled gate must not write anything to the data directory")
	}
}

// OIDC switched on with half its settings: refuse to start, and name them.
func TestMisconfiguredOIDCRefusesToStart(t *testing.T) {
	s := Up(t, "local/misconfigured")
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
// rather than run and lose the account at the first restart.
func TestUnwritableDataDirectoryRefusesToStart(t *testing.T) {
	s := Up(t, "local/unwritable-data")
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
