//go:build integration

package integration

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// csrfFrom pulls the CSRF token out of a rendered form page; the cookie half
// of the double submit is already in the browser's jar from the same response.
func csrfFrom(t *testing.T, r *Resp) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(r.Body)
	if m == nil {
		t.Fatalf("no csrf token on %s (status %d): %.300s", r.URL, r.Status, r.Body)
	}
	return m[1]
}

// With no OIDC configuration at all the app is still protected: the first
// visitor creates the single local account, the account and the session
// survive a restart, and sign-out ends the session.
func TestLocalFirstLaunch(t *testing.T) {
	s := Up(t, "gate/local-first-launch")
	s.WaitReady()
	b := s.Browser()

	// First unauthenticated page load ends on the setup form.
	r := b.Get("/dash", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/setup" || !strings.Contains(r.Body, "Create your account") {
		t.Fatalf("first launch should land on setup: %d at %s: %.300s", r.Status, r.URL, r.Body)
	}
	r = b.Post("/auth/setup", url.Values{
		"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct horse"},
		"csrf": {csrfFrom(t, r)}, "next": {"/dash"},
	})
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") || r.URL.Path != "/dash" {
		t.Fatalf("setup should sign in and return to the page: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}

	// On disk: the account next to the gate's own state, and never a plaintext password.
	raw, err := os.ReadFile(filepath.Join(s.Dir, "data", "auth", "local.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "alice") || !strings.Contains(string(raw), "password_hash") {
		t.Errorf("local.json should hold the account: %s", raw)
	}
	if strings.Contains(string(raw), "correct horse") {
		t.Error("the password must never be stored in the clear")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "data", "auth", "auth.json")); err != nil {
		t.Errorf("auth.json should exist next to the account: %v", err)
	}

	// Both the session and the account survive a restart.
	s.Restart("subject")
	s.WaitReady()
	if r := b.Get("/", FetchAPI); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("the session did not survive a restart: %d", r.Status)
	}

	if r := b.Get("/auth/logout", Nav); r.URL.Path != "/auth/logged-out" || !strings.Contains(r.Body, "signed out") {
		t.Errorf("logout: %d at %s", r.Status, r.URL)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("still signed in after logout: %d", r.Status)
	}

	// Setup is closed for good: a new visitor gets the login form, not setup.
	b2 := s.Browser()
	r = b2.Get("/dash", Nav)
	if r.URL.Path != "/auth/local" || !strings.Contains(r.Body, `action="/auth/local"`) || strings.Contains(r.Body, "Create your account") {
		t.Fatalf("after setup every visitor gets the login form: %d at %s: %.300s", r.Status, r.URL, r.Body)
	}
	r = b2.Post("/auth/local", url.Values{
		"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrfFrom(t, r)}, "next": {"/dash"},
	})
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") || r.URL.Path != "/dash" {
		t.Errorf("login after the restart: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}
}

// OIDC with DEMO_LOCAL_ENABLED: the IdP owns the front door, but when it turns
// a login away the fallback page offers the local account, and that escape
// hatch works end to end.
func TestOIDCDeniedOffersTheLocalEscapeHatch(t *testing.T) {
	s := Up(t, "oidc/with-local")
	s.WaitReady()
	waitForOIDC(t, s)

	// Setup is open while no account exists, so the operator creates it first
	// (this is the documented, deliberate window).
	b := s.Browser()
	r := b.Get("/auth/setup", Nav)
	if r.Status != 200 || !strings.Contains(r.Body, "Create your account") {
		t.Fatalf("setup should be open before an account exists: %d %.300s", r.Status, r.Body)
	}
	r = b.Post("/auth/setup", url.Values{
		"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct horse"},
		"csrf": {csrfFrom(t, r)},
	})
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Fatalf("creating the account: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}
	if r := b.Get("/auth/logout", Nav); r.URL.Path != "/auth/logged-out" {
		t.Fatalf("logout landed at %s", r.URL)
	}

	// The IdP denies; the fallback page lists both ways back in.
	r = b.Get("/dash", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/login" {
		t.Fatalf("expected the fallback page after the IdP denied, got %d at %s", r.Status, r.URL)
	}
	for _, want := range []string{"Try again with OpenID Connect", "Try again with the local account", "/auth/local?next="} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("the fallback page is missing %q: %.400s", want, r.Body)
		}
	}

	// The local sign-in works although the IdP says no.
	r = b.Get("/auth/local?next=%2Fdash", Nav)
	if r.Status != 200 || !strings.Contains(r.Body, `action="/auth/local"`) {
		t.Fatalf("the local login form: %d at %s: %.300s", r.Status, r.URL, r.Body)
	}
	r = b.Post("/auth/local", url.Values{
		"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrfFrom(t, r)}, "next": {"/dash"},
	})
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") || r.URL.Path != "/dash" {
		t.Fatalf("local login: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}
	if r := b.Get("/", FetchAPI); r.Status != 200 {
		t.Errorf("session after the local login: %d", r.Status)
	}

	// Sign-out ends the locally-made session like any other.
	if r := b.Get("/auth/logout", Nav); r.URL.Path != "/auth/logged-out" {
		t.Errorf("logout landed at %s", r.URL)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("still signed in after logout: %d", r.Status)
	}
}
