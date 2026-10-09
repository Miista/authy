//go:build integration

package integration

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitForOIDC waits until the subject has found its provider: a page load is
// then sent to /auth/oidc. The subject and the IdP start together, so the
// first discovery can lose the race and the gate retries; this is the
// convergence the rest of the test needs.
func waitForOIDC(t *testing.T, s *Scenario) {
	t.Helper()
	waitFor(t, "the subject to find the identity provider", 60*time.Second, func() bool {
		r, err := s.Browser().Still().try("GET", "/", nil, Nav)
		return err == nil && r.Status == 302 && strings.HasPrefix(r.Header.Get("Location"), "/auth/oidc")
	}, func() string { return s.Logs("subject") + "\n" + s.Logs("fakeidp") })
}

// OIDC from the first launch: a page load goes to the IdP, the login completes
// through it, no local account is created, and setup stays closed.
func TestOIDCFirstLaunchGoesStraightToTheIdP(t *testing.T) {
	s := Up(t, "oidc/first-launch")
	s.WaitReady()
	waitForOIDC(t, s)
	b := s.Browser()

	// The hops, one at a time: the gate, then the IdP with PKCE.
	r := b.Still().Get("/dash", Nav)
	if r.Status != 302 || r.Header.Get("Location") != "/auth/oidc?next=%2Fdash" {
		t.Fatalf("expected the gate to send the page load to /auth/oidc: %d -> %s", r.Status, r.Header.Get("Location"))
	}
	r = b.Still().Get("/auth/oidc?next=%2Fdash", nil)
	loc := r.Header.Get("Location")
	if r.Status != 302 || !strings.HasPrefix(loc, idpURL+"/authorize?") || !strings.Contains(loc, "code_challenge_method=S256") ||
		!strings.Contains(loc, "redirect_uri="+url.QueryEscape(subjectURL+"/auth/callback")) {
		t.Fatalf("authorize redirect: %d -> %s", r.Status, loc)
	}

	// The whole flow, followed like a browser would.
	r = b.Get("/dash?x=1", Nav)
	if r.Status != 200 || !strings.Contains(r.Body, "hello demo") || r.URL.Path != "/dash" || r.URL.RawQuery != "x=1" {
		t.Fatalf("sign-in through the IdP: %d at %s: %.200s", r.Status, r.URL, r.Body)
	}
	if r := b.Get("/", FetchAPI); r.Status != 200 {
		t.Errorf("session after the OIDC login: %d", r.Status)
	}

	// No account was created, and nobody can claim the app by being first.
	if r := s.Browser().Still().Get("/auth/setup", Nav); r.Status != 302 || r.Header.Get("Location") != "/auth/login" {
		t.Errorf("setup must be closed with OIDC: %d -> %s", r.Status, r.Header.Get("Location"))
	}
	raw, err := os.ReadFile(filepath.Join(s.Dir, "data", "auth", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password_hash") || strings.Contains(string(raw), "username") {
		t.Errorf("no local account should exist: %s", raw)
	}
}

// An account exists and OIDC is configured: the IdP is still tried first, and
// the local form stays reachable at /auth/login (the way in if the IdP is down).
func TestOIDCWithAnAccountStillTriesTheIdPFirst(t *testing.T) {
	s := Up(t, "oidc/with-account")
	s.WaitReady()
	waitForOIDC(t, s)

	if r := s.Browser().Get("/dash", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("OIDC login with an existing account: %d at %s", r.Status, r.URL)
	}

	b := s.Browser()
	page := b.Get("/auth/login", Nav)
	if !strings.Contains(page.Body, `action="/auth/login"`) || !strings.Contains(page.Body, "Sign in with OpenID Connect") {
		t.Fatalf("/auth/login must offer the local form and the OIDC button: %.300s", page.Body)
	}
	tok := b.Token("/auth/login")
	if r := b.Post("/auth/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}}); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("local login while OIDC is configured: %d", r.Status)
	}
}

// The IdP does not approve: the user lands once on a page with the local form
// and a retry button. A loop would make the client give up after ten redirects.
func TestOIDCDeniedFallsBackToTheLocalForm(t *testing.T) {
	s := Up(t, "oidc/idp-denies")
	s.WaitReady()
	waitForOIDC(t, s)
	b := s.Browser()

	r := b.Get("/dash", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/login" {
		t.Fatalf("expected the sign-in page, got %d at %s", r.Status, r.URL)
	}
	for _, want := range []string{`action="/auth/login"`, "Try again with OpenID Connect", "not approved by the identity provider"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("the fallback page is missing %q", want)
		}
	}
	tok := b.Token("/auth/login")
	if r := b.Post("/auth/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}}); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("the local form must work from the fallback page: %d", r.Status)
	}
}

// The IdP is not running when the app starts. The app starts anyway, the local
// login keeps working, and once the IdP appears the app starts using it
// without being restarted.
func TestOIDCProviderDownAtStartup(t *testing.T) {
	s := Up(t, "oidc/idp-down-at-start")
	s.WaitReady() // the subject is up although its provider is not

	b := s.Browser()
	r := b.Get("/", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/login" || !strings.Contains(r.Body, `action="/auth/login"`) {
		t.Fatalf("with the IdP down, the local form must be the way in: %d at %s", r.Status, r.URL)
	}
	tok := b.Token("/auth/login")
	if r := b.Post("/auth/login", url.Values{"csrf": {tok}, "username": {user}, "password": {pass}}); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("local login while the IdP is down: %d", r.Status)
	}
	if !strings.Contains(s.Logs("subject"), "not reachable yet") {
		t.Errorf("the log should say the provider is unreachable and retrying:\n%s", s.Logs("subject"))
	}

	s.StartService("fakeidp")
	waitForOIDC(t, s) // found by the background retry; the subject was not restarted

	if r := s.Browser().Get("/dash", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("sign-in through the IdP after it came up: %d at %s", r.Status, r.URL)
	}
}

// OIDC is the only way in: the local form is gone from the page and the
// server refuses it, so a hidden form is not all that stands in the way.
func TestOIDCOnlyWhenBuiltInLoginIsDisabled(t *testing.T) {
	s := Up(t, "oidc/built-in-disabled")
	s.WaitReady()
	waitForOIDC(t, s)

	b := s.Browser()
	page := b.Get("/auth/login", Nav)
	if strings.Contains(page.Body, "<form") || !strings.Contains(page.Body, "OpenID Connect") {
		t.Errorf("the local form must be gone: %.300s", page.Body)
	}
	// Give the browser a matching CSRF cookie and field (the check is a
	// double-submit, so a client that sets both passes it), so the request gets
	// past CSRF and reaches the decision that is under test: the server's own
	// refusal, not the absence of a form.
	su, _ := url.Parse(subjectURL)
	b.Jar.SetCookies(su, []*http.Cookie{{Name: "demo_csrf", Value: "x", Path: "/auth"}})
	r := b.Post("/auth/login", url.Values{"csrf": {"x"}, "username": {user}, "password": {pass}})
	if r.Status != 403 || !strings.Contains(r.Body, "Local sign-in is disabled") {
		t.Errorf("local login must be refused by the server: %d %.200s", r.Status, r.Body)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("the refused login must not have signed anyone in: %d", r.Status)
	}
	if r := s.Browser().Get("/dash", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("OIDC login: %d", r.Status)
	}
}
