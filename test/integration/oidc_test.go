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

// A page load goes to the IdP, the login completes through it, and the data
// directory holds only the signing key -- no account of any kind.
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

	// The contract an app's Sign out button relies on.
	js := b.Get("/auth/client.js", nil)
	if js.Status != 200 || !strings.HasPrefix(js.Header.Get("Content-Type"), "application/javascript") ||
		!strings.Contains(js.Body, `dataset.oidcgate="on"`) {
		t.Errorf("client.js: %d %s %q", js.Status, js.Header.Get("Content-Type"), js.Body)
	}

	// On disk: only the signing key and sign-out records; the gate has no accounts.
	raw, err := os.ReadFile(filepath.Join(s.Dir, "data", "auth", "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "session_key") ||
		strings.Contains(string(raw), "password_hash") || strings.Contains(string(raw), "username") {
		t.Errorf("auth.json should hold only the gate's own state: %s", raw)
	}
}

// The session key lives in the volume, so a restarted container still knows
// who you are; signing out is a confirmed POST and revokes the session.
func TestSessionSurvivesARestartAndLogoutEndsIt(t *testing.T) {
	s := Up(t, "oidc/first-launch")
	s.WaitReady()
	waitForOIDC(t, s)
	b := s.Browser()
	if r := b.Get("/", Nav); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Fatalf("sign-in: %d at %s", r.Status, r.URL)
	}

	s.Restart("subject")
	s.WaitReady()

	if r := b.Get("/", FetchAPI); r.Status != 200 || !strings.Contains(r.Body, "hello demo") {
		t.Errorf("the session did not survive a restart: %d", r.Status)
	}

	// Sign-out is a same-site navigation; the landing page keeps the browser
	// from bouncing back into the IdP's SSO session.
	if r := b.Get("/auth/logout", Nav); r.URL.Path != "/auth/logged-out" || !strings.Contains(r.Body, "signed out") {
		t.Errorf("logout: %d at %s", r.Status, r.URL)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("still signed in after logout: %d", r.Status)
	}
}

// The IdP does not approve: the user lands once on the fallback page with a
// retry button and no form. A loop would make the client give up after ten
// redirects.
func TestOIDCDeniedFallsBackWithoutLooping(t *testing.T) {
	s := Up(t, "oidc/idp-denies")
	s.WaitReady()
	waitForOIDC(t, s)
	b := s.Browser()

	r := b.Get("/dash", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/login" {
		t.Fatalf("expected the fallback page, got %d at %s", r.Status, r.URL)
	}
	for _, want := range []string{"Try again with OpenID Connect", "not approved by the identity provider"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("the fallback page is missing %q", want)
		}
	}
	if strings.Contains(r.Body, "<form") {
		t.Errorf("the fallback page must not have a form: %.300s", r.Body)
	}
	if r := b.Get("/", FetchAPI); r.Status != 401 {
		t.Errorf("the denied login must not have signed anyone in: %d", r.Status)
	}
}

// The IdP is not running when the app starts. The app starts anyway, explains
// that the provider is unreachable, and once the IdP appears starts using it
// without being restarted.
func TestOIDCProviderDownAtStartup(t *testing.T) {
	s := Up(t, "oidc/idp-down-at-start")
	s.WaitReady() // the subject is up although its provider is not

	b := s.Browser()
	r := b.Get("/", Nav)
	if r.Status != 200 || r.URL.Path != "/auth/login" || !strings.Contains(r.Body, "not reachable") || strings.Contains(r.Body, "<form") {
		t.Fatalf("with the IdP down, the fallback page must say so: %d at %s: %.300s", r.Status, r.URL, r.Body)
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
