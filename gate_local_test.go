package authy

// The local-account method through the gate, over HTTP only: these tests run
// at the production bcrypt cost (the cost variable belongs to package local),
// so they create at most one account each and never wait out the limiter.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// formToken loads a form page and returns its CSRF token; the cookie half of
// the double submit lands in the client's jar.
func formToken(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	res, body := get(t, c, u, nav)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token on %s (status %d): %.300s", u, res.StatusCode, body)
	}
	return m[1]
}

// createAccount drives /auth/setup as the first visitor would, leaving c
// signed in as alice.
func createAccount(t *testing.T, c *http.Client, app *httptest.Server) {
	t.Helper()
	tok := formToken(t, c, app.URL+"/auth/setup")
	res, body := do(t, c, "POST", app.URL+"/auth/setup",
		url.Values{"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct horse"}, "csrf": {tok}}, nil)
	if res.StatusCode != 200 || body != "hello app" {
		t.Fatalf("creating the account: %d %.200s", res.StatusCode, body)
	}
}

func signOut(t *testing.T, c *http.Client, app *httptest.Server) {
	t.Helper()
	if res, _ := get(t, c, app.URL+"/auth/logout", nav); res.Request.URL.Path != "/auth/logged-out" {
		t.Fatalf("sign-out landed at %s", res.Request.URL.Path)
	}
}

// --- no OIDC: the local account is the method ------------------------------

func TestLocalFirstLaunchRedirectsToSetup(t *testing.T) {
	app, _ := startApp(t, Config{})
	c := noRedirect(browser())

	res, _ := get(t, c, app.URL+"/some/page?a=b", nav)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/local?next=%2Fsome%2Fpage%3Fa%3Db" {
		t.Fatalf("navigation: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, _ = get(t, c, app.URL+res.Header.Get("Location"), nav)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/setup?next=%2Fsome%2Fpage%3Fa%3Db" {
		t.Fatalf("with no account /auth/local must hand over to setup: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := get(t, c, app.URL+"/api/x", map[string]string{"Sec-Fetch-Mode": "cors"}); res.StatusCode != 401 {
		t.Errorf("fetch: %d", res.StatusCode)
	}
}

func TestLocalSetupFlow(t *testing.T) {
	app, _ := startApp(t, Config{})
	c := browser()

	_, body := get(t, c, app.URL+"/some/page", nav)
	if !strings.Contains(body, "Create your account") {
		t.Fatalf("first launch should land on setup: %.300s", body)
	}
	tok := csrfRe.FindStringSubmatch(body)
	if tok == nil {
		t.Fatalf("no csrf field on the setup form: %.300s", body)
	}
	post := func(v url.Values) (*http.Response, string) {
		v.Set("csrf", tok[1])
		return do(t, c, "POST", app.URL+"/auth/setup", v, nil)
	}

	for name, tc := range map[string]struct {
		v    url.Values
		want string
		code int
	}{
		"short password": {url.Values{"username": {"alice"}, "password": {"short"}, "confirm": {"short"}}, "at least 8", 400},
		"long password":  {url.Values{"username": {"alice"}, "password": {strings.Repeat("x", 73)}, "confirm": {strings.Repeat("x", 73)}}, "at most 72", 400},
		"mismatch":       {url.Values{"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct hors3"}}, "do not match", 400},
		"no username":    {url.Values{"username": {"  "}, "password": {"correct horse"}, "confirm": {"correct horse"}}, "Enter a username", 400},
	} {
		res, body := post(tc.v)
		if res.StatusCode != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %.200s", name, res.StatusCode, body)
		}
	}
	// A forged token: refused, and nothing was created or signed in. (The 403
	// is a direct response, so the redirect-following client is fine here.)
	res, _ := do(t, c, "POST", app.URL+"/auth/setup",
		url.Values{"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct horse"}, "csrf": {"forged"}}, nil)
	if res.StatusCode != 403 {
		t.Fatalf("bad CSRF token accepted: %d", res.StatusCode)
	}
	if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 401 {
		t.Fatal("the failed attempts must not have signed anyone in")
	}

	res, body = post(url.Values{"username": {"alice"}, "password": {"correct horse"}, "confirm": {"correct horse"}, "next": {"/some/page"}})
	if res.StatusCode != 200 || body != "hello app" || res.Request.URL.Path != "/some/page" {
		t.Fatalf("setup should sign in and return to the page: %d %q at %s", res.StatusCode, body, res.Request.URL.Path)
	}
	_, body = get(t, c, app.URL+"/whoami", nil)
	for _, want := range []string{`"Subject":"local:alice"`, `"Name":"alice"`, `"Groups":null`} {
		if !strings.Contains(body, want) {
			t.Errorf("whoami is missing %s: %s", want, body)
		}
	}

	// A second visitor cannot create another account or take over.
	other := browser()
	otherTok := formToken(t, other, app.URL+"/auth/local")
	res, _ = do(t, noRedirect(other), "POST", app.URL+"/auth/setup",
		url.Values{"username": {"mallory"}, "password": {"hunter2hunter2"}, "confirm": {"hunter2hunter2"}, "csrf": {otherTok}}, nil)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/local" {
		t.Errorf("setup must be closed once an account exists: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := get(t, noRedirect(other), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Error("the refused setup must not have signed mallory in")
	}
	// And the original account is unchanged: alice still signs in.
	signOut(t, c, app)
	tok2 := formToken(t, c, app.URL+"/auth/local")
	res, body = do(t, c, "POST", app.URL+"/auth/local",
		url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {tok2}}, nil)
	if res.StatusCode != 200 || body != "hello app" {
		t.Errorf("alice must still sign in after the takeover attempt: %d %.200s", res.StatusCode, body)
	}
}

func TestLocalLoginLogoutAndRateLimit(t *testing.T) {
	app, _ := startApp(t, Config{})
	c := browser()
	createAccount(t, c, app)
	signOut(t, c, app)

	_, body := get(t, c, app.URL+"/dash", nav)
	if !strings.Contains(body, `action="/auth/local"`) || !strings.Contains(body, `type="password"`) || strings.Contains(body, "OpenID") {
		t.Fatalf("expected the local login form alone: %.300s", body)
	}
	tok := csrfRe.FindStringSubmatch(body)
	if tok == nil {
		t.Fatalf("no csrf field on the login form: %.300s", body)
	}
	login := func(user, pass string) (*http.Response, string) {
		return do(t, c, "POST", app.URL+"/auth/local",
			url.Values{"username": {user}, "password": {pass}, "csrf": {tok[1]}, "next": {"/dash"}}, nil)
	}

	// Usernames are case-sensitive, and the message gives nothing away.
	if res, body := login("ALICE", "correct horse"); res.StatusCode != 401 || !strings.Contains(body, "Invalid username or password") {
		t.Fatalf("usernames are case-sensitive: %d %.200s", res.StatusCode, body)
	}
	// Success resets the limiter and lands on next with the identity.
	res, body := login("alice", "correct horse")
	if res.StatusCode != 200 || body != "hello app" || res.Request.URL.Path != "/dash" {
		t.Fatalf("login: %d %q at %s", res.StatusCode, body, res.Request.URL.Path)
	}
	_, body = get(t, c, app.URL+"/whoami", nil)
	if !strings.Contains(body, `"Subject":"local:alice"`) {
		t.Errorf("whoami after a form login: %s", body)
	}
	signOut(t, c, app)
	if res, _ := get(t, noRedirect(c), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Fatalf("still signed in after logout: %d", res.StatusCode)
	}

	// Five failures block the sixth attempt, right password or wrong; the test
	// never waits the window out, so it asserts only on this side of it.
	for i := 0; i < 5; i++ {
		if res, body := login("alice", "wrong password"); res.StatusCode != 401 || !strings.Contains(body, "Invalid username or password") {
			t.Fatalf("wrong password #%d: %d %.200s", i, res.StatusCode, body)
		}
	}
	res, body = login("nobody", "wrong password")
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || !strings.Contains(body, "Too many failed attempts") {
		t.Errorf("limiter should block after 5 failures: %d Retry-After=%q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if res, _ := login("alice", "correct horse"); res.StatusCode != 429 {
		t.Errorf("the correct password must also wait out the window, got %d", res.StatusCode)
	}
	if res, _ := get(t, noRedirect(c), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Error("nothing during the block may have signed anyone in")
	}
}

func TestLocalCSRFAndMethods(t *testing.T) {
	app, _ := startApp(t, Config{})
	c := browser()
	createAccount(t, c, app)
	signOut(t, c, app)

	tok := formToken(t, c, app.URL+"/auth/local")
	good := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {tok}}

	if res, _ := do(t, noRedirect(c), "POST", app.URL+"/auth/local", good, map[string]string{"Sec-Fetch-Site": "cross-site"}); res.StatusCode != 403 {
		t.Errorf("cross-site POST accepted: %d", res.StatusCode)
	}
	if res, _ := do(t, noRedirect(browser()), "POST", app.URL+"/auth/local", good, nil); res.StatusCode != 403 {
		t.Errorf("POST without the CSRF cookie accepted: %d", res.StatusCode)
	}
	if res, _ := do(t, noRedirect(c), "PUT", app.URL+"/auth/local", good, nil); res.StatusCode != 405 {
		t.Errorf("PUT: %d", res.StatusCode)
	}
	if res, _ := get(t, noRedirect(c), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Error("none of the refused requests may sign in")
	}
}

// --- OIDC without local: the local routes do not exist ----------------------

func TestOIDCOnlyServesNoLocalRoutes(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	c := noRedirect(browser())

	for _, p := range []string{"/auth/setup", "/auth/local"} {
		res, body := get(t, c, app.URL+p, nav)
		if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/auth/oidc") {
			t.Errorf("%s must fall through to the OIDC redirect: %d %s", p, res.StatusCode, res.Header.Get("Location"))
		}
		if strings.Contains(body, "<form") || strings.Contains(body, "Create your account") {
			t.Errorf("%s must not render a form: %.200s", p, body)
		}
		if res, _ := get(t, c, app.URL+p, nil); res.StatusCode != 401 {
			t.Errorf("%s for a non-navigation must be 401: %d", p, res.StatusCode)
		}
		if res, _ := do(t, c, "POST", app.URL+p, url.Values{"username": {"a"}, "password": {"hunter2hunter2"}}, nil); res.StatusCode != 401 {
			t.Errorf("POST %s must be denied: %d", p, res.StatusCode)
		}
	}
}

// --- OIDC with the local account stacked as the escape hatch ----------------

func TestOIDCWithLocalEscapeHatch(t *testing.T) {
	idp := newFakeIdP(t)
	idp.Start()
	on := true
	app, _ := startApp(t, Config{OIDC: oidcCfg(idp), LocalLogin: &on})

	// An unauthenticated page load still goes straight to the IdP: stacking the
	// local account must not change the front door.
	if res, _ := get(t, noRedirect(browser()), app.URL+"/dash", nav); res.Header.Get("Location") != "/auth/oidc?next=%2Fdash" {
		t.Fatalf("navigation should go to the IdP first, got %s", res.Header.Get("Location"))
	}

	// Setup is open while no account exists (deliberate trust-on-first-use:
	// claim the account before exposing the app; see Config.LocalLogin).
	c := browser()
	createAccount(t, c, app)
	_, body := get(t, c, app.URL+"/whoami", nil)
	if !strings.Contains(body, `"Subject":"local:alice"`) {
		t.Fatalf("whoami after setup: %s", body)
	}
	signOut(t, c, app)

	// The IdP turns the user away; the fallback page offers both ways back in.
	idp.mu.Lock()
	idp.denyLogin = true
	idp.mu.Unlock()
	res, body := get(t, c, app.URL+"/dash", nav)
	if res.StatusCode != 200 || res.Request.URL.Path != "/auth/login" {
		t.Fatalf("expected the fallback page, got %d at %s", res.StatusCode, res.Request.URL)
	}
	for _, want := range []string{"Try again with OpenID Connect", "Try again with the local account", "/auth/local?next="} {
		if !strings.Contains(body, want) {
			t.Errorf("the fallback page is missing %q: %.400s", want, body)
		}
	}

	// The escape hatch end to end: the local form signs in although the IdP says no.
	tok := formToken(t, c, app.URL+"/auth/local?next=%2Fdash")
	res, body = do(t, c, "POST", app.URL+"/auth/local",
		url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {tok}, "next": {"/dash"}}, nil)
	if res.StatusCode != 200 || body != "hello app" || res.Request.URL.Path != "/dash" {
		t.Fatalf("local login with the IdP denying: %d %q at %s", res.StatusCode, body, res.Request.URL.Path)
	}

	// One sign-out ends the session whichever method made it.
	signOut(t, c, app)
	if res, _ := get(t, noRedirect(c), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Errorf("still signed in after logout: %d", res.StatusCode)
	}
}

func TestFallbackPageListsBothMethods(t *testing.T) {
	idp := newFakeIdP(t)
	idp.Start()
	on := true
	app, _ := startApp(t, Config{OIDC: oidcCfg(idp), LocalLogin: &on})

	_, body := get(t, browser(), app.URL+"/auth/login?next=/dash", nav)
	for _, want := range []string{"Sign in with OpenID Connect", "/auth/oidc?next=%2Fdash", "a new local account", "/auth/local?next=%2Fdash"} {
		if !strings.Contains(body, want) {
			t.Errorf("the sign-in page is missing %q: %.400s", want, body)
		}
	}
	if strings.Contains(body, "<form") {
		t.Errorf("the fallback page itself must not carry a form: %.300s", body)
	}
}
