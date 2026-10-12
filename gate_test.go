package oidcgate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// --- fake IdP ----------------------------------------------------------

// fakeIdP is a minimal OIDC provider: discovery, authorize (auto-approves),
// token (verifies PKCE and the client secret) and JWKS.
type fakeIdP struct {
	URL string
	l   net.Listener
	key *rsa.PrivateKey
	mux *http.ServeMux

	mu        sync.Mutex
	challenge map[string]string // code -> PKCE challenge
	nonce     map[string]string // code -> nonce
	badNonce  bool              // return a wrong nonce in the id_token
	denyLogin bool              // authorize returns access_denied

	idClaims     map[string]any // extra claims in the id_token
	userinfo     map[string]any // served by /userinfo; nil: the endpoint answers 404
	userinfoSub  string         // the "sub" /userinfo reports; default user-1
	scopes       []string       // the scope parameter of the last authorize request
	userinfoHits int
}

// newFakeIdP reserves an address; Start brings it up. Splitting them lets a
// test begin with the provider unreachable.
func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{URL: "http://" + l.Addr().String(), l: l, key: key, mux: http.NewServeMux(),
		challenge: map[string]string{}, nonce: map[string]string{}}
	t.Cleanup(func() { l.Close() })

	f.mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/authorize",
			"token_endpoint":                        f.URL + "/token",
			"jwks_uri":                              f.URL + "/jwks",
			"userinfo_endpoint":                     f.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	f.mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	f.mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("state", q.Get("state"))
		f.mu.Lock()
		f.scopes = strings.Fields(q.Get("scope"))
		if f.denyLogin {
			rq.Set("error", "access_denied")
		} else {
			code := randString()
			f.challenge[code] = q.Get("code_challenge")
			f.nonce[code] = q.Get("nonce")
			rq.Set("code", code)
		}
		f.mu.Unlock()
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	f.mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if id, secret, ok := r.BasicAuth(); !ok || id != "cid" || secret != "csecret" {
			if r.FormValue("client_id") != "cid" || r.FormValue("client_secret") != "csecret" {
				http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
				return
			}
		}
		code := r.FormValue("code")
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if want, ok := f.challenge[code]; !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != want {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		nonce := f.nonce[code]
		if f.badNonce {
			nonce = "wrong"
		}
		delete(f.challenge, code)

		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		raw, _ := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:   f.URL,
			Subject:  "user-1",
			Audience: jwt.Audience{"cid"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		}).Claims(f.tokenClaims(nonce)).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
	})
	return f
}

// tokenClaims are the id_token's claims beyond the standard ones. Callers hold f.mu.
func (f *fakeIdP) tokenClaims(nonce string) map[string]any {
	m := map[string]any{"nonce": nonce, "email": "a@example.com"}
	for k, v := range f.idClaims {
		m[k] = v
	}
	return m
}

func (f *fakeIdP) Start() {
	f.mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.userinfoHits++
		if f.userinfo == nil || r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		sub := f.userinfoSub
		if sub == "" {
			sub = "user-1"
		}
		m := map[string]any{"sub": sub}
		for k, v := range f.userinfo {
			m[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m)
	})
	go http.Serve(f.l, f.mux)
}

// --- app harness -------------------------------------------------------

var inner = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		io.WriteString(w, "ok")
		return
	}
	if r.URL.Path == "/whoami" {
		u, ok := UserFrom(r)
		json.NewEncoder(w).Encode(map[string]any{"ok": ok, "user": u})
		return
	}
	io.WriteString(w, "hello app")
})

// startApp serves `inner` behind a gate built from cfg. cfg.OIDC is required
// (the gate has no login of its own); its BaseURL defaults to the server's URL.
func startApp(t *testing.T, cfg Config) (*httptest.Server, *Gate) {
	t.Helper()
	var g *Gate
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Wrap(inner).ServeHTTP(w, r)
	}))
	t.Cleanup(app.Close)

	cfg.App = "my-app"
	cfg.Logger = quiet
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	if cfg.OIDC != nil && cfg.OIDC.BaseURL == "" {
		cfg.OIDC.BaseURL = app.URL
	}
	var err error
	if g, err = New(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return app, g
}

// startOIDCApp starts a fake IdP and an app gated by it: the common case.
func startOIDCApp(t *testing.T) (*httptest.Server, *Gate, *fakeIdP) {
	t.Helper()
	idp := newFakeIdP(t)
	idp.Start()
	app, g := startApp(t, Config{OIDC: oidcCfg(idp)})
	return app, g, idp
}

func oidcCfg(idp *fakeIdP) *OIDCConfig {
	return &OIDCConfig{Issuer: idp.URL, ClientID: "cid", ClientSecret: "csecret"}
}

func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func noRedirect(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

var nav = map[string]string{"Sec-Fetch-Mode": "navigate"}

func do(t *testing.T, c *http.Client, method, u string, form url.Values, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, u, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func get(t *testing.T, c *http.Client, u string, hdr map[string]string) (*http.Response, string) {
	return do(t, c, http.MethodGet, u, nil, hdr)
}

// signedIn returns a browser signed in through the fake IdP (it auto-approves).
func signedIn(t *testing.T, app *httptest.Server) *http.Client {
	t.Helper()
	c := browser()
	res, body := get(t, c, app.URL+"/", nav)
	if res.StatusCode != 200 || body != "hello app" {
		t.Fatalf("OIDC sign-in failed: %d %.200s", res.StatusCode, body)
	}
	return c
}

// --- routing -------------------------------------------------------------

func TestUnauthenticatedRequestRouting(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	c := noRedirect(browser())

	res, _ := get(t, c, app.URL+"/page?a=b", nav)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/oidc?next=%2Fpage%3Fa%3Db" {
		t.Errorf("navigation: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, body := get(t, c, app.URL+"/api/x", map[string]string{"Sec-Fetch-Mode": "cors"}); res.StatusCode != 401 || !strings.Contains(body, "unauthorized") {
		t.Errorf("fetch: %d %q", res.StatusCode, body)
	}
	if res, _ := get(t, c, app.URL+"/api/x", nil); res.StatusCode != 401 {
		t.Errorf("plain API client: %d", res.StatusCode)
	}
	if res, body := get(t, c, app.URL+"/healthz", nil); res.StatusCode != 200 || body != "ok" {
		t.Errorf("healthz should be public: %d %q", res.StatusCode, body)
	}
}

func TestClientJS(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	res, body := get(t, noRedirect(browser()), app.URL+"/auth/client.js", nil)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/javascript") {
		t.Fatalf("client.js: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if !strings.Contains(body, `dataset.oidcgate="on"`) || !strings.Contains(body, "/auth/logout") {
		t.Errorf("unexpected script: %q", body)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("client.js should be nosniff")
	}
}

// --- fallback page -------------------------------------------------------

func TestFallbackPage(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	c := noRedirect(browser())

	_, body := get(t, c, app.URL+"/auth/login?next=/dash", nav)
	if !strings.Contains(body, "Sign in with OpenID Connect") || !strings.Contains(body, "/auth/oidc?next=%2Fdash") {
		t.Errorf("the fallback page must offer the OIDC button: %.300s", body)
	}
	if strings.Contains(body, "<form") || strings.Contains(body, `type="password"`) {
		t.Errorf("the fallback page must not have a form: %.300s", body)
	}
	_, body = get(t, c, app.URL+"/auth/login?error=unavailable", nav)
	if !strings.Contains(body, "Sign-in failed") || !strings.Contains(body, "not reachable") {
		t.Errorf("?error=unavailable: %.300s", body)
	}
	if res, _ := do(t, c, "POST", app.URL+"/auth/login", url.Values{"username": {"alice"}, "password": {"x"}}, nil); res.StatusCode != 405 {
		t.Errorf("POST to the fallback page must be 405: %d", res.StatusCode)
	}
}

func TestUndiscoveredProviderSendsNavigationToTheFallbackPage(t *testing.T) {
	idp := newFakeIdP(t) // reserved but not started: unreachable
	app, _ := startApp(t, Config{OIDC: oidcCfg(idp), retryBase: time.Hour})

	res, _ := get(t, noRedirect(browser()), app.URL+"/dash", nav)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/login?next=%2Fdash&error=unavailable" {
		t.Errorf("navigation with the provider undiscovered: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := get(t, browser(), app.URL+"/", nav)
	if res.StatusCode != 200 || res.Request.URL.Path != "/auth/login" || !strings.Contains(body, "not reachable") || strings.Contains(body, "<form") {
		t.Errorf("fallback page: %d at %s: %.200s", res.StatusCode, res.Request.URL, body)
	}
}

// --- logout --------------------------------------------------------------

func TestLogoutIsASameSiteNavigation(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	c := signedIn(t, app)

	// A cross-site navigation must never sign out (forced-logout CSRF).
	if res, _ := get(t, noRedirect(c), app.URL+"/auth/logout", map[string]string{"Sec-Fetch-Site": "cross-site"}); res.StatusCode != 403 {
		t.Errorf("cross-site logout accepted: %d", res.StatusCode)
	}
	if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 200 {
		t.Errorf("a refused logout must not sign out: %d", res.StatusCode)
	}
	// The app's own sign-out link is a same-origin GET navigation.
	res, _ := get(t, c, app.URL+"/auth/logout", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin"})
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/logged-out" {
		t.Errorf("logout landing: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 401 {
		t.Errorf("still signed in after logout: %d", res.StatusCode)
	}
}

func TestLogoutRevokesEveryCopyOfTheSession(t *testing.T) {
	app, g, _ := startOIDCApp(t)
	c := signedIn(t, app)

	// An attacker steals a copy of the session cookie before the user signs out.
	appURL, _ := url.Parse(app.URL)
	var stolen *http.Cookie
	for _, ck := range c.Jar.Cookies(appURL) {
		if ck.Name == g.sessionCookie {
			stolen = ck
		}
	}
	if stolen == nil {
		t.Fatal("no session cookie to steal")
	}

	if res, _ := get(t, c, app.URL+"/auth/logout", nav); res.Request.URL.Path != "/auth/logged-out" {
		t.Fatalf("logout landed at %s", res.Request.URL.Path)
	}

	thief := noRedirect(browser())
	thief.Jar.SetCookies(appURL, []*http.Cookie{stolen})
	if res, _ := get(t, thief, app.URL+"/api", nil); res.StatusCode != 401 {
		t.Errorf("a stolen cookie must die with the sign-out: %d", res.StatusCode)
	}
}

func TestSessionsEndAtTheAbsoluteCap(t *testing.T) {
	app, g, _ := startOIDCApp(t)
	c := noRedirect(browser())

	// A session created maxSessionFactor×TTL ago is dead even with a fresh Exp,
	// so sliding renewal cannot keep one sign-in alive forever.
	old := time.Now().Add(-time.Duration(maxSessionFactor)*g.ttl - time.Hour)
	claims := sessionClaims{Exp: time.Now().Add(g.ttl).Unix(), Iat: old.Unix(), SID: randString(), U: newSessionUser("user-1", "alice", "", nil)}
	appURL, _ := url.Parse(app.URL)
	c.Jar.SetCookies(appURL, []*http.Cookie{{Name: g.sessionCookie, Value: g.seal(purposeSession, claims)}})
	if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 401 {
		t.Errorf("a session past the absolute cap must be rejected: %d", res.StatusCode)
	}
}

func TestLogoutMethods(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	c := signedIn(t, app)

	if res, _ := do(t, noRedirect(c), "POST", app.URL+"/auth/logout", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); res.StatusCode != 403 {
		t.Errorf("cross-site POST accepted: %d", res.StatusCode)
	}
	if res, _ := do(t, noRedirect(c), "PUT", app.URL+"/auth/logout", nil, nil); res.StatusCode != 405 {
		t.Errorf("PUT: %d", res.StatusCode)
	}
	if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 200 {
		t.Errorf("none of the refused requests may sign out: %d", res.StatusCode)
	}
}

// --- sessions ------------------------------------------------------------

func TestSessionCookieValidation(t *testing.T) {
	app, g, _ := startOIDCApp(t)
	u, _ := url.Parse(app.URL)
	c := noRedirect(browser())
	set := func(val string) {
		c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: val, Path: "/"}})
	}
	valid := g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()})
	set(valid)
	if res, _ := get(t, c, app.URL+"/", nil); res.StatusCode != 200 {
		t.Fatalf("valid cookie rejected: %d", res.StatusCode)
	}
	other := startOtherKey(t)
	for name, v := range map[string]string{
		"forged key":  other.seal(purposeSession, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()}),
		"tampered":    "e30" + valid[strings.Index(valid, "."):],
		"expired":     g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(-time.Minute).Unix()}),
		"wrong kind":  g.seal(purposeFlow, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()}),
		"garbage":     "nonsense",
		"empty parts": ".",
	} {
		set(v)
		if res, _ := get(t, c, app.URL+"/", nil); res.StatusCode != 401 {
			t.Errorf("%s: accepted (%d)", name, res.StatusCode)
		}
	}
}

// startOtherKey makes an unrelated gate, to forge cookies with a different key.
func startOtherKey(t *testing.T) *Gate {
	idp := newFakeIdP(t)
	idp.Start()
	cfg := oidcCfg(idp)
	cfg.BaseURL = "http://localhost:1"
	g, err := New(context.Background(), Config{App: "my-app", DataDir: t.TempDir(), Logger: quiet, OIDC: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSlidingSessionRefresh(t *testing.T) {
	app, g, _ := startOIDCApp(t)
	c := noRedirect(browser())
	u, _ := url.Parse(app.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Path: "/",
		Value: g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()})}})
	res, _ := get(t, c, app.URL+"/", nil)
	if res.StatusCode != 200 || len(res.Cookies()) == 0 {
		t.Errorf("expected a refreshed cookie, got status %d, cookies %v", res.StatusCode, res.Cookies())
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	idp := newFakeIdP(t)
	idp.Start()
	app, _ := startApp(t, Config{DataDir: dir, OIDC: oidcCfg(idp)})
	c := signedIn(t, app)
	u, _ := url.Parse(app.URL)

	// "Restart": a new Gate over the same directory, behind a new server.
	cfg := oidcCfg(idp)
	cfg.BaseURL = app.URL
	g2, err := New(context.Background(), Config{App: "my-app", DataDir: dir, Logger: quiet, OIDC: cfg})
	if err != nil {
		t.Fatal(err)
	}
	app2 := httptest.NewServer(g2.Wrap(inner))
	t.Cleanup(app2.Close)
	u2, _ := url.Parse(app2.URL)
	c.Jar.SetCookies(u2, c.Jar.Cookies(u))
	if res, body := get(t, noRedirect(c), app2.URL+"/", nil); res.StatusCode != 200 || body != "hello app" {
		t.Errorf("session did not survive a restart: %d", res.StatusCode)
	}
}

func TestStoreFilePermissions(t *testing.T) {
	dir := t.TempDir() + "/auth"
	startOIDCAppAt(t, dir)
	di, _ := os.Stat(dir)
	fi, err := os.Stat(dir + "/auth.json")
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Errorf("modes: dir %v file %v, want 0700/0600", di.Mode().Perm(), fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(dir + "/auth.json")
	if !strings.Contains(string(raw), "session_key") {
		t.Error("auth.json should hold the session key")
	}
}

func startOIDCAppAt(t *testing.T, dir string) {
	t.Helper()
	idp := newFakeIdP(t)
	idp.Start()
	startApp(t, Config{DataDir: dir, OIDC: oidcCfg(idp)})
}

func TestNewFailsWhenDataDirNotWritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	_, err := New(context.Background(), Config{App: "my-app", DataDir: ro + "/auth", Logger: quiet})
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("expected a clear data-directory error, got %v", err)
	}
}

func TestPagesEscapeInput(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	_, body := get(t, browser(), app.URL+`/auth/login?next=/%22%3E%3Cscript%3Ealert(1)%3C/script%3E`, nav)
	if strings.Contains(body, "<script>alert") {
		t.Error("?next= was reflected unescaped")
	}
	res, _ := get(t, browser(), app.URL+"/auth/login", nav)
	for h, want := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"} {
		if res.Header.Get(h) != want {
			t.Errorf("%s = %q, want %q", h, res.Header.Get(h), want)
		}
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("missing CSP")
	}
}

func TestCookiesSecureBehindHTTPSProxy(t *testing.T) {
	// The logout confirmation page sets the CSRF cookie.
	app, _, _ := startOIDCApp(t)
	res, _ := get(t, noRedirect(browser()), app.URL+"/auth/logout", map[string]string{"X-Forwarded-Proto": "https"})
	var found bool
	for _, ck := range res.Cookies() {
		found = true
		if !ck.Secure || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %s: secure=%v httponly=%v samesite=%v", ck.Name, ck.Secure, ck.HttpOnly, ck.SameSite)
		}
	}
	if !found {
		t.Error("expected a CSRF cookie")
	}
	res, _ = get(t, noRedirect(browser()), app.URL+"/auth/logout", nil)
	for _, ck := range res.Cookies() {
		if ck.Secure {
			t.Errorf("cookie %s is Secure over plain http", ck.Name)
		}
	}
}

// --- OIDC (fake IdP) ---------------------------------------------------

func TestOIDCSignInRedirectsStraightToIdP(t *testing.T) {
	app, _, _ := startOIDCApp(t)

	if res, _ := get(t, noRedirect(browser()), app.URL+"/dash", nav); res.StatusCode != 302 || res.Header.Get("Location") != "/auth/oidc?next=%2Fdash" {
		t.Fatalf("expected an immediate OIDC redirect, got %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := get(t, browser(), app.URL+"/some/page?x=1", nav)
	if res.StatusCode != 200 || body != "hello app" || res.Request.URL.Path != "/some/page" || res.Request.URL.RawQuery != "x=1" {
		t.Fatalf("sign-in through the IdP: %d %q at %s", res.StatusCode, body, res.Request.URL)
	}
}

func TestOIDCAuthorizeRequestUsesPKCE(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	res, _ := get(t, noRedirect(browser()), app.URL+"/auth/oidc", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("redirect_uri") != app.URL+"/auth/callback" || q.Get("response_type") != "code" {
		t.Errorf("bad authorize request: %v", q)
	}
}

func TestOIDCDeniedFallsBackWithoutLooping(t *testing.T) {
	idp := newFakeIdP(t)
	idp.Start()
	idp.denyLogin = true
	app, _ := startApp(t, Config{OIDC: oidcCfg(idp)})

	res, body := get(t, browser(), app.URL+"/dash", nav) // a redirect loop would make the client error out
	if res.StatusCode != 200 || res.Request.URL.Path != "/auth/login" {
		t.Fatalf("%d at %s", res.StatusCode, res.Request.URL)
	}
	if strings.Contains(body, "<form") {
		t.Errorf("the fallback page must not have a form: %.300s", body)
	}
	for _, want := range []string{"Sign-in failed", "Try again with OpenID Connect", "not approved by the identity provider"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestOIDCRejections(t *testing.T) {
	t.Run("nonce mismatch", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.Start()
		idp.badNonce = true
		app, _ := startApp(t, Config{OIDC: oidcCfg(idp)})
		res, body := get(t, browser(), app.URL+"/", nav)
		if res.Request.URL.Path != "/auth/login" || body == "hello app" || !strings.Contains(body, "Sign-in failed") {
			t.Errorf("%d at %s", res.StatusCode, res.Request.URL)
		}
	})
	t.Run("wrong client secret", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.Start()
		bad := oidcCfg(idp)
		bad.ClientSecret = "nope"
		app, _ := startApp(t, Config{OIDC: bad})
		res, body := get(t, browser(), app.URL+"/", nav)
		if res.Request.URL.Path != "/auth/login" || body == "hello app" {
			t.Errorf("%d at %s", res.StatusCode, res.Request.URL)
		}
	})
	t.Run("forged state and missing flow cookie", func(t *testing.T) {
		app, g, _ := startOIDCApp(t)
		c := noRedirect(browser())
		_, _ = get(t, c, app.URL+"/auth/oidc", nil)
		res, _ := get(t, c, app.URL+"/auth/callback?code=x&state=forged", nil)
		if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/auth/login?error=failed") {
			t.Errorf("forged state: %d %s", res.StatusCode, res.Header.Get("Location"))
		}
		res, _ = get(t, noRedirect(browser()), app.URL+"/auth/callback?code=x&state=y", nil)
		if res.StatusCode != 302 || !strings.HasPrefix(res.Header.Get("Location"), "/auth/login?error=failed") {
			t.Errorf("no flow cookie: %d %s", res.StatusCode, res.Header.Get("Location"))
		}
		u, _ := url.Parse(app.URL)
		for _, ck := range c.Jar.Cookies(u) {
			if ck.Name == g.sessionCookie {
				t.Error("a rejected login must not set a session")
			}
		}
	})
	t.Run("flow cookie is not a session", func(t *testing.T) {
		app, g, _ := startOIDCApp(t)
		c := noRedirect(browser())
		_, _ = get(t, c, app.URL+"/auth/oidc", nil)
		u, _ := url.Parse(app.URL)
		for _, ck := range c.Jar.Cookies(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/auth/"}) {
			if ck.Name == g.flowCookie {
				c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: ck.Value, Path: "/"}})
			}
		}
		if res, _ := get(t, c, app.URL+"/api", nil); res.StatusCode != 401 {
			t.Errorf("flow cookie accepted as a session: %d", res.StatusCode)
		}
	})
}

func TestOIDCProviderDownAtStartup(t *testing.T) {
	idp := newFakeIdP(t) // reserved but not started: unreachable
	app, g := startApp(t, Config{OIDC: oidcCfg(idp), retryBase: 20 * time.Millisecond})

	// The page explains the provider is unreachable; there is nothing else to use.
	res, body := get(t, browser(), app.URL+"/", nav)
	if res.StatusCode != 200 || res.Request.URL.Path != "/auth/login" || !strings.Contains(body, "not reachable") || strings.Contains(body, "<form") {
		t.Errorf("provider down: %d at %s: %.200s", res.StatusCode, res.Request.URL, body)
	}
	// The provider comes up; the gate notices and starts redirecting to it.
	idp.Start()
	deadline := time.Now().Add(5 * time.Second)
	for g.oidcGet() == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g.oidcGet() == nil {
		t.Fatal("the gate never picked up the provider")
	}
	if res, _ := get(t, noRedirect(browser()), app.URL+"/dash", nav); res.Header.Get("Location") != "/auth/oidc?next=%2Fdash" {
		t.Errorf("after recovery expected an OIDC redirect, got %s", res.Header.Get("Location"))
	}
	if _, body := get(t, browser(), app.URL+"/", nav); body != "hello app" {
		t.Errorf("sign-in after recovery: %q", body)
	}
}

// --- configuration -----------------------------------------------------

func TestFromEnv(t *testing.T) {
	ctx := context.Background()
	opts := []Option{WithLogger(quiet)}
	dir := func(t *testing.T) Option { return WithDataDir(t.TempDir()) }

	t.Run("AUTH_DISABLED turns the gate off", func(t *testing.T) {
		t.Setenv("MY_APP_AUTH_DISABLED", "true")
		g, err := FromEnv(ctx, "my-app", opts...)
		if g != nil || err != nil {
			t.Fatalf("got %v, %v", g, err)
		}
		h := http.NewServeMux()
		if g.Wrap(h) != http.Handler(h) {
			t.Error("a nil gate must return the handler unchanged")
		}
	})
	t.Run("without OIDC settings FromEnv refuses", func(t *testing.T) {
		_, err := FromEnv(ctx, "my-app", append(opts, dir(t))...)
		if err == nil {
			t.Fatal("expected an error: the OIDC settings are required")
		}
		for _, v := range []string{"MY_APP_OIDC_ISSUER", "MY_APP_OIDC_CLIENT_ID", "MY_APP_OIDC_CLIENT_SECRET", "MY_APP_OIDC_BASE_URL", "MY_APP_AUTH_DISABLED"} {
			if !strings.Contains(err.Error(), v) {
				t.Errorf("error should name %s: %v", v, err)
			}
		}
	})
	t.Run("invalid boolean", func(t *testing.T) {
		t.Setenv("MY_APP_AUTH_DISABLED", "maybe")
		if _, err := FromEnv(ctx, "my-app", append(opts, dir(t))...); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("incomplete OIDC settings refuse and name the missing ones", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ISSUER", "https://auth.example.com")
		_, err := FromEnv(ctx, "my-app", append(opts, dir(t))...)
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, v := range []string{"MY_APP_OIDC_CLIENT_ID", "MY_APP_OIDC_CLIENT_SECRET", "MY_APP_OIDC_BASE_URL"} {
			if !strings.Contains(err.Error(), v) {
				t.Errorf("error should name %s: %v", v, err)
			}
		}
		if strings.Contains(err.Error(), "MY_APP_OIDC_ISSUER,") {
			t.Errorf("the issuer was set and must not be listed: %v", err)
		}
	})
	t.Run("an unreachable provider is not an error", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ISSUER", "http://127.0.0.1:1")
		t.Setenv("MY_APP_OIDC_CLIENT_ID", "cid")
		t.Setenv("MY_APP_OIDC_CLIENT_SECRET", "s")
		t.Setenv("MY_APP_OIDC_BASE_URL", "http://localhost:8080")
		cctx, cancel := context.WithCancel(ctx)
		defer cancel() // stops the background retry
		g, err := FromEnv(cctx, "my-app", append(opts, dir(t))...)
		if err != nil || g == nil || g.oidcGet() != nil {
			t.Fatalf("got %v, %v", g, err)
		}
	})
	t.Run("complete OIDC config with public paths", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.Start()
		t.Setenv("MY_APP_OIDC_ISSUER", idp.URL)
		t.Setenv("MY_APP_OIDC_CLIENT_ID", "cid")
		t.Setenv("MY_APP_OIDC_CLIENT_SECRET", "csecret")
		t.Setenv("MY_APP_OIDC_BASE_URL", "http://localhost:8080")
		t.Setenv("MY_APP_AUTH_PUBLIC_PATHS", "/a, /b/")
		g, err := FromEnv(ctx, "my-app", append(opts, dir(t), WithPublicPaths("/c"))...)
		if err != nil || g == nil {
			t.Fatalf("got %v, %v", g, err)
		}
		if g.oidcGet() == nil {
			t.Error("OIDC should be ready")
		}
		for _, p := range []string{"/healthz", "/a", "/b/x", "/c"} {
			if !g.isPublic(p) {
				t.Errorf("%s should be public", p)
			}
		}
		if g.isPublic("/other") {
			t.Error("/other should not be public")
		}
	})
}

func TestNewValidation(t *testing.T) {
	idp := newFakeIdP(t)
	idp.Start()
	good := func() Config {
		return Config{App: "a", DataDir: t.TempDir(), Logger: quiet, OIDC: &OIDCConfig{Issuer: idp.URL, ClientID: "c", ClientSecret: "s", BaseURL: "http://localhost:1"}}
	}
	for name, mutate := range map[string]func(*Config){
		"no OIDC at all":     func(c *Config) { c.OIDC = nil },
		"no issuer":          func(c *Config) { c.OIDC.Issuer = "" },
		"base url with path": func(c *Config) { c.OIDC.BaseURL = "https://x.example.com/app" },
		"base url relative":  func(c *Config) { c.OIDC.BaseURL = "x.example.com" },
		"no client secret":   func(c *Config) { c.OIDC.ClientSecret = "" },
		"no app":             func(c *Config) { c.App = "" },
	} {
		cfg := good()
		mutate(&cfg)
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := New(context.Background(), good()); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// A public prefix must not be a way past the gate for a handler that cleans
// paths itself: "/public/../secret" is gated, and the real public path is not.
func TestPublicPrefixIsNotAnEscapeViaDotSegments(t *testing.T) {
	// Like a bare http.FileServer: serves whatever the cleaned path names.
	cleaning := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served "+path.Clean(r.URL.Path))
	})
	idp := newFakeIdP(t)
	idp.Start()
	cfg := oidcCfg(idp)
	cfg.BaseURL = "http://localhost:1"
	g, err := New(context.Background(), Config{App: "my-app", DataDir: t.TempDir(), Logger: quiet, PublicPaths: []string{"/public/"}, OIDC: cfg})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewServer(g.Wrap(cleaning))
	t.Cleanup(app.Close)
	c := noRedirect(browser())

	if res, body := get(t, c, app.URL+"/public/file.txt", nil); res.StatusCode != 200 || body != "served /public/file.txt" {
		t.Errorf("the real public path must stay public: %d %q", res.StatusCode, body)
	}
	for _, p := range []string{"/public/../secret", "/public/./../secret", "/public/%2e%2e/secret", "/public/.."} {
		if res, body := get(t, c, app.URL+p, nil); res.StatusCode == 200 {
			t.Errorf("%s reached the app: %d %q", p, res.StatusCode, body)
		}
	}
}

func TestRedirectLocalNeverLeavesTheSite(t *testing.T) {
	for in, want := range map[string]string{
		"/ok?a=1":          "/ok?a=1",
		"":                 "/",
		"//evil.com":       "/",
		"https://evil.com": "/",
		"/\\evil.com":      "/",
		"/a\r\nX: y":       "/",
	} {
		rec := httptest.NewRecorder()
		redirectLocal(rec, httptest.NewRequest("GET", "/", nil), in)
		if got := rec.Header().Get("Location"); got != want || rec.Code != 302 {
			t.Errorf("redirectLocal(%q) -> %q (%d), want %q", in, got, rec.Code, want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "/",
		"/ok?a=1":               "/ok?a=1",
		"//evil.com":            "/",
		"/\\evil.com":           "/",
		"https://evil.com":      "/",
		"evil.com":              "/",
		"/auth/login":           "/",
		"/auth/callback?code=x": "/",
		"/x\r\nSet-Cookie: a=b": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoggedOutPage(t *testing.T) {
	app, _, _ := startOIDCApp(t)
	res, body := get(t, noRedirect(browser()), app.URL+"/auth/logged-out", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Sign in again") {
		t.Errorf("%d %.100s", res.StatusCode, body)
	}
}
