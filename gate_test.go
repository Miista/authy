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
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP is a minimal OIDC provider: discovery, authorize (auto-approves),
// token (verifies PKCE and the client secret) and JWKS.
type fakeIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu         sync.Mutex
	challenge  map[string]string // code -> PKCE challenge
	nonce      map[string]string // code -> nonce
	badNonce   bool              // return a wrong nonce in the id_token
	denyLogin  bool              // authorize returns access_denied
	tokenCalls int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, challenge: map[string]string{}, nonce: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/authorize",
			"token_endpoint":                        f.URL + "/token",
			"jwks_uri":                              f.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		rq := redirect.Query()
		rq.Set("state", q.Get("state"))
		f.mu.Lock()
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
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		if id, secret, ok := r.BasicAuth(); !ok || id != "cid" || secret != "csecret" {
			// oauth2 may also send credentials in the body.
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
		}).Claims(map[string]any{"nonce": nonce, "email": "a@example.com", "name": "Alice"}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// newApp starts an app guarded by a Gate pointed at idp. The app echoes the
// signed-in user's email.
func newApp(t *testing.T, idp *fakeIdP, mutate func(*Config)) (*httptest.Server, *Gate) {
	t.Helper()
	var g *Gate
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				io.WriteString(w, "ok")
				return
			}
			u, _ := UserFrom(r.Context())
			io.WriteString(w, "hello "+u.Email+" "+u.Name)
		})).ServeHTTP(w, r)
	}))
	t.Cleanup(app.Close)

	cfg := Config{
		App: "my-app", Issuer: idp.URL, ClientID: "cid", ClientSecret: "csecret",
		BaseURL: app.URL, SessionSecret: "0123456789abcdef",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	var err error
	g, err = New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return app, g
}

func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func get(t *testing.T, c *http.Client, u string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
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

func noRedirect(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

var nav = map[string]string{"Sec-Fetch-Mode": "navigate"}

func TestFullLoginFlow(t *testing.T) {
	idp := newFakeIdP(t)
	app, _ := newApp(t, idp, nil)
	c := browser(t)

	res, body := get(t, c, app.URL+"/some/page?x=1", nav)
	if res.StatusCode != 200 || body != "hello a@example.com Alice" {
		t.Fatalf("after login flow: %d %q", res.StatusCode, body)
	}
	if res.Request.URL.Path != "/some/page" || res.Request.URL.RawQuery != "x=1" {
		t.Errorf("not returned to original page: %s", res.Request.URL)
	}
	// Second request uses the session cookie only: no more IdP round trips.
	idp.mu.Lock()
	calls := idp.tokenCalls
	idp.mu.Unlock()
	if _, body := get(t, c, app.URL+"/", nav); body != "hello a@example.com Alice" {
		t.Errorf("session not reused: %q", body)
	}
	if idp.tokenCalls != calls {
		t.Error("second request triggered another login")
	}
}

func TestUnauthenticated(t *testing.T) {
	idp := newFakeIdP(t)
	app, _ := newApp(t, idp, nil)
	c := noRedirect(browser(t))

	res, _ := get(t, c, app.URL+"/page?a=b", nav)
	if res.StatusCode != 302 || res.Header.Get("Location") != "/auth/login?next=%2Fpage%3Fa%3Db" {
		t.Errorf("navigation: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, body := get(t, c, app.URL+"/api/x", map[string]string{"Sec-Fetch-Mode": "cors"})
	if res.StatusCode != 401 || !strings.Contains(body, "unauthorized") {
		t.Errorf("fetch: %d %q", res.StatusCode, body)
	}
	res, _ = get(t, c, app.URL+"/api/x", nil)
	if res.StatusCode != 401 {
		t.Errorf("plain API client: %d", res.StatusCode)
	}
	res, body = get(t, c, app.URL+"/healthz", nil)
	if res.StatusCode != 200 || body != "ok" {
		t.Errorf("healthz should be public: %d %q", res.StatusCode, body)
	}
}

func TestPublicPaths(t *testing.T) {
	idp := newFakeIdP(t)
	app, _ := newApp(t, idp, func(c *Config) { c.PublicPaths = []string{"/hook", "/static/"} })
	c := noRedirect(browser(t))
	for path, want := range map[string]int{"/hook": 200, "/hooks": 401, "/static/a.js": 200, "/staticx": 401} {
		if res, _ := get(t, c, app.URL+path, nil); res.StatusCode != want {
			t.Errorf("%s: got %d want %d", path, res.StatusCode, want)
		}
	}
}

func TestTamperedAndExpiredSession(t *testing.T) {
	idp := newFakeIdP(t)
	app, g := newApp(t, idp, nil)
	c := noRedirect(browser(t))
	u, _ := url.Parse(app.URL)

	set := func(val string) {
		c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: val, Path: "/"}})
	}
	valid := g.seal(purposeSession, sessionClaims{Sub: "x", Exp: time.Now().Add(time.Hour).Unix()})
	set(valid)
	if res, _ := get(t, c, app.URL+"/", nil); res.StatusCode != 200 {
		t.Fatalf("valid cookie rejected: %d", res.StatusCode)
	}
	forged := (&Gate{key: []byte("another-secret-key")}).seal(purposeSession, sessionClaims{Sub: "x", Exp: time.Now().Add(time.Hour).Unix()})
	for name, v := range map[string]string{
		"forged key":  forged,
		"tampered":    "e30" + valid[strings.Index(valid, "."):],
		"expired":     g.seal(purposeSession, sessionClaims{Sub: "x", Exp: time.Now().Add(-time.Minute).Unix()}),
		"wrong kind":  g.seal(purposeFlow, sessionClaims{Sub: "x", Exp: time.Now().Add(time.Hour).Unix()}),
		"no subject":  g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()}),
		"garbage":     "nonsense",
		"empty parts": ".",
	} {
		set(v)
		if res, _ := get(t, c, app.URL+"/", nil); res.StatusCode != 401 {
			t.Errorf("%s: accepted (%d)", name, res.StatusCode)
		}
	}
}

func TestSlidingSessionRefresh(t *testing.T) {
	idp := newFakeIdP(t)
	app, g := newApp(t, idp, nil)
	c := noRedirect(browser(t))
	u, _ := url.Parse(app.URL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Path: "/",
		Value: g.seal(purposeSession, sessionClaims{Sub: "x", Exp: time.Now().Add(time.Hour).Unix()})}})
	res, _ := get(t, c, app.URL+"/", nil)
	if res.StatusCode != 200 || len(res.Cookies()) == 0 {
		t.Errorf("expected a refreshed cookie, got status %d, cookies %v", res.StatusCode, res.Cookies())
	}
}

func TestCallbackRejections(t *testing.T) {
	login := func(t *testing.T, idp *fakeIdP, app *httptest.Server) (*http.Client, string) {
		c := noRedirect(browser(t))
		res, _ := get(t, c, app.URL+"/auth/login", nil)
		if res.StatusCode != 302 {
			t.Fatalf("login: %d", res.StatusCode)
		}
		return c, res.Header.Get("Location")
	}

	t.Run("state mismatch", func(t *testing.T) {
		idp := newFakeIdP(t)
		app, _ := newApp(t, idp, nil)
		c, _ := login(t, idp, app)
		res, _ := get(t, c, app.URL+"/auth/callback?code=x&state=forged", nil)
		if res.StatusCode != 400 {
			t.Errorf("got %d", res.StatusCode)
		}
	})
	t.Run("no flow cookie", func(t *testing.T) {
		idp := newFakeIdP(t)
		app, _ := newApp(t, idp, nil)
		res, _ := get(t, noRedirect(browser(t)), app.URL+"/auth/callback?code=x&state=y", nil)
		if res.StatusCode != 400 {
			t.Errorf("got %d", res.StatusCode)
		}
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.badNonce = true
		app, _ := newApp(t, idp, nil)
		res, _ := get(t, browser(t), app.URL+"/", nav)
		if res.StatusCode != 400 {
			t.Errorf("got %d", res.StatusCode)
		}
	})
	t.Run("access denied at IdP", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.denyLogin = true
		app, _ := newApp(t, idp, nil)
		res, _ := get(t, browser(t), app.URL+"/", nav)
		if res.StatusCode != 403 {
			t.Errorf("got %d", res.StatusCode)
		}
	})
	t.Run("wrong client secret", func(t *testing.T) {
		idp := newFakeIdP(t)
		app, _ := newApp(t, idp, func(c *Config) { c.ClientSecret = "nope" })
		res, _ := get(t, browser(t), app.URL+"/", nav)
		if res.StatusCode != 502 {
			t.Errorf("got %d", res.StatusCode)
		}
	})
	t.Run("flow cookie is not a session", func(t *testing.T) {
		idp := newFakeIdP(t)
		app, g := newApp(t, idp, nil)
		c, _ := login(t, idp, app)
		u, _ := url.Parse(app.URL)
		for _, ck := range c.Jar.Cookies(&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/auth/"}) {
			if ck.Name == g.flowCookie {
				c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: ck.Value, Path: "/"}})
			}
		}
		if res, _ := get(t, c, app.URL+"/", nil); res.StatusCode != 401 {
			t.Errorf("flow cookie accepted as session: %d", res.StatusCode)
		}
	})
}

func TestAuthorizeRequestUsesPKCE(t *testing.T) {
	idp := newFakeIdP(t)
	app, _ := newApp(t, idp, nil)
	res, _ := get(t, noRedirect(browser(t)), app.URL+"/auth/login", nil)
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("state") == "" || q.Get("nonce") == "" ||
		q.Get("redirect_uri") != app.URL+"/auth/callback" || q.Get("response_type") != "code" {
		t.Errorf("bad authorize request: %v", q)
	}
	for _, s := range []string{"openid", "email"} {
		if !strings.Contains(q.Get("scope"), s) {
			t.Errorf("scope %q missing: %s", s, q.Get("scope"))
		}
	}
}

func TestLogout(t *testing.T) {
	idp := newFakeIdP(t)
	app, _ := newApp(t, idp, nil)
	c := browser(t)
	if _, body := get(t, c, app.URL+"/", nav); !strings.HasPrefix(body, "hello") {
		t.Fatalf("login failed: %q", body)
	}
	res, body := get(t, c, app.URL+"/auth/logout", nav)
	if res.Request.URL.Path != "/auth/logged-out" || !strings.Contains(body, "signed out") {
		t.Errorf("logout landing: %s %q", res.Request.URL.Path, body)
	}
	if res, _ := get(t, noRedirect(c), app.URL+"/api", nil); res.StatusCode != 401 {
		t.Errorf("still signed in after logout: %d", res.StatusCode)
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

func TestSecureCookieFollowsBaseURLScheme(t *testing.T) {
	idp := newFakeIdP(t)
	app, g := newApp(t, idp, nil)
	if g.secure {
		t.Error("http base URL should not set Secure")
	}
	_ = app
	g2, err := New(context.Background(), Config{App: "a", Issuer: idp.URL, ClientID: "cid", ClientSecret: "s",
		BaseURL: "https://app.example.com", SessionSecret: "0123456789abcdef",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil || !g2.secure {
		t.Errorf("https base URL should set Secure (err=%v)", err)
	}
}

func TestFromEnv(t *testing.T) {
	idp := newFakeIdP(t)
	quiet := WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()

	t.Run("disabled by default", func(t *testing.T) {
		g, err := FromEnv(ctx, "my-app")
		if g != nil || err != nil {
			t.Fatalf("got %v, %v", g, err)
		}
		h := http.NewServeMux()
		if g.Wrap(h) != http.Handler(h) {
			t.Error("nil gate must return the handler unchanged")
		}
	})
	t.Run("explicitly disabled", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ENABLED", "false")
		if g, err := FromEnv(ctx, "my-app"); g != nil || err != nil {
			t.Fatalf("got %v, %v", g, err)
		}
	})
	t.Run("invalid enabled value", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ENABLED", "maybe")
		if _, err := FromEnv(ctx, "my-app"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("enabled but incomplete refuses", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ENABLED", "true")
		t.Setenv("MY_APP_OIDC_ISSUER", idp.URL)
		_, err := FromEnv(ctx, "my-app", quiet)
		if err == nil {
			t.Fatal("expected error")
		}
		for _, v := range []string{"MY_APP_OIDC_CLIENT_ID", "MY_APP_OIDC_CLIENT_SECRET", "MY_APP_OIDC_BASE_URL"} {
			if !strings.Contains(err.Error(), v) {
				t.Errorf("error should name %s: %v", v, err)
			}
		}
	})
	t.Run("unreachable issuer refuses", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ENABLED", "true")
		t.Setenv("MY_APP_OIDC_ISSUER", "http://127.0.0.1:1")
		t.Setenv("MY_APP_OIDC_CLIENT_ID", "cid")
		t.Setenv("MY_APP_OIDC_CLIENT_SECRET", "s")
		t.Setenv("MY_APP_OIDC_BASE_URL", "http://localhost:8080")
		if _, err := FromEnv(ctx, "my-app", quiet); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("complete config works", func(t *testing.T) {
		t.Setenv("MY_APP_OIDC_ENABLED", "TRUE")
		t.Setenv("MY_APP_OIDC_ISSUER", idp.URL)
		t.Setenv("MY_APP_OIDC_CLIENT_ID", "cid")
		t.Setenv("MY_APP_OIDC_CLIENT_SECRET", "csecret")
		t.Setenv("MY_APP_OIDC_BASE_URL", "http://localhost:8080")
		t.Setenv("MY_APP_OIDC_PUBLIC_PATHS", "/a, /b/")
		g, err := FromEnv(ctx, "my-app", quiet, WithPublicPaths("/c"))
		if err != nil || g == nil {
			t.Fatalf("got %v, %v", g, err)
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
	ok := Config{App: "a", Issuer: idp.URL, ClientID: "c", ClientSecret: "s", BaseURL: "http://localhost:1",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for name, mutate := range map[string]func(*Config){
		"base url with path": func(c *Config) { c.BaseURL = "https://x.example.com/app" },
		"base url relative":  func(c *Config) { c.BaseURL = "x.example.com" },
		"short secret":       func(c *Config) { c.SessionSecret = "short" },
		"no app":             func(c *Config) { c.App = "" },
	} {
		cfg := ok
		mutate(&cfg)
		if _, err := New(context.Background(), cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := New(context.Background(), ok); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
