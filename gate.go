// Package oidcgate puts OpenID Connect login in front of any net/http app
// with two lines:
//
//	gate, err := oidcgate.FromEnv(ctx, "myapp") // reads MYAPP_OIDC_* env vars
//	if err != nil { log.Fatal(err) }            // enabled but misconfigured
//	handler = gate.Wrap(handler)                // no-op when OIDC is off
//
// Wrap adds /auth/login, /auth/callback, /auth/logout, /auth/logged-out and
// /auth/me (the signed-in user as JSON, or 401), and requires a signed-in
// user for every other path. Who may sign in is
// decided at the IdP (e.g. Authelia access policy, Entra "assignment
// required"); the gate only verifies that the IdP authenticated them.
package oidcgate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	loginPath     = "/auth/login"
	callbackPath  = "/auth/callback"
	logoutPath    = "/auth/logout"
	loggedOutPath = "/auth/logged-out"
	mePath        = "/auth/me"

	flowTTL    = 10 * time.Minute
	defaultTTL = 7 * 24 * time.Hour
)

// Gate authenticates requests against an OIDC provider. Create one with
// FromEnv or New; a nil *Gate means "auth disabled".
type Gate struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	key      []byte
	secure   bool
	ttl      time.Duration
	public   []string
	log      *slog.Logger

	sessionCookie string
	flowCookie    string
}

// New validates cfg, discovers the provider (failing if the issuer is
// unreachable) and returns a ready Gate.
func New(ctx context.Context, cfg Config) (*Gate, error) {
	if cfg.App == "" {
		return nil, errors.New("oidc: App is required")
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("oidc: Issuer, ClientID and ClientSecret are required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("oidc: BaseURL %q must be an absolute http(s) URL", cfg.BaseURL)
	}
	if p := strings.Trim(base.Path, "/"); p != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("oidc: BaseURL %q must not contain a path, query or fragment", cfg.BaseURL)
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	key := []byte(cfg.SessionSecret)
	switch {
	case len(key) == 0:
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("oidc: generating session key: %w", err)
		}
		log.Warn("oidc: no session secret set; sessions will end when the process restarts")
	case len(key) < 16:
		return nil, errors.New("oidc: SessionSecret must be at least 16 characters")
	}

	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(dctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovering issuer %s: %w", cfg.Issuer, err)
	}

	redirect := strings.TrimRight(cfg.BaseURL, "/") + callbackPath
	app := cookieName(cfg.App)
	g := &Gate{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirect,
			Scopes:       scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		key:           key,
		secure:        base.Scheme == "https",
		ttl:           ttl,
		public:        append([]string{"/healthz"}, cfg.PublicPaths...),
		log:           log,
		sessionCookie: app + "_session",
		flowCookie:    app + "_oidc_flow",
	}
	log.Info("oidc: enabled", "issuer", cfg.Issuer, "redirect_uri", redirect)
	return g, nil
}

// Wrap returns next guarded by the gate. On a nil Gate it returns next
// unchanged.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case loginPath:
			g.handleLogin(w, r)
			return
		case callbackPath:
			g.handleCallback(w, r)
			return
		case logoutPath:
			g.handleLogout(w, r)
			return
		case loggedOutPath:
			g.handleLoggedOut(w, r)
			return
		case mePath:
			g.handleMe(w, r)
			return
		}
		if g.isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := g.session(w, r)
		if !ok {
			g.deny(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func (g *Gate) isPublic(path string) bool {
	for _, p := range g.public {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// deny sends browser page loads to the login flow and answers everything
// else (fetch/XHR, API clients) with 401, so no client-side code is needed.
func (g *Gate) deny(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isNavigation(r) {
		http.Redirect(w, r, loginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	flow := flowClaims{
		State:    randString(),
		Nonce:    randString(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     safeNext(r.URL.Query().Get("next")),
		Exp:      time.Now().Add(flowTTL).Unix(),
	}
	g.setCookie(w, g.flowCookie, g.seal(purposeFlow, flow), "/auth", flowTTL)
	authURL := g.oauth.AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (g *Gate) handleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()

	var flow flowClaims
	ck, err := r.Cookie(g.flowCookie)
	if err != nil || !g.open(purposeFlow, ck.Value, &flow) || time.Now().Unix() > flow.Exp {
		g.fail(w, http.StatusBadRequest, "login expired or cookies are blocked; try again", "missing or invalid flow cookie")
		return
	}
	g.clearCookie(w, g.flowCookie, "/auth")

	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		g.fail(w, http.StatusBadRequest, "login failed; try again", "state mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		status := http.StatusBadRequest
		if e == "access_denied" {
			status = http.StatusForbidden
		}
		g.fail(w, status, "login was not completed: "+e, "idp returned error "+e+": "+q.Get("error_description"))
		return
	}
	code := q.Get("code")
	if code == "" {
		g.fail(w, http.StatusBadRequest, "login failed; try again", "no code in callback")
		return
	}

	tok, err := g.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		g.fail(w, http.StatusBadGateway, "login failed; try again", "token exchange: "+err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		g.fail(w, http.StatusBadGateway, "login failed; try again", "no id_token in token response")
		return
	}
	idToken, err := g.verifier.Verify(r.Context(), rawID)
	if err != nil {
		g.fail(w, http.StatusBadGateway, "login failed; try again", "id_token verification: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		g.fail(w, http.StatusBadRequest, "login failed; try again", "nonce mismatch")
		return
	}
	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		g.fail(w, http.StatusBadGateway, "login failed; try again", "reading claims: "+err.Error())
		return
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}

	g.startSession(w, User{Subject: idToken.Subject, Email: clip(claims.Email), Name: clip(name)})
	g.log.Info("oidc: login", "sub", idToken.Subject)
	http.Redirect(w, r, flow.Next, http.StatusFound)
}

// fail logs the detail server-side and shows the user only a generic message.
func (g *Gate) fail(w http.ResponseWriter, status int, userMsg, detail string) {
	g.log.Warn("oidc: login rejected", "reason", detail)
	http.Error(w, userMsg, status)
}

func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	g.clearCookie(w, g.sessionCookie, "/")
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loggedOutPath, http.StatusFound)
}

// handleMe lets a front end ask "is auth on, and who am I?": 200 with the
// user as JSON, or 401. With the gate off the route doesn't exist, so the
// app's own 404 tells the front end there is nothing to show (no logout
// button, no account name).
func (g *Gate) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := g.session(w, r)
	if !ok {
		g.deny(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"subject": u.Subject, "email": u.Email, "name": u.Name})
}

// handleLoggedOut shows a landing page rather than bouncing straight back
// into login, which with SSO would silently sign the user in again.
func (g *Gate) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Signed out</title>` +
		`<body style="font-family:system-ui,sans-serif;max-width:24rem;margin:20vh auto;text-align:center">` +
		`<p>You have been signed out.</p><p><a href="` + loginPath + `">Sign in again</a></p></body>`))
}

// safeNext keeps only same-site absolute paths, so /auth/login?next= cannot
// be used as an open redirect, and never targets /auth/* (redirect loops).
func safeNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || strings.HasPrefix(u.Path, "/auth/") {
		return "/"
	}
	return next
}

func randString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oidcgate: no entropy: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func clip(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

func cookieName(app string) string {
	return strings.ToLower(envPrefix(app))
}
