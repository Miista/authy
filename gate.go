// Package oidcgate puts login in front of any net/http app with two lines:
//
//	gate, err := oidcgate.FromEnv(ctx, "myapp") // reads MYAPP_* env vars
//	if err != nil { log.Fatal(err) }            // misconfigured: refuse to start
//	handler = gate.Wrap(handler)                // no-op when the gate is off
//
// The gate owns everything about authentication, so the app needs no code for
// it: a local account (created on first launch), optional OpenID Connect
// login, the login/setup/error pages, sessions, and the routes under /auth/.
// Remove the two lines and the app has no idea any of it existed.
//
// Who may sign in through OIDC is decided at the identity provider; the gate
// only verifies that the provider authenticated the user for this client, and
// records that the browser is authorized and who it is. An app that needs to tell
// people apart reads that with UserFrom; one that does not never sees it.
package oidcgate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	clientJSPath  = "/auth/client.js"
	loginPath     = "/auth/login"
	setupPath     = "/auth/setup"
	oidcPath      = "/auth/oidc"
	callbackPath  = "/auth/callback"
	logoutPath    = "/auth/logout"
	loggedOutPath = "/auth/logged-out"

	defaultTTL = 7 * 24 * time.Hour
)

// Gate guards an app. Create one with FromEnv or New; a nil *Gate means "off".
type Gate struct {
	app    string
	store  *store
	ttl    time.Duration
	public []string
	log    *slog.Logger
	lim    *limiter

	// OIDC (oidcCfg == nil: local account only). The provider is discovered in
	// the background if it is unreachable at startup, so oidcS may be nil.
	oidcCfg       *OIDCConfig
	redirect      string
	baseSecure    bool
	localDisabled bool
	oidcMu        sync.RWMutex
	oidcS         *oidcState

	sessionCookie string
	csrfCookie    string
	flowCookie    string
}

type oidcState struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

// New validates cfg, opens the store (failing if its directory is not
// writable) and, when OIDC is configured, tries to reach the provider. An
// unreachable provider is not an error: discovery retries in the background.
func New(ctx context.Context, cfg Config) (*Gate, error) {
	if cfg.App == "" {
		return nil, errors.New("auth: App is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	dir := cfg.DataDir
	if dir == "" {
		dir = defaultDataDir
	}
	st, err := openStore(dir)
	if err != nil {
		return nil, fmt.Errorf("auth: opening %s: %w (the data directory must be writable by the app's user)", dir, err)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	name := strings.ToLower(envPrefix(cfg.App))
	g := &Gate{
		app:           cfg.App,
		store:         st,
		ttl:           ttl,
		public:        append([]string{"/healthz"}, cfg.PublicPaths...),
		log:           log,
		lim:           newLimiter(),
		sessionCookie: name + "_session",
		csrfCookie:    name + "_csrf",
		flowCookie:    name + "_oidc_flow",
	}

	if o := cfg.OIDC; o != nil {
		if o.Issuer == "" || o.ClientID == "" || o.ClientSecret == "" {
			return nil, errors.New("auth: OIDC needs Issuer, ClientID and ClientSecret")
		}
		base, err := url.Parse(o.BaseURL)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
			return nil, fmt.Errorf("auth: OIDC BaseURL %q must be an absolute http(s) URL", o.BaseURL)
		}
		if strings.Trim(base.Path, "/") != "" || base.RawQuery != "" || base.Fragment != "" {
			return nil, fmt.Errorf("auth: OIDC BaseURL %q must not contain a path, query or fragment", o.BaseURL)
		}
		g.oidcCfg = o
		g.redirect = strings.TrimRight(o.BaseURL, "/") + callbackPath
		g.baseSecure = base.Scheme == "https"
		g.localDisabled = cfg.DisableBuiltInLogin

		if err := g.discover(ctx, 5*time.Second); err != nil {
			retry := cfg.retryBase
			if retry <= 0 {
				retry = 5 * time.Second
			}
			log.Warn("auth: OIDC provider not reachable yet; retrying in the background (local login keeps working)",
				"issuer", o.Issuer, "err", err)
			go g.discoverLoop(ctx, retry)
		}
	} else if cfg.DisableBuiltInLogin {
		log.Warn("auth: DISABLE_BUILT_IN_LOGIN is ignored because OIDC is not enabled")
	}

	args := []any{"oidc", g.oidcCfg != nil, "local_account", st.hasAccount(), "local_login", g.localEnabled(), "data_dir", dir}
	if g.oidcCfg != nil {
		args = append(args, "issuer", g.oidcCfg.Issuer, "redirect_uri", g.redirect)
	}
	log.Info("auth: enabled", args...)
	return g, nil
}

func (g *Gate) localEnabled() bool { return !g.localDisabled }

func (g *Gate) oidcGet() *oidcState {
	g.oidcMu.RLock()
	defer g.oidcMu.RUnlock()
	return g.oidcS
}

// discover contacts the provider and, on success, makes OIDC login available.
func (g *Gate) discover(ctx context.Context, timeout time.Duration) error {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	provider, err := oidc.NewProvider(dctx, g.oidcCfg.Issuer)
	if err != nil {
		return err
	}
	scopes := scopesOrDefault(g.oidcCfg.Scopes)
	s := &oidcState{
		provider: provider,
		oauth: &oauth2.Config{
			ClientID:     g.oidcCfg.ClientID,
			ClientSecret: g.oidcCfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  g.redirect,
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: g.oidcCfg.ClientID}),
	}
	g.oidcMu.Lock()
	g.oidcS = s
	g.oidcMu.Unlock()
	return nil
}

func (g *Gate) discoverLoop(ctx context.Context, delay time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		err := g.discover(ctx, 10*time.Second)
		if err == nil {
			g.log.Info("auth: OIDC provider reachable; OIDC login is now available", "issuer", g.oidcCfg.Issuer)
			return
		}
		g.log.Warn("auth: OIDC provider still unreachable", "err", err)
		if delay *= 2; delay > time.Minute {
			delay = time.Minute
		}
	}
}

// Wrap returns next guarded by the gate. On a nil Gate it returns next
// unchanged.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	if g == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case clientJSPath:
			g.handleClientJS(w, r)
			return
		case loginPath:
			g.handleLogin(w, r)
			return
		case setupPath:
			g.handleSetup(w, r)
			return
		case oidcPath:
			g.handleOIDCStart(w, r)
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
		}
		if g.isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if u, ok := g.session(w, r); ok {
			if u != nil {
				r = withUser(r, u.user())
			}
			next.ServeHTTP(w, r)
			return
		}
		g.deny(w, r)
	})
}

func (g *Gate) isPublic(path string) bool {
	// A path with dot segments is never public. Some handlers (a bare
	// http.FileServer) clean the path themselves, so "/public/../secret" would
	// otherwise pass a "/public/" allowance here and be served as "/secret".
	if hasDotSegment(path) {
		return false
	}
	for _, p := range g.public {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// deny answers an unauthenticated request: browser page loads go to the right
// entry point, everything else (fetch/XHR, API clients) gets 401, so no
// client-side code is needed.
func (g *Gate) deny(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if isNavigation(r) {
		redirectLocal(w, r, g.entryURL(r.URL.RequestURI()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

// entryURL picks where an unauthenticated page load starts, per the flow:
// OIDC first whenever it is configured; otherwise the local pages.
func (g *Gate) entryURL(next string) string {
	q := "?next=" + url.QueryEscape(next)
	hasAccount := g.store.hasAccount()
	switch {
	case g.oidcCfg != nil && g.oidcGet() != nil:
		return oidcPath + q
	case g.oidcCfg != nil && hasAccount && g.localEnabled():
		return loginPath + q // provider unreachable: local login is the fallback
	case g.oidcCfg != nil:
		return loginPath + q + "&error=unavailable"
	case !hasAccount:
		return setupPath + q
	default:
		return loginPath + q
	}
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

func (g *Gate) handleClientJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/javascript; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(clientJS))
}

// --- local login ---------------------------------------------------------

func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		q := r.URL.Query()
		g.showLogin(w, r, http.StatusOK, "", safeNext(q.Get("next")), q.Get("error"))
	case http.MethodPost:
		g.postLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// showLogin renders the sign-in page: the local form (when an account exists
// and local login is allowed) and the OIDC button (when configured). After a
// failed OIDC attempt it is the fallback page, and it never redirects, so a
// rejection cannot loop.
func (g *Gate) showLogin(w http.ResponseWriter, r *http.Request, status int, msg, next, errCode string) {
	hasAccount := g.store.hasAccount()
	if !hasAccount && g.oidcCfg == nil {
		http.Redirect(w, r, setupPath+"?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	d := pageData{Title: "Sign in", Heading: "Sign in", Next: next, Error: msg}
	if d.Error == "" {
		d.Error = errorMessages[errCode]
	}
	d.ShowForm = hasAccount && g.localEnabled()
	if g.oidcCfg != nil {
		d.ShowOIDC = true
		d.OIDCURL = oidcPath + "?next=" + url.QueryEscape(next)
		d.OIDCLabel = "Sign in with OpenID Connect"
		if errCode != "" {
			d.OIDCLabel = "Try again with OpenID Connect"
		}
	}
	if d.ShowForm {
		d.CSRF = g.csrfToken(w, r)
	} else if errCode != "" {
		d.Title, d.Heading = "Sign-in failed", "Sign-in failed"
	}
	g.render(w, status, d)
}

func (g *Gate) postLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	if !g.checkCSRF(r) {
		g.showLogin(w, r, http.StatusForbidden, "Your session expired. Please try again.", next, "")
		return
	}
	if !g.localEnabled() {
		g.render(w, http.StatusForbidden, pageData{
			Title: "Local sign-in is disabled", Heading: "Local sign-in is disabled",
			Message: "Use OpenID Connect to sign in.", ShowOIDC: true,
			OIDCURL: oidcPath + "?next=" + url.QueryEscape(next), OIDCLabel: "Sign in with OpenID Connect",
		})
		return
	}
	if !g.store.hasAccount() {
		http.Redirect(w, r, loginPath+"?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	now := time.Now()
	if blocked, wait := g.lim.blocked(now); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		g.showLogin(w, r, http.StatusTooManyRequests, "Too many failed attempts. Try again in a minute.", next, "")
		return
	}
	if !g.store.verify(r.PostFormValue("username"), r.PostFormValue("password")) {
		g.lim.fail(now)
		g.log.Warn("auth: local login failed")
		g.showLogin(w, r, http.StatusUnauthorized, "Invalid username or password.", next, "")
		return
	}
	g.lim.reset()
	g.startSession(w, r, localUser(r.PostFormValue("username")))
	g.log.Info("auth: local login ok")
	redirectLocal(w, r, next)
}

// --- first-launch account creation --------------------------------------

func (g *Gate) handleSetup(w http.ResponseWriter, r *http.Request) {
	// Setup exists only for a first launch without OIDC. With OIDC configured
	// there is no local account to create, and nobody can claim the app by
	// being first.
	if g.oidcCfg != nil || g.store.hasAccount() {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		g.showSetup(w, r, http.StatusOK, "", safeNext(r.URL.Query().Get("next")))
	case http.MethodPost:
		g.postSetup(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gate) showSetup(w http.ResponseWriter, r *http.Request, status int, msg, next string) {
	g.render(w, status, pageData{
		Title: "Create your account", Heading: "Create your account",
		Message: "Choose a username and password. This is the only account.",
		Error:   msg, Next: next, ShowSetup: true, CSRF: g.csrfToken(w, r),
	})
}

func (g *Gate) postSetup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	if !g.checkCSRF(r) {
		g.showSetup(w, r, http.StatusForbidden, "Your session expired. Please try again.", next)
		return
	}
	username, password := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	if err := validateCredentials(username, password); err != nil {
		g.showSetup(w, r, http.StatusBadRequest, err.Error(), next)
		return
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(r.PostFormValue("confirm"))) != 1 {
		g.showSetup(w, r, http.StatusBadRequest, "The passwords do not match.", next)
		return
	}
	switch err := g.store.createAccount(username, password); {
	case errors.Is(err, errAccountExists):
		http.Redirect(w, r, loginPath+"?next="+url.QueryEscape(next), http.StatusFound)
		return
	case err != nil:
		g.log.Error("auth: creating the account", "err", err)
		g.showSetup(w, r, http.StatusInternalServerError, "Could not save the account. Check the server log.", next)
		return
	}
	g.log.Info("auth: local account created")
	g.startSession(w, r, localUser(username)) // the key was rotated by createAccount, so this cookie is the only valid one
	redirectLocal(w, r, next)
}

// --- OIDC ----------------------------------------------------------------

func (g *Gate) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if g.oidcCfg == nil {
		http.NotFound(w, r)
		return
	}
	next := safeNext(r.URL.Query().Get("next"))
	s := g.oidcGet()
	if s == nil {
		g.loginFail(w, r, "unavailable", next, "provider not discovered yet")
		return
	}
	flow := flowClaims{
		State:    randString(),
		Nonce:    randString(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     next,
		Exp:      time.Now().Add(flowTTL).Unix(),
	}
	g.setCookie(w, r, g.flowCookie, g.seal(purposeFlow, flow), "/auth", flowTTL)
	authURL := s.oauth.AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (g *Gate) handleCallback(w http.ResponseWriter, r *http.Request) {
	if g.oidcCfg == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()

	var flow flowClaims
	ck, err := r.Cookie(g.flowCookie)
	if err != nil || !g.open(purposeFlow, ck.Value, &flow) || time.Now().Unix() > flow.Exp {
		g.loginFail(w, r, "failed", "/", "missing or invalid flow cookie")
		return
	}
	g.clearCookie(w, r, g.flowCookie, "/auth")
	next := safeNext(flow.Next)

	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		g.loginFail(w, r, "failed", next, "state mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		code := "failed"
		if e == "access_denied" {
			code = "access_denied"
		}
		g.loginFail(w, r, code, next, "idp returned error "+e+": "+q.Get("error_description"))
		return
	}
	s := g.oidcGet()
	if s == nil {
		g.loginFail(w, r, "unavailable", next, "provider not discovered yet")
		return
	}
	code := q.Get("code")
	if code == "" {
		g.loginFail(w, r, "failed", next, "no code in callback")
		return
	}
	tok, err := s.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		g.loginFail(w, r, "failed", next, "token exchange: "+err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		g.loginFail(w, r, "failed", next, "no id_token in token response")
		return
	}
	idToken, err := s.verifier.Verify(r.Context(), rawID)
	if err != nil {
		g.loginFail(w, r, "failed", next, "id_token verification: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		g.loginFail(w, r, "failed", next, "nonce mismatch")
		return
	}

	u, err := g.oidcUser(r.Context(), s, tok, idToken)
	if err != nil {
		g.loginFail(w, r, "failed", next, "reading the user's claims: "+err.Error())
		return
	}
	g.startSession(w, r, u)
	g.log.Info("auth: oidc login ok", "sub", idToken.Subject)
	redirectLocal(w, r, next)
}

// oidcClaims are the claims the gate reads, from the ID token or UserInfo.
type oidcClaims struct {
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	hasGroups         bool
}

// oidcUser builds the signed-in user. Some providers (Authelia by default)
// serve the profile and groups only from the UserInfo endpoint, so when groups
// were asked for and the ID token has none, UserInfo is asked too. It is not
// optional then: an app that asked for groups decides who may do what by them,
// so a login whose groups cannot be read fails rather than carry on without
// them. A user with no groups at all is fine, and is told apart from "could not
// ask" by the call succeeding.
func (g *Gate) oidcUser(ctx context.Context, s *oidcState, tok *oauth2.Token, idToken *oidc.IDToken) (*sessionUser, error) {
	var c oidcClaims
	if err := idToken.Claims(&c); err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, err
	}
	_, c.hasGroups = raw["groups"]

	if wantsGroups(g.oidcCfg.Scopes) && !c.hasGroups {
		ui, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("userinfo: %w", err)
		}
		if ui.Subject != idToken.Subject {
			return nil, errors.New("userinfo is for a different subject than the id_token")
		}
		var fromInfo oidcClaims
		if err := ui.Claims(&fromInfo); err != nil {
			return nil, err
		}
		// The ID token's own values win; UserInfo fills what it lacks.
		if c.PreferredUsername == "" {
			c.PreferredUsername = fromInfo.PreferredUsername
		}
		if c.Name == "" {
			c.Name = fromInfo.Name
		}
		if c.Email == "" {
			c.Email = fromInfo.Email
		}
		c.Groups = fromInfo.Groups
	}

	// "local:" is the built-in account's namespace (see localUser). A provider
	// subject inside it would collide with the local admin for any app keying
	// on User.Subject, so it is refused rather than passed through.
	if strings.HasPrefix(idToken.Subject, "local:") {
		return nil, errors.New(`the id_token subject starts with "local:", which is reserved for the built-in account`)
	}
	name := c.PreferredUsername
	if name == "" {
		name = c.Name
	}
	u := newSessionUser(idToken.Subject, name, c.Email, c.Groups, false)
	if u == nil {
		return nil, errors.New("the id_token has no subject")
	}
	if len(c.Groups) > len(u.Groups) {
		g.log.Warn("auth: some groups were dropped (too many or too long)", "sub", idToken.Subject, "sent", len(c.Groups), "kept", len(u.Groups))
	}
	return u, nil
}

// loginFail logs the detail and sends the browser to the sign-in page with a
// generic error code, where it shows the fallback (local form and/or a retry
// button) instead of redirecting again.
func (g *Gate) loginFail(w http.ResponseWriter, r *http.Request, code, next, detail string) {
	g.log.Warn("auth: oidc login not completed", "code", code, "reason", detail)
	http.Redirect(w, r, loginPath+"?error="+code+"&next="+url.QueryEscape(next), http.StatusFound)
}

// --- logout --------------------------------------------------------------

// handleLogout signs out only on a POST that passes the CSRF check: a GET shows
// a confirmation page instead, so a third-party page cannot sign the user out
// by making the browser follow a link.
func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		g.showLogout(w, r, http.StatusOK, "")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if !g.checkCSRF(r) {
			g.showLogout(w, r, http.StatusForbidden, "Your session expired. Please try again.")
			return
		}
		g.endSession(w, r)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, loggedOutPath, http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (g *Gate) showLogout(w http.ResponseWriter, r *http.Request, status int, msg string) {
	g.render(w, status, pageData{
		Title: "Sign out", Heading: "Sign out",
		Message: "Do you want to sign out?", Error: msg,
		ShowLogout: true, CSRF: g.csrfToken(w, r),
		Link: "/", LinkLabel: "Cancel",
	})
}

// handleLoggedOut shows a landing page rather than bouncing straight back into
// login, which with SSO would silently sign the user in again.
func (g *Gate) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	g.render(w, http.StatusOK, pageData{
		Title: "Signed out", Heading: "Signed out",
		Message: "You have been signed out.", Link: "/", LinkLabel: "Sign in again",
	})
}

// redirectLocal redirects only to a path on this site. Every target is already
// built from constants or sanitised by safeNext; this is the last line of
// defence, so a future mistake falls back to "/" instead of leaving the site.
func redirectLocal(w http.ResponseWriter, r *http.Request, target string) {
	if target == "" || target[0] != '/' || strings.HasPrefix(target, "//") || strings.ContainsAny(target, "\\\r\n") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound) // #nosec G710 -- target is a local path, checked above
}

// safeNext keeps only same-site absolute paths, so ?next= cannot be used as an
// open redirect, and never targets /auth/* (redirect loops).
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
