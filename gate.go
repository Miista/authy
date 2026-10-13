// Package authy puts login in front of any net/http app with two lines:
//
//	gate, err := authy.FromEnv(ctx, "myapp") // reads MYAPP_* env vars
//	if err != nil { log.Fatal(err) }            // misconfigured: refuse to start
//	handler = gate.Wrap(handler)                // no-op when the gate is off
//
// The gate owns everything about authentication, so the app needs no code for
// it: the sign-in methods, sessions, sign-out, and the routes under /auth/.
// Remove the two lines and the app has no idea any of it existed.
//
// Sign-in is a method's ceremony (today: OpenID Connect, where the identity
// provider decides who may sign in); the gate runs the methods and owns the
// one session they all result in. An app that needs to tell people apart reads
// the identity with UserFrom; one that does not never sees it.
package authy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miista/authy/internal/shell"
	"github.com/miista/authy/local"
	"github.com/miista/authy/oidc"
)

const (
	clientJSPath  = "/auth/client.js"
	loginPath     = "/auth/login" // the fallback page: entries and errors, never a loop
	logoutPath    = "/auth/logout"
	loggedOutPath = "/auth/logged-out"

	defaultTTL = 7 * 24 * time.Hour
)

// Gate guards an app. Create one with FromEnv or New; a nil *Gate means "off".
type Gate struct {
	app        string
	store      *store
	ttl        time.Duration
	public     []string
	log        *slog.Logger
	methods    []shell.Method
	baseSecure bool
	oidc       bool // sign-in is delegated to an identity provider

	sessionCookie string
	csrfCookie    string
}

// New validates cfg, opens the store (failing if its directory is not
// writable) and builds the sign-in methods. An unreachable OIDC provider is
// not an error: discovery retries in the background.
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
		sessionCookie: name + "_session",
		csrfCookie:    name + "_csrf",
	}

	// The local account is on exactly when OIDC is off, unless said otherwise:
	// an app with no configuration at all is still protected, and one with a
	// provider delegates sign-in to it.
	localOn := cfg.OIDC == nil
	if cfg.LocalLogin != nil {
		localOn = *cfg.LocalLogin
	}
	if cfg.OIDC == nil && !localOn {
		return nil, errors.New("auth: no way to sign in (configure OIDC or leave the local account enabled)")
	}

	args := []any{"data_dir", dir, "local_login", localOn}
	if o := cfg.OIDC; o != nil {
		base, err := url.Parse(o.BaseURL)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
			return nil, fmt.Errorf("auth: OIDC BaseURL %q must be an absolute http(s) URL", o.BaseURL)
		}
		if strings.Trim(base.Path, "/") != "" || base.RawQuery != "" || base.Fragment != "" {
			return nil, fmt.Errorf("auth: OIDC BaseURL %q must not contain a path, query or fragment", o.BaseURL)
		}
		g.baseSecure = base.Scheme == "https"
		redirect := strings.TrimRight(o.BaseURL, "/") + "/auth/callback"

		m, err := oidc.New(ctx, &gateShell{g: g, ns: "oidc"}, oidc.Config{
			Issuer:       o.Issuer,
			ClientID:     o.ClientID,
			ClientSecret: o.ClientSecret,
			RedirectURL:  redirect,
			Scopes:       o.Scopes,
			RetryBase:    cfg.retryBase,
		}, name+"_oidc_flow")
		if err != nil {
			return nil, err
		}
		g.methods = append(g.methods, m)
		g.oidc = true
		args = append(args, "issuer", o.Issuer, "redirect_uri", redirect)
	}
	if localOn {
		m, err := local.New(&gateShell{g: g, ns: "local"}, dir)
		if err != nil {
			return nil, fmt.Errorf("auth: opening the local account store: %w", err)
		}
		g.methods = append(g.methods, m)
	}

	log.Info("auth: enabled", args...)
	return g, nil
}

// OIDC reports whether sign-in is delegated to an identity provider, so an
// app can tell whether provider data such as groups is there to be read. It
// is false on a nil Gate (no login at all).
func (g *Gate) OIDC() bool { return g != nil && g.oidc }

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
		case logoutPath:
			g.handleLogout(w, r)
			return
		case loggedOutPath:
			g.handleLoggedOut(w, r)
			return
		}
		for _, m := range g.methods {
			if m.Serve(w, r) {
				return
			}
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

// entryURL picks where an unauthenticated page load starts: the first method
// whose ceremony can start now, or the fallback page when none can.
func (g *Gate) entryURL(next string) string {
	for _, m := range g.methods {
		if m.Ready() {
			return m.Entry(next).URL
		}
	}
	return loginPath + "?next=" + url.QueryEscape(next) + "&error=unavailable"
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

// --- fallback page ---------------------------------------------------------

// handleLogin renders the fallback page: every method's entry and the error
// from a failed or unavailable attempt. It never redirects, so a rejection at
// a provider cannot loop.
func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	next, errCode := safeNext(q.Get("next")), q.Get("error")
	d := pageData{Title: "Sign in", Heading: "Sign in", Error: errorMessages[errCode]}
	verb := "Sign in with "
	if errCode != "" {
		d.Title, d.Heading, verb = "Sign-in failed", "Sign-in failed", "Try again with "
	}
	for _, m := range g.methods {
		e := m.Entry(next)
		d.Entries = append(d.Entries, pageEntry{Label: verb + e.Label, URL: e.URL})
	}
	g.render(w, http.StatusOK, d)
}

// --- logout --------------------------------------------------------------

// handleLogout signs out, but never for another site: a request whose
// Sec-Fetch-Site says it was caused cross-site is refused, so a third-party
// page cannot sign the user out with a crafted link. Every current browser
// sends the header; a client without it can at worst cause a sign-out, not a
// sign-in.
func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site sign-out refused", http.StatusForbidden)
		return
	}
	g.endSession(w, r)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loggedOutPath, http.StatusFound)
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
