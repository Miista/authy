package oidcgate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// sessionClaims is the payload of the session cookie: when it ends, when it was
// created, its ID (so sign-out can revoke it) and who it is for. A session from
// before identities were recorded has no U and is still valid, so an app that
// does not use UserFrom is unaffected by an upgrade; one from before Iat/SID
// existed is stamped with both at its next renewal.
type sessionClaims struct {
	Exp int64        `json:"exp"`
	Iat int64        `json:"iat,omitempty"`
	SID string       `json:"sid,omitempty"`
	U   *sessionUser `json:"u,omitempty"`
}

// flowClaims is the payload of the short-lived cookie carrying one OIDC login
// attempt's state between /auth/oidc and /auth/callback.
type flowClaims struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
	Exp      int64  `json:"exp"`
}

const (
	purposeSession = "session"
	purposeFlow    = "flow"
	flowTTL        = 10 * time.Minute

	// maxSessionFactor caps what sliding renewal can add up to: a session ends
	// for good maxSessionFactor×TTL after sign-in, no matter how often it is
	// refreshed, so a stolen cookie cannot be kept alive forever.
	maxSessionFactor = 4
)

// seal serialises v and appends an HMAC bound to purpose, so a flow cookie can
// never be replayed as a session cookie.
func (g *Gate) seal(purpose string, v any) string {
	b, _ := json.Marshal(v)
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + g.mac(purpose, p)
}

// open verifies and decodes a sealed value. It does not check expiry.
func (g *Gate) open(purpose, s string, v any) bool {
	p, sig, ok := strings.Cut(s, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(g.mac(purpose, p))) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

func (g *Gate) mac(purpose, payload string) string {
	h := hmac.New(sha256.New, g.store.sessionKey())
	h.Write([]byte(purpose + "." + payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// secure reports whether the browser reached us over HTTPS (directly, or via a
// proxy that says so), which decides the cookies' Secure flag.
func (g *Gate) secure(r *http.Request) bool {
	return g.baseSecure || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (g *Gate) setCookie(w http.ResponseWriter, r *http.Request, name, value, path string, maxAge time.Duration) {
	// Secure follows the request on purpose: a Secure cookie is never stored over
	// plain http, which would break a LAN-only install without a TLS proxy.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly and SameSite=Lax are fixed; Secure is per request
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   g.secure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gate) clearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- same attributes as setCookie
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: g.secure(r), SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gate) startSession(w http.ResponseWriter, r *http.Request, u *sessionUser) {
	now := time.Now()
	c := sessionClaims{Exp: now.Add(g.ttl).Unix(), Iat: now.Unix(), SID: randString(), U: u}
	g.setCookie(w, r, g.sessionCookie, g.seal(purposeSession, c), "/", g.ttl)
}

// session reports whether the request carries a valid, unexpired, unrevoked
// session, and who it is for, if the session says. It re-issues the cookie once
// less than half its lifetime remains (sliding expiry), keeping the same
// identity, sign-in time and ID: the groups are those from sign-in, so they are
// as old as the sign-in is, and the whole session ends at maxSessionFactor×TTL
// after sign-in however often it is renewed.
func (g *Gate) session(w http.ResponseWriter, r *http.Request) (*sessionUser, bool) {
	ck, err := r.Cookie(g.sessionCookie)
	if err != nil {
		return nil, false
	}
	var c sessionClaims
	if !g.open(purposeSession, ck.Value, &c) {
		return nil, false
	}
	now := time.Now()
	remaining := time.Unix(c.Exp, 0).Sub(now)
	if remaining <= 0 {
		return nil, false
	}
	if c.Iat > 0 && now.After(time.Unix(c.Iat, 0).Add(maxSessionFactor*g.ttl)) {
		return nil, false
	}
	if c.SID != "" && g.store.isRevoked(c.SID) {
		return nil, false
	}
	if remaining < g.ttl/2 {
		// A pre-upgrade session has no sign-in time or ID; stamp both here, so
		// the absolute cap and sign-out apply to it from now on.
		if c.Iat == 0 {
			c.Iat = now.Unix()
		}
		if c.SID == "" {
			c.SID = randString()
		}
		c.Exp = now.Add(g.ttl).Unix()
		g.setCookie(w, r, g.sessionCookie, g.seal(purposeSession, c), "/", g.ttl)
	}
	return c.U, true
}

// endSession revokes the request's session, so sign-out also kills every copy
// of the cookie, and clears it from the browser. The revocation is kept until
// the session would have hit its absolute cap anyway.
func (g *Gate) endSession(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(g.sessionCookie); err == nil {
		var c sessionClaims
		if g.open(purposeSession, ck.Value, &c) && c.SID != "" {
			keep := c.Exp
			if c.Iat > 0 {
				keep = c.Iat + int64(maxSessionFactor*g.ttl/time.Second)
			}
			if err := g.store.revoke(c.SID, keep); err != nil {
				g.log.Error("auth: recording the sign-out", "err", err)
			}
		}
	}
	g.clearCookie(w, r, g.sessionCookie, "/")
}

// csrfToken returns the double-submit token for the login and setup forms,
// setting its cookie if the browser has none yet.
func (g *Gate) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if ck, err := r.Cookie(g.csrfCookie); err == nil && len(ck.Value) == 43 {
		return ck.Value
	}
	t := randString()
	g.setCookie(w, r, g.csrfCookie, t, "/auth", 24*time.Hour)
	return t
}

// checkCSRF accepts a POST only when it comes from this site (when the browser
// says where it came from) and its form token matches the cookie's.
func (g *Gate) checkCSRF(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	ck, err := r.Cookie(g.csrfCookie)
	if err != nil || ck.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(ck.Value), []byte(r.PostFormValue("csrf"))) == 1
}

func randString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oidcgate: no entropy: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// limiter blocks password guessing: after max failures within window, every
// local login is refused until the window passes. It is process-wide, not per
// IP, because behind a proxy the client address cannot be trusted. OIDC logins
// are unaffected.
type limiter struct {
	mu     sync.Mutex
	fails  []time.Time
	max    int
	window time.Duration
}

func newLimiter() *limiter { return &limiter{max: 5, window: time.Minute} }

// blocked reports whether logins are currently refused, and for how long.
func (l *limiter) blocked(now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	if len(l.fails) < l.max {
		return false, 0
	}
	return true, l.fails[0].Add(l.window).Sub(now)
}

func (l *limiter) fail(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	l.fails = append(l.fails, now)
}

func (l *limiter) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails = nil
}

func (l *limiter) pruneLocked(now time.Time) {
	i := 0
	for i < len(l.fails) && now.Sub(l.fails[i]) >= l.window {
		i++
	}
	l.fails = l.fails[i:]
}
