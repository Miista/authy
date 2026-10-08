package oidcgate

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// User is the authenticated identity, available to handlers behind the gate
// via UserFrom.
type User struct {
	Subject string
	Email   string
	Name    string
}

type ctxKey struct{}

// UserFrom returns the signed-in user for a request that passed the gate.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxKey{}).(User)
	return u, ok
}

// sessionClaims is the payload of the session cookie.
type sessionClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
	Exp   int64  `json:"exp"`
}

// flowClaims is the payload of the short-lived cookie carrying one login
// attempt's state between /auth/login and /auth/callback.
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
)

// seal serialises v and appends an HMAC bound to purpose, so a flow cookie
// can never be replayed as a session cookie.
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
	h := hmac.New(sha256.New, g.key)
	h.Write([]byte(purpose + "." + payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (g *Gate) setCookie(w http.ResponseWriter, name, value, path string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   g.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gate) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: g.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gate) startSession(w http.ResponseWriter, u User) {
	c := sessionClaims{Sub: u.Subject, Email: u.Email, Name: u.Name, Exp: time.Now().Add(g.ttl).Unix()}
	g.setCookie(w, g.sessionCookie, g.seal(purposeSession, c), "/", g.ttl)
}

// session returns the user for a valid, unexpired session cookie, and
// re-issues the cookie once less than half its lifetime remains (sliding
// expiry).
func (g *Gate) session(w http.ResponseWriter, r *http.Request) (User, bool) {
	ck, err := r.Cookie(g.sessionCookie)
	if err != nil {
		return User{}, false
	}
	var c sessionClaims
	if !g.open(purposeSession, ck.Value, &c) || c.Sub == "" {
		return User{}, false
	}
	remaining := time.Until(time.Unix(c.Exp, 0))
	if remaining <= 0 {
		return User{}, false
	}
	u := User{Subject: c.Sub, Email: c.Email, Name: c.Name}
	if remaining < g.ttl/2 {
		g.startSession(w, u)
	}
	return u, true
}
