// Package oidc is authy's OpenID Connect sign-in method: the authorization
// code flow with PKCE, state and nonce, verified by go-oidc. It authenticates;
// the shell owns the session it results in.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/miista/authy/internal/shell"
)

const (
	startPath    = "/auth/oidc"
	callbackPath = "/auth/callback"

	purposeFlow = "flow" // unchanged from oidcgate, so live flow cookies stay valid
	flowTTL     = 10 * time.Minute
)

// Config is the method's part of the gate's configuration, already validated
// by the gate (issuer, client and the redirect URL derived from BaseURL).
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	RetryBase    time.Duration // first discovery retry delay; tests shorten it
}

// Method implements shell.Method. The provider is discovered in the background
// when it is unreachable at startup, so state may be nil for a while.
type Method struct {
	sh         shell.Shell
	cfg        Config
	flowCookie string

	mu    sync.RWMutex
	state *providerState
}

type providerState struct {
	oauth    *oauth2.Config
	verifier *goidc.IDTokenVerifier
	provider *goidc.Provider
}

// flowClaims is the payload of the short-lived cookie carrying one login
// attempt's state between the start route and the callback.
type flowClaims struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Next     string `json:"next"`
	Exp      int64  `json:"exp"`
}

// New tries to reach the provider; an unreachable provider is not an error,
// discovery retries in the background until ctx ends.
func New(ctx context.Context, sh shell.Shell, cfg Config, flowCookie string) (*Method, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("auth: OIDC needs Issuer, ClientID and ClientSecret")
	}
	m := &Method{sh: sh, cfg: cfg, flowCookie: flowCookie}
	if err := m.discover(ctx, 5*time.Second); err != nil {
		retry := cfg.RetryBase
		if retry <= 0 {
			retry = 5 * time.Second
		}
		sh.Log().Warn("auth: OIDC provider not reachable yet; retrying in the background",
			"issuer", cfg.Issuer, "err", err)
		go m.discoverLoop(ctx, retry)
	}
	return m, nil
}

func (m *Method) Ready() bool { return m.get() != nil }

func (m *Method) Entry(next string) shell.Entry {
	return shell.Entry{Label: "OpenID Connect", URL: startPath + "?next=" + url.QueryEscape(next)}
}

func (m *Method) Serve(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case startPath:
		m.start(w, r)
	case callbackPath:
		m.callback(w, r)
	default:
		return false
	}
	return true
}

func (m *Method) get() *providerState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// discover contacts the provider and, on success, makes OIDC login available.
func (m *Method) discover(ctx context.Context, timeout time.Duration) error {
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	provider, err := goidc.NewProvider(dctx, m.cfg.Issuer)
	if err != nil {
		return err
	}
	s := &providerState{
		provider: provider,
		oauth: &oauth2.Config{
			ClientID:     m.cfg.ClientID,
			ClientSecret: m.cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  m.cfg.RedirectURL,
			Scopes:       scopesOrDefault(m.cfg.Scopes),
		},
		verifier: provider.Verifier(&goidc.Config{ClientID: m.cfg.ClientID}),
	}
	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
	return nil
}

func (m *Method) discoverLoop(ctx context.Context, delay time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		err := m.discover(ctx, 10*time.Second)
		if err == nil {
			m.sh.Log().Info("auth: OIDC provider reachable; OIDC login is now available", "issuer", m.cfg.Issuer)
			return
		}
		m.sh.Log().Warn("auth: OIDC provider still unreachable", "err", err)
		if delay *= 2; delay > time.Minute {
			delay = time.Minute
		}
	}
}

func (m *Method) start(w http.ResponseWriter, r *http.Request) {
	next := m.sh.SafeNext(r.URL.Query().Get("next"))
	s := m.get()
	if s == nil {
		m.sh.Fail(w, r, "unavailable", next, "provider not discovered yet")
		return
	}
	flow := flowClaims{
		State:    randString(),
		Nonce:    randString(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     next,
		Exp:      time.Now().Add(flowTTL).Unix(),
	}
	m.sh.SetCookie(w, r, m.flowCookie, m.sh.Seal(purposeFlow, flow), "/auth", flowTTL)
	authURL := s.oauth.AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier), goidc.Nonce(flow.Nonce))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (m *Method) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()

	var flow flowClaims
	ck, err := r.Cookie(m.flowCookie)
	if err != nil || !m.sh.Open(purposeFlow, ck.Value, &flow) || time.Now().Unix() > flow.Exp {
		m.sh.Fail(w, r, "failed", "/", "missing or invalid flow cookie")
		return
	}
	m.sh.ClearCookie(w, r, m.flowCookie, "/auth")
	next := m.sh.SafeNext(flow.Next)

	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		m.sh.Fail(w, r, "failed", next, "state mismatch")
		return
	}
	if e := q.Get("error"); e != "" {
		code := "failed"
		if e == "access_denied" {
			code = "access_denied"
		}
		m.sh.Fail(w, r, code, next, "idp returned error "+e+": "+q.Get("error_description"))
		return
	}
	s := m.get()
	if s == nil {
		m.sh.Fail(w, r, "unavailable", next, "provider not discovered yet")
		return
	}
	code := q.Get("code")
	if code == "" {
		m.sh.Fail(w, r, "failed", next, "no code in callback")
		return
	}
	tok, err := s.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		m.sh.Fail(w, r, "failed", next, "token exchange: "+err.Error())
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		m.sh.Fail(w, r, "failed", next, "no id_token in token response")
		return
	}
	idToken, err := s.verifier.Verify(r.Context(), rawID)
	if err != nil {
		m.sh.Fail(w, r, "failed", next, "id_token verification: "+err.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		m.sh.Fail(w, r, "failed", next, "nonce mismatch")
		return
	}

	id, err := m.identity(r.Context(), s, tok, idToken)
	if err != nil {
		m.sh.Fail(w, r, "failed", next, "reading the user's claims: "+err.Error())
		return
	}
	if err := m.sh.SignIn(w, r, id, next); err != nil {
		m.sh.Fail(w, r, "failed", next, err.Error())
		return
	}
	m.sh.Log().Info("auth: oidc login ok", "sub", idToken.Subject)
}

// claims are what the method reads, from the ID token or UserInfo.
type claims struct {
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
	hasGroups         bool
}

// identity builds the authenticated identity. Some providers (Authelia by
// default) serve the profile and groups only from the UserInfo endpoint, so
// when groups were asked for and the ID token has none, UserInfo is asked too.
// It is not optional then: an app that asked for groups decides who may do
// what by them, so a login whose groups cannot be read fails rather than carry
// on without them. A user with no groups at all is fine, and is told apart
// from "could not ask" by the call succeeding.
func (m *Method) identity(ctx context.Context, s *providerState, tok *oauth2.Token, idToken *goidc.IDToken) (shell.Identity, error) {
	var c claims
	if err := idToken.Claims(&c); err != nil {
		return shell.Identity{}, err
	}
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return shell.Identity{}, err
	}
	_, c.hasGroups = raw["groups"]

	if wantsGroups(m.cfg.Scopes) && !c.hasGroups {
		ui, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return shell.Identity{}, fmt.Errorf("userinfo: %w", err)
		}
		if ui.Subject != idToken.Subject {
			return shell.Identity{}, errors.New("userinfo is for a different subject than the id_token")
		}
		var fromInfo claims
		if err := ui.Claims(&fromInfo); err != nil {
			return shell.Identity{}, err
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

	return shell.Identity{Subject: idToken.Subject, Username: c.PreferredUsername, DisplayName: c.Name, Email: c.Email, Groups: c.Groups}, nil
}

// scopesOrDefault is what is asked of the provider: the configured scopes, or
// "openid profile email", and always "openid".
func scopesOrDefault(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	out := make([]string, 0, len(scopes)+1)
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		out = append(out, "openid")
	}
	return append(out, scopes...)
}

func wantsGroups(scopes []string) bool {
	for _, s := range scopes {
		if s == "groups" {
			return true
		}
	}
	return false
}

func randString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("authy: no entropy: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
