// Command fakeidp is a minimal OpenID Connect provider for the integration
// suite: discovery, authorize (auto-approves a fixed user), token (verifies
// PKCE and the client secret) and JWKS. It is strict where a real provider is
// strict -- it checks the redirect URI, PKCE and the client credentials --
// so a misconfigured gate fails here the way it would against Authelia.
//
// Configuration, all environment variables:
//
//	ISSUER         externally visible issuer URL, e.g. http://fakeidp:8080 (required)
//	REDIRECT_URI   the one redirect URI the client may use (required)
//	CLIENT_ID      default "cid"
//	CLIENT_SECRET  default "csecret"
//	FAKEIDP_DENY   "true": authorize answers access_denied (also /testonly/deny?on=1|0)
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type idp struct {
	issuer, redirect, clientID, clientSecret string
	key                                      *rsa.PrivateKey

	mu        sync.Mutex
	deny      bool
	challenge map[string]string // code -> PKCE challenge
	nonce     map[string]string // code -> nonce
}

func main() {
	issuer, redirect := os.Getenv("ISSUER"), os.Getenv("REDIRECT_URI")
	if issuer == "" || redirect == "" {
		log.Fatal("ISSUER and REDIRECT_URI are required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	f := &idp{
		issuer: issuer, redirect: redirect,
		clientID: env("CLIENT_ID", "cid"), clientSecret: env("CLIENT_SECRET", "csecret"),
		key: key, deny: os.Getenv("FAKEIDP_DENY") == "true",
		challenge: map[string]string{}, nonce: map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/testonly/deny", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.deny = r.URL.Query().Get("on") == "1"
		f.mu.Unlock()
	})
	log.Print("fakeidp listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux)) // #nosec G114 -- test mock
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (f *idp) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *idp) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

func (f *idp) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case q.Get("client_id") != f.clientID:
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	case q.Get("redirect_uri") != f.redirect:
		http.Error(w, "redirect_uri not registered: "+q.Get("redirect_uri"), http.StatusBadRequest)
		return
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
		http.Error(w, "code flow with PKCE S256 is required", http.StatusBadRequest)
		return
	}
	redirect, _ := url.Parse(f.redirect)
	rq := redirect.Query()
	rq.Set("state", q.Get("state"))

	f.mu.Lock()
	if f.deny {
		rq.Set("error", "access_denied")
	} else {
		code := randToken()
		f.challenge[code] = q.Get("code_challenge")
		f.nonce[code] = q.Get("nonce")
		rq.Set("code", code)
	}
	f.mu.Unlock()
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *idp) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, secret, ok := r.BasicAuth(); !ok || id != f.clientID || secret != f.clientSecret {
		if r.FormValue("client_id") != f.clientID || r.FormValue("client_secret") != f.clientSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
	}
	code := r.FormValue("code")
	sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
	want, ok := f.challenge[code]
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != want {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	nonce := f.nonce[code]
	delete(f.challenge, code) // a code works once

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   f.issuer,
		Subject:  "it-user",
		Audience: jwt.Audience{f.clientID},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}).Claims(map[string]any{"nonce": nonce, "email": "it@example.com"}).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": raw})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
