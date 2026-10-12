package oidcgate

import (
	"context"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// User is who a request was made by. The gate records it when a browser signs in
// and hands it to the app through UserFrom, so an app can tell people apart and
// decide what each may do. Who may sign in at all is still decided at the
// identity provider.
type User struct {
	// Subject is the provider's stable ID for the person (the "sub" claim).
	Subject string
	// Name is the person's username if the provider gave one, else their name,
	// else their email, else the subject. It is for display and logs; it is not
	// an identifier, and two people can share one.
	Name  string
	Email string
	// Groups is the "groups" claim, which the provider only sends when the app
	// asked for the "groups" scope (see WithScopes).
	Groups []string
}

// InGroup reports whether the user is in the group (an exact, case-sensitive match).
func (u User) InGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}
	return false
}

type userKey struct{}

// UserFrom returns who the request is from. It reports false when the gate is
// off, for a public path, or for a session that carries no identity (one made
// before identities were recorded); an app that needs a user must treat all of
// those as "nobody".
func UserFrom(r *http.Request) (User, bool) {
	u, ok := r.Context().Value(userKey{}).(User)
	return u, ok
}

func withUser(r *http.Request, u User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey{}, u))
}

// Limits keep the session cookie, which carries the identity, well under the
// 4 KB browsers allow. Anything over a limit is dropped, never an error: a
// dropped group can only take access away.
const (
	maxNameLen    = 128
	maxEmailLen   = 254
	maxGroups     = 32
	maxGroupLen   = 64
	maxSubjectLen = 255
)

// sessionUser is the identity as it is stored in the session cookie.
type sessionUser struct {
	Sub    string   `json:"s"`
	Name   string   `json:"n,omitempty"`
	Email  string   `json:"e,omitempty"`
	Groups []string `json:"g,omitempty"`
}

func (s *sessionUser) user() User {
	return User{Subject: s.Sub, Name: s.Name, Email: s.Email, Groups: s.Groups}
}

// newSessionUser cleans what a provider sent. An empty subject yields nil: an
// identity with no stable ID would let two people be mistaken for one.
func newSessionUser(sub, name, email string, groups []string) *sessionUser {
	sub = clean(sub, maxSubjectLen)
	if sub == "" {
		return nil
	}
	u := &sessionUser{Sub: sub, Name: clean(name, maxNameLen), Email: clean(email, maxEmailLen)}
	if u.Name == "" {
		u.Name = u.Email
	}
	if u.Name == "" {
		u.Name = clean(sub, maxNameLen)
	}
	seen := map[string]bool{}
	for _, g := range groups {
		g = clean(g, maxGroupLen)
		if g == "" || seen[g] || len(u.Groups) >= maxGroups {
			continue
		}
		seen[g] = true
		u.Groups = append(u.Groups, g)
	}
	return u
}

// clean trims, drops control characters, and cuts to max bytes on a rune boundary.
// A value that was too long is dropped whole rather than cut, so a truncated group
// name can never equal a different, real one.
func clean(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if len(s) > max || !utf8.ValidString(s) {
		return ""
	}
	return s
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
