// Package shell is the contract between the authy pipeline and its sign-in
// methods. A method owns one ceremony (OIDC, a local form); the shell owns
// everything they share: the session, sign-out, the fallback page, cookies and
// redirects. Methods never import each other, and only the shell mints
// sessions, so session revocation and the absolute lifetime cap apply to every
// method the same way.
package shell

import (
	"log/slog"
	"net/http"
	"time"
)

// Identity is who a method authenticated. The shell cleans it (length caps,
// control characters) before it enters a session; a method hands it over raw.
type Identity struct {
	Subject string
	Name    string
	Email   string
	Groups  []string
}

// Entry is a method's line on the sign-in page: where its ceremony starts.
type Entry struct {
	Label string // e.g. "OpenID Connect"
	URL   string // e.g. /auth/oidc?next=%2F
}

// Method is one way to sign a browser in.
type Method interface {
	// Serve handles the method's own routes (its callback, its form POST) and
	// reports whether it recognised the path.
	Serve(w http.ResponseWriter, r *http.Request) bool
	// Entry is the method's line on the sign-in page, for the given return path.
	Entry(next string) Entry
	// Ready reports whether the ceremony can start right now (an OIDC method
	// is not ready until its provider is discovered). The sign-in page lists
	// the method either way; Ready only steers the automatic redirect.
	Ready() bool
}

// FormPage is a gate-styled page with one POST form, for a method that signs
// people in with a form of its own (the local account). The shell renders it,
// so every method's pages share one look and one set of response headers.
type FormPage struct {
	Title   string
	Heading string
	Error   string
	Message string
	Action  string // the POST target, one of the method's own routes
	Submit  string // the button's label
	Next    string // carried through the form, already SafeNext-ed by the caller
	CSRF    string // from CSRFToken; the shell adds the hidden fields
	Fields  []Field
}

// Field is one input on a FormPage.
type Field struct {
	ID           string
	Name         string
	Label        string
	Type         string // "text" or "password"
	Autocomplete string
	MinLen       int
	MaxLen       int
	Autofocus    bool
}

// Shell is what the pipeline offers a method. It is implemented by the gate.
type Shell interface {
	// SignIn mints the session for an authenticated identity and redirects to
	// next. It fails only on an identity with no usable subject.
	SignIn(w http.ResponseWriter, r *http.Request, id Identity, next string) error
	// Fail logs detail and sends the browser to the fallback page with a
	// generic error code ("failed", "access_denied", "unavailable").
	Fail(w http.ResponseWriter, r *http.Request, code, next, detail string)
	// Seal and Open sign and verify a method's own short-lived state (e.g. an
	// OIDC flow cookie) with the shell's key, bound to purpose.
	Seal(purpose string, v any) string
	Open(purpose, sealed string, v any) bool
	SetCookie(w http.ResponseWriter, r *http.Request, name, value, path string, maxAge time.Duration)
	ClearCookie(w http.ResponseWriter, r *http.Request, name, path string)
	// SafeNext keeps only same-site absolute paths outside /auth/.
	SafeNext(next string) string
	Log() *slog.Logger

	// RenderForm shows a method's form page in the gate's shared style.
	RenderForm(w http.ResponseWriter, status int, p FormPage)
	// CSRFToken returns the double-submit token for a method's form, setting
	// its cookie if the browser has none yet; CheckCSRF verifies a POST
	// against it (and against Sec-Fetch-Site).
	CSRFToken(w http.ResponseWriter, r *http.Request) string
	CheckCSRF(r *http.Request) bool
}
