package authy

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miista/authy/internal/shell"
)

// localNamespace is the local method's subject prefix. The shell owns the
// namespacing, so no other method — today OIDC, tomorrow anything — can hand
// over an identity that collides with a local account (an IdP token whose sub
// is literally "local:admin", say).
const localNamespace = "local:"

// gateShell is the gate as one method sees it (shell.Shell). Each method gets
// its own handle carrying its namespace; the helpers stay off Gate's public API.
type gateShell struct {
	g  *Gate
	ns string // "local" for the local method, anything else for the rest
}

// SignIn mints the session for an authenticated identity and redirects to
// next. The identity is cleaned here (length caps, control characters), so a
// method cannot put an unclean value into a session; an identity whose subject
// does not survive cleaning is refused, because an identity with no stable ID
// would let two people be mistaken for one. The local namespace is enforced in
// both directions: only the local method may use it, and it must.
func (s *gateShell) SignIn(w http.ResponseWriter, r *http.Request, id shell.Identity, next string) error {
	u := newSessionUser(id.Subject, id.Username, id.DisplayName, id.Email, id.Groups)
	if u == nil {
		return errors.New("the identity has no usable subject")
	}
	// The namespace is checked on the cleaned subject — the one that enters
	// the session — never the raw one: cleaning trims whitespace and control
	// characters, so " local:admin" from a provider would otherwise pass the
	// raw check and still normalise into the local namespace.
	if (s.ns == "local") != strings.HasPrefix(u.Sub, localNamespace) {
		return errors.New(`the subject is outside the method's namespace ("local:" is the local account's)`)
	}
	if len(id.Groups) > len(u.Groups) {
		s.g.log.Warn("auth: some groups were dropped (too many or too long)", "sub", u.Sub, "sent", len(id.Groups), "kept", len(u.Groups))
	}
	s.g.startSession(w, r, u)
	redirectLocal(w, r, safeNext(next))
	return nil
}

// Fail logs the detail and sends the browser to the fallback page with a
// generic error code, where it shows the entries instead of redirecting again.
func (s *gateShell) Fail(w http.ResponseWriter, r *http.Request, code, next, detail string) {
	s.g.log.Warn("auth: login not completed", "method", s.ns, "code", code, "reason", detail)
	http.Redirect(w, r, loginPath+"?error="+url.QueryEscape(code)+"&next="+url.QueryEscape(next), http.StatusFound)
}

// Seal and Open refuse the session purpose: only the shell mints sessions
// (through SignIn, which cleans the identity), and no method may forge one.
// The purpose is also bound to the method, so two methods cannot open each
// other's cookies.
func (s *gateShell) Seal(purpose string, v any) string {
	if purpose == purposeSession {
		panic("authy: methods must not seal sessions; use SignIn")
	}
	return s.g.seal(s.ns+":"+purpose, v)
}

func (s *gateShell) Open(purpose, sealed string, v any) bool {
	if purpose == purposeSession {
		panic("authy: methods must not open sessions")
	}
	return s.g.open(s.ns+":"+purpose, sealed, v)
}

func (s *gateShell) SetCookie(w http.ResponseWriter, r *http.Request, name, value, path string, maxAge time.Duration) {
	s.g.setCookie(w, r, name, value, path, maxAge)
}

func (s *gateShell) ClearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	s.g.clearCookie(w, r, name, path)
}

func (s *gateShell) SafeNext(next string) string { return safeNext(next) }

func (s *gateShell) Log() *slog.Logger { return s.g.log }

func (s *gateShell) RenderForm(w http.ResponseWriter, status int, p shell.FormPage) {
	s.g.render(w, status, pageData{
		Title: p.Title, Heading: p.Heading, Error: p.Error, Message: p.Message, Form: &p,
	})
}

func (s *gateShell) CSRFToken(w http.ResponseWriter, r *http.Request) string {
	return s.g.csrfToken(w, r)
}

func (s *gateShell) CheckCSRF(r *http.Request) bool { return s.g.checkCSRF(r) }
