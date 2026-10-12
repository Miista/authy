package authy

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/miista/authy/internal/shell"
)

// gateShell is the gate as a method sees it (shell.Shell). It is a separate
// type so the helpers a method may call stay off Gate's public API.
type gateShell Gate

func (s *gateShell) gate() *Gate { return (*Gate)(s) }

// SignIn mints the session for an authenticated identity and redirects to
// next. The identity is cleaned here (length caps, control characters), so a
// method cannot put an unclean value into a session; an identity whose subject
// does not survive cleaning is refused, because an identity with no stable ID
// would let two people be mistaken for one.
func (s *gateShell) SignIn(w http.ResponseWriter, r *http.Request, id shell.Identity, next string) error {
	g := s.gate()
	u := newSessionUser(id.Subject, id.Name, id.Email, id.Groups)
	if u == nil {
		return errors.New("the identity has no usable subject")
	}
	if len(id.Groups) > len(u.Groups) {
		g.log.Warn("auth: some groups were dropped (too many or too long)", "sub", u.Sub, "sent", len(id.Groups), "kept", len(u.Groups))
	}
	g.startSession(w, r, u)
	redirectLocal(w, r, safeNext(next))
	return nil
}

// Fail logs the detail and sends the browser to the fallback page with a
// generic error code, where it shows the entries instead of redirecting again.
func (s *gateShell) Fail(w http.ResponseWriter, r *http.Request, code, next, detail string) {
	g := s.gate()
	g.log.Warn("auth: login not completed", "code", code, "reason", detail)
	http.Redirect(w, r, loginPath+"?error="+url.QueryEscape(code)+"&next="+url.QueryEscape(next), http.StatusFound)
}

// Seal and Open refuse the session purpose: only the shell mints sessions
// (through SignIn, which cleans the identity), and no method may forge one.
func (s *gateShell) Seal(purpose string, v any) string {
	if purpose == purposeSession {
		panic("authy: methods must not seal sessions; use SignIn")
	}
	return s.gate().seal(purpose, v)
}

func (s *gateShell) Open(purpose, sealed string, v any) bool {
	if purpose == purposeSession {
		panic("authy: methods must not open sessions")
	}
	return s.gate().open(purpose, sealed, v)
}

func (s *gateShell) SetCookie(w http.ResponseWriter, r *http.Request, name, value, path string, maxAge time.Duration) {
	s.gate().setCookie(w, r, name, value, path, maxAge)
}

func (s *gateShell) ClearCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	s.gate().clearCookie(w, r, name, path)
}

func (s *gateShell) SafeNext(next string) string { return safeNext(next) }

func (s *gateShell) Log() *slog.Logger { return s.gate().log }
