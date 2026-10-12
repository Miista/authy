// Package local is authy's local-account sign-in method: one account, created
// on first launch, verified with bcrypt. It exists chiefly for apps where OIDC
// is not configured, and as an explicit opt-in escape hatch next to it. It
// authenticates; the shell owns the session it results in, and the subject it
// hands over lives in the "local:" namespace the shell enforces.
package local

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miista/authy/internal/shell"
)

const (
	loginPath = "/auth/local"
	setupPath = "/auth/setup"
)

// Method implements shell.Method.
type Method struct {
	sh  shell.Shell
	st  *store
	lim *limiter
}

// New opens the account store in dir (the gate's data directory). Setup is
// open while no account exists; creating the account closes it for good.
func New(sh shell.Shell, dir string) (*Method, error) {
	st, err := openStore(dir)
	if err != nil {
		return nil, err
	}
	return &Method{sh: sh, st: st, lim: newLimiter()}, nil
}

// Ready is always true: a form needs no discovery. With OIDC stacked first,
// the automatic redirect still goes to the IdP; the local entry is reached
// from the sign-in page.
func (m *Method) Ready() bool { return true }

func (m *Method) Entry(next string) shell.Entry {
	label := "the local account"
	if !m.st.hasAccount() {
		label = "a new local account"
	}
	return shell.Entry{Label: label, URL: loginPath + "?next=" + url.QueryEscape(next)}
}

func (m *Method) Serve(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case loginPath:
		m.handleLogin(w, r)
	case setupPath:
		m.handleSetup(w, r)
	default:
		return false
	}
	return true
}

// --- login -----------------------------------------------------------------

func (m *Method) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !m.st.hasAccount() {
		http.Redirect(w, r, setupPath+"?next="+url.QueryEscape(m.sh.SafeNext(nextFrom(r))), http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		m.showLogin(w, r, http.StatusOK, "", m.sh.SafeNext(r.URL.Query().Get("next")))
	case http.MethodPost:
		m.postLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Method) showLogin(w http.ResponseWriter, r *http.Request, status int, msg, next string) {
	m.sh.RenderForm(w, status, shell.FormPage{
		Title: "Sign in", Heading: "Sign in", Error: msg,
		Action: loginPath, Submit: "Sign in", Next: next, CSRF: m.sh.CSRFToken(w, r),
		Fields: []shell.Field{
			{ID: "u", Name: "username", Label: "Username", Type: "text", Autocomplete: "username", MaxLen: maxUsernameN, Autofocus: true},
			{ID: "p", Name: "password", Label: "Password", Type: "password", Autocomplete: "current-password", MaxLen: maxPassword},
		},
	})
}

func (m *Method) postLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := m.sh.SafeNext(r.PostFormValue("next"))
	if !m.sh.CheckCSRF(r) {
		m.showLogin(w, r, http.StatusForbidden, "Your session expired. Please try again.", next)
		return
	}
	now := time.Now()
	if blocked, wait := m.lim.blocked(now); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		m.showLogin(w, r, http.StatusTooManyRequests, "Too many failed attempts. Try again in a minute.", next)
		return
	}
	if !m.st.verify(r.PostFormValue("username"), r.PostFormValue("password")) {
		m.lim.fail(now)
		m.sh.Log().Warn("auth: local login failed")
		m.showLogin(w, r, http.StatusUnauthorized, "Invalid username or password.", next)
		return
	}
	m.lim.reset()
	m.signIn(w, r, r.PostFormValue("username"), next)
}

// --- first-launch account creation ------------------------------------------

func (m *Method) handleSetup(w http.ResponseWriter, r *http.Request) {
	// Setup exists only while there is no account; afterwards nobody can
	// create another or take over.
	if m.st.hasAccount() {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		m.showSetup(w, r, http.StatusOK, "", m.sh.SafeNext(r.URL.Query().Get("next")))
	case http.MethodPost:
		m.postSetup(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (m *Method) showSetup(w http.ResponseWriter, r *http.Request, status int, msg, next string) {
	m.sh.RenderForm(w, status, shell.FormPage{
		Title: "Create your account", Heading: "Create your account",
		Message: "Choose a username and password. This is the only account.",
		Error:   msg, Action: setupPath, Submit: "Create account", Next: next, CSRF: m.sh.CSRFToken(w, r),
		Fields: []shell.Field{
			{ID: "u", Name: "username", Label: "Username", Type: "text", Autocomplete: "username", MaxLen: maxUsernameN, Autofocus: true},
			{ID: "p", Name: "password", Label: "Password", Type: "password", Autocomplete: "new-password", MinLen: minPassword, MaxLen: maxPassword},
			{ID: "c", Name: "confirm", Label: "Confirm password", Type: "password", Autocomplete: "new-password", MinLen: minPassword, MaxLen: maxPassword},
		},
	})
}

func (m *Method) postSetup(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := m.sh.SafeNext(r.PostFormValue("next"))
	if !m.sh.CheckCSRF(r) {
		m.showSetup(w, r, http.StatusForbidden, "Your session expired. Please try again.", next)
		return
	}
	username, password := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	if err := validateCredentials(username, password); err != nil {
		m.showSetup(w, r, http.StatusBadRequest, err.Error(), next)
		return
	}
	if password != r.PostFormValue("confirm") {
		m.showSetup(w, r, http.StatusBadRequest, "The passwords do not match.", next)
		return
	}
	switch err := m.st.createAccount(username, password); {
	case err == errAccountExists:
		http.Redirect(w, r, loginPath+"?next="+url.QueryEscape(next), http.StatusFound)
		return
	case err != nil:
		m.sh.Log().Error("auth: creating the account", "err", err)
		m.showSetup(w, r, http.StatusInternalServerError, "Could not save the account. Check the server log.", next)
		return
	}
	m.sh.Log().Info("auth: local account created")
	m.signIn(w, r, username, next)
}

func (m *Method) signIn(w http.ResponseWriter, r *http.Request, username, next string) {
	username = strings.TrimSpace(username)
	id := shell.Identity{Subject: "local:" + username, Name: username}
	if err := m.sh.SignIn(w, r, id, next); err != nil {
		m.sh.Fail(w, r, "failed", next, err.Error())
		return
	}
	m.sh.Log().Info("auth: local login ok")
}

// limiter blocks password guessing: after max failures within window, every
// local login is refused until the window passes. It is process-wide, not per
// IP, because behind a proxy the client address cannot be trusted. Other
// methods are unaffected.
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

func nextFrom(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue("next")
	}
	return r.URL.Query().Get("next")
}
