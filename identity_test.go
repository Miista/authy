package oidcgate

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type who struct {
	OK   bool `json:"ok"`
	User struct {
		Subject string
		Name    string
		Email   string
		Groups  []string
		Local   bool
	} `json:"user"`
}

func whoami(t *testing.T, c *http.Client, app string) (who, int) {
	t.Helper()
	res, body := get(t, c, app+"/whoami", nil)
	var w who
	_ = json.Unmarshal([]byte(body), &w)
	return w, res.StatusCode
}

// oidcApp starts an app gated by the fake IdP, asking for the "groups" scope the
// way an app that needs roles would.
func oidcApp(t *testing.T, idp *fakeIdP, scopes ...string) (string, *Gate) {
	t.Helper()
	cfg := Config{OIDC: oidcCfg(idp)}
	if len(scopes) > 0 {
		WithScopes(scopes...)(&cfg)
	}
	app, g := startApp(t, cfg)
	return app.URL, g
}

func signInOIDC(t *testing.T, app string) *http.Client {
	t.Helper()
	c := browser()
	_, _ = get(t, c, app+"/", nav)
	return c
}

func sessionPayload(t *testing.T, c *http.Client, app string, g *Gate) string {
	t.Helper()
	u, _ := url.Parse(app)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == g.sessionCookie {
			p, _, _ := strings.Cut(ck.Value, ".")
			b, _ := base64.RawURLEncoding.DecodeString(p)
			return string(b)
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestLocalAccountIsAUserWithNoGroups(t *testing.T) {
	app, g := startApp(t, Config{})
	c := signedIn(t, app, g)
	w, code := whoami(t, c, app.URL)
	if code != 200 || !w.OK || w.User.Subject != "local:alice" || w.User.Name != "alice" || !w.User.Local || len(w.User.Groups) != 0 {
		t.Errorf("%d %+v", code, w)
	}
}

func TestFirstLaunchSetupSignsTheNewAccountIn(t *testing.T) {
	app, _ := startApp(t, Config{})
	c := browser()
	tok := formToken(t, c, app.URL+"/auth/setup")
	do(t, c, "POST", app.URL+"/auth/setup", url.Values{"username": {"owner"}, "password": {"correct horse"}, "confirm": {"correct horse"}, "csrf": {tok}}, nil)
	if w, _ := whoami(t, c, app.URL); !w.OK || w.User.Name != "owner" || !w.User.Local {
		t.Errorf("%+v", w)
	}
}

func TestOIDCUserFromTheIDTokenWithoutAskingUserInfo(t *testing.T) {
	idp := newFakeIdP(t)
	idp.idClaims = map[string]any{"preferred_username": "alice", "groups": []string{"admins", "users"}}
	idp.Start()
	app, _ := oidcApp(t, idp, "openid", "profile", "email", "groups")
	w, code := whoami(t, signInOIDC(t, app), app)
	if code != 200 || !w.OK || w.User.Subject != "user-1" || w.User.Name != "alice" || w.User.Email != "a@example.com" || w.User.Local {
		t.Fatalf("%d %+v", code, w)
	}
	if strings.Join(w.User.Groups, ",") != "admins,users" {
		t.Errorf("groups = %v", w.User.Groups)
	}
	if idp.userinfoHits != 0 {
		t.Error("UserInfo was called although the id_token had the groups")
	}
}

func TestOIDCGroupsOnlyInUserInfoAreFetched(t *testing.T) {
	// Authelia serves groups from UserInfo unless a claims policy says otherwise.
	idp := newFakeIdP(t)
	idp.userinfo = map[string]any{"preferred_username": "alice", "name": "Alice", "groups": []string{"media-editors", "users"}}
	idp.Start()
	app, _ := oidcApp(t, idp, "openid", "profile", "email", "groups")
	w, code := whoami(t, signInOIDC(t, app), app)
	if code != 200 || !w.OK || w.User.Name != "alice" || strings.Join(w.User.Groups, ",") != "media-editors,users" {
		t.Errorf("%d %+v", code, w)
	}
	if idp.userinfoHits != 1 {
		t.Errorf("UserInfo hits = %d, want 1", idp.userinfoHits)
	}
}

func TestOIDCUserWithNoGroupsStillSignsIn(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userinfo = map[string]any{"preferred_username": "guest"} // the claim is simply absent
	idp.Start()
	app, _ := oidcApp(t, idp, "openid", "profile", "email", "groups")
	w, code := whoami(t, signInOIDC(t, app), app)
	if code != 200 || !w.OK || w.User.Name != "guest" || len(w.User.Groups) != 0 {
		t.Errorf("%d %+v", code, w)
	}
}

func TestOIDCLoginFailsWhenGroupsWereAskedForButCannotBeRead(t *testing.T) {
	for name, setup := range map[string]func(*fakeIdP){
		"UserInfo is unavailable": func(f *fakeIdP) { f.userinfo = nil },
		"UserInfo is for someone else": func(f *fakeIdP) {
			f.userinfo = map[string]any{"groups": []string{"admins"}}
			f.userinfoSub = "someone-else"
		},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIdP(t)
			setup(idp)
			idp.Start()
			app, _ := oidcApp(t, idp, "openid", "profile", "email", "groups")
			c := signInOIDC(t, app)
			if w, code := whoami(t, c, app); code == 200 || w.OK {
				t.Errorf("a login whose groups cannot be read must not sign anyone in: %d %+v", code, w)
			}
		})
	}
}

func TestOIDCWithoutTheGroupsScopeNeverAsksUserInfo(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userinfo = map[string]any{"groups": []string{"admins"}}
	idp.Start()
	app, _ := oidcApp(t, idp) // the default scopes
	w, code := whoami(t, signInOIDC(t, app), app)
	if code != 200 || !w.OK || w.User.Subject != "user-1" || len(w.User.Groups) != 0 || idp.userinfoHits != 0 {
		t.Errorf("%d %+v userinfo hits %d: an app that did not ask for groups gets none", code, w, idp.userinfoHits)
	}
	if strings.Join(idp.scopes, " ") != "openid profile email" {
		t.Errorf("default scopes = %v", idp.scopes)
	}
}

func TestWithScopesIsWhatIsRequested(t *testing.T) {
	idp := newFakeIdP(t)
	idp.userinfo = map[string]any{}
	idp.Start()
	app, _ := oidcApp(t, idp, "profile", "groups") // no "openid": the gate adds it
	signInOIDC(t, app)
	got := strings.Join(idp.scopes, " ")
	if got != "openid profile groups" {
		t.Errorf("scope = %q, want openid added in front of exactly what the app asked for", got)
	}
}

func TestWithScopesHasNoEffectWithoutOIDC(t *testing.T) {
	cfg := Config{}
	WithScopes("groups")(&cfg) // must not panic
	if cfg.OIDC != nil {
		t.Error("WithScopes must not create an OIDC config")
	}
}

func TestTheIdentityIsSignedAndCannotBeEdited(t *testing.T) {
	idp := newFakeIdP(t)
	idp.idClaims = map[string]any{"groups": []string{"users"}}
	idp.Start()
	app, g := oidcApp(t, idp, "openid", "profile", "email", "groups")
	c := signInOIDC(t, app)
	u, _ := url.Parse(app)
	var raw string
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == g.sessionCookie {
			raw = ck.Value
		}
	}
	payload, sig, _ := strings.Cut(raw, ".")
	b, _ := base64.RawURLEncoding.DecodeString(payload)
	forged := strings.Replace(string(b), `"users"`, `"admins"`, 1)
	if forged == string(b) {
		t.Fatalf("setup: no group to forge in %s", b)
	}
	evil := browser()
	evil.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + sig, Path: "/"}})
	if w, code := whoami(t, evil, app); code != 401 || w.OK {
		t.Errorf("a cookie with edited groups was accepted: %d %+v", code, w)
	}
}

func TestIdentitySurvivesTheSlidingRefresh(t *testing.T) {
	app, g := startApp(t, Config{SessionTTL: time.Hour})
	g.ttl = time.Hour
	su := newSessionUser("user-1", "alice", "a@example.com", []string{"admins"}, false)
	old := g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(10 * time.Minute).Unix(), U: su}) // under half left
	u, _ := url.Parse(app.URL)
	c := browser()
	c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: old, Path: "/"}})
	w, code := whoami(t, c, app.URL)
	if code != 200 || w.User.Subject != "user-1" || len(w.User.Groups) != 1 {
		t.Fatalf("%d %+v", code, w)
	}
	var sc sessionClaims
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == g.sessionCookie {
			g.open(purposeSession, ck.Value, &sc)
		}
	}
	if sc.U == nil || sc.U.Sub != "user-1" || len(sc.U.Groups) != 1 || time.Until(time.Unix(sc.Exp, 0)) < 50*time.Minute {
		t.Errorf("the refreshed cookie must carry the same identity and a fresh expiry: %+v", sc)
	}
}

func TestASessionFromBeforeIdentitiesIsStillValidButHasNoUser(t *testing.T) {
	app, g := startApp(t, Config{})
	g.store.createAccount("alice", "correct horse")
	old := g.seal(purposeSession, sessionClaims{Exp: time.Now().Add(time.Hour).Unix()})
	u, _ := url.Parse(app.URL)
	c := browser()
	c.Jar.SetCookies(u, []*http.Cookie{{Name: g.sessionCookie, Value: old, Path: "/"}})
	w, code := whoami(t, c, app.URL)
	if code != 200 || w.OK {
		t.Errorf("an app that does not use identities keeps working, and one that does sees nobody: %d %+v", code, w)
	}
}

func TestNobodyOnAPublicPath(t *testing.T) {
	app, g := startApp(t, Config{PublicPaths: []string{"/whoami"}})
	c := signedIn(t, app, g)
	if w, code := whoami(t, c, app.URL); code != 200 || w.OK {
		t.Errorf("a public path skips the gate, so it must not claim to know the user: %d %+v", code, w)
	}
}

func TestNobodyWithTheGateOff(t *testing.T) {
	var g *Gate
	var got bool
	g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, got = UserFrom(r) })).ServeHTTP(
		nopWriter{}, mustReq(t, "/"))
	if got {
		t.Error("a nil gate must report no user")
	}
}

func TestEntriesAreCleanedBeforeTheyGoIntoACookie(t *testing.T) {
	many := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		many = append(many, "group-"+strings.Repeat("x", i%5)+string(rune('a'+i%26))+strings.Repeat("y", i))
	}
	long := strings.Repeat("z", maxGroupLen+1)
	u := newSessionUser("user-1", "  ali\nce\t ", "a@example.com", append([]string{"admins", "admins", "", long, "ad\x00mins2"}, many...), false)
	if u.Name != "alice" {
		t.Errorf("name = %q", u.Name)
	}
	if len(u.Groups) > maxGroups {
		t.Errorf("%d groups kept, cap is %d", len(u.Groups), maxGroups)
	}
	seen := map[string]int{}
	for _, g := range u.Groups {
		seen[g]++
		if g == long || g == "" || len(g) > maxGroupLen || strings.ContainsAny(g, "\x00\n") {
			t.Errorf("bad group kept: %q", g)
		}
	}
	if seen["admins"] != 1 || seen["admins2"] != 1 {
		t.Errorf("duplicates should collapse and control characters be stripped: %v", seen)
	}
	b, _ := json.Marshal(sessionClaims{Exp: time.Now().Unix(), U: u})
	if len(b)*4/3+64 > 3800 {
		t.Errorf("the session cookie would be about %d bytes: too close to the 4 KB limit", len(b)*4/3+64)
	}
}

func TestAnIdentityWithoutASubjectIsRefused(t *testing.T) {
	if newSessionUser("", "x", "a@b", nil, false) != nil || newSessionUser("  \n", "x", "", nil, false) != nil {
		t.Error("two people with no stable ID could be mistaken for one")
	}
	if localUser("") != nil || localUser("   ") != nil {
		t.Error("an empty local username must not make a user")
	}
	if newSessionUser("s", "", "", nil, false).Name != "s" {
		t.Error("the name should fall back to the subject")
	}
}

func TestInGroupIsExact(t *testing.T) {
	u := User{Groups: []string{"admins", "media-editors"}}
	for g, want := range map[string]bool{"admins": true, "media-editors": true, "Admins": false, "admin": false, "": false, "media": false} {
		if u.InGroup(g) != want {
			t.Errorf("InGroup(%q) = %v, want %v", g, !want, want)
		}
	}
}

type nopWriter struct{}

func (nopWriter) Header() http.Header         { return http.Header{} }
func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopWriter) WriteHeader(int)             {}

func mustReq(t *testing.T, path string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
