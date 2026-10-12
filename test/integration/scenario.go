//go:build integration

package integration

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// nextTestbed numbers the testbed directories within a run.
var nextTestbed atomic.Int64

const (
	subjectURL = "http://subject:8080" // the app, as a browser on the compose network names it
	idpURL     = "http://fakeidp:8080"
)

// Scenario is one test's world: a compose project in the testbed, with
// whatever the fixture declares running.
type Scenario struct {
	t    *testing.T
	Name string
	Dir  string // the project under testbed/

	mu    sync.Mutex
	hosts map[string]string // "subject:8080" -> "127.0.0.1:<published port>"
}

// Up copies hack/fixtures/<name> into the testbed and brings up everything it
// declares. Teardown is registered with the test, so the world is removed
// however the test ends, including a panic or a failed assertion.
func Up(t *testing.T, name string) *Scenario {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	// The testbed lives in the repository, not $TMPDIR: on macOS that is a
	// symlink, docker records the resolved path, and anything that looks a
	// path up afterwards silently finds nothing.
	//
	// And each scenario gets a directory of its own. Deleting a bind-mounted
	// directory and recreating it at the same path moments later leaves
	// Docker Desktop's file sharing serving the container a stale mount, which
	// shows up as the process failing to create files in a volume that is
	// plainly there. (Setup clears every testbed-* a killed run left behind.)
	s := &Scenario{
		t: t, Name: name, hosts: map[string]string{},
		Dir: filepath.Join(root, "testbed-"+strconv.FormatInt(nextTestbed.Add(1), 10)),
	}

	// Swept before the fixture goes in as well as after the test: a killed run
	// may have left containers behind.
	sweep()
	t.Cleanup(s.down)

	src := filepath.Join(root, "hack", "fixtures", filepath.FromSlash(name))
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("no fixture at %s", src)
	}
	if err := copyTree(src, s.Dir); err != nil {
		t.Fatal(err)
	}

	// The container runs as whoever ran the suite, so what it writes into the
	// mounted data directory belongs to us and the testbed can be removed.
	env := "RUN_AS=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()) + "\n"
	if err := os.WriteFile(filepath.Join(s.Dir, ".env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	// The state directory the fixtures mount. Created here, open, because docker
	// would otherwise create a missing bind source as root.
	if err := os.MkdirAll(filepath.Join(s.Dir, "data"), 0o777); err != nil {
		t.Fatal(err)
	}
	openPermissions(filepath.Join(s.Dir, "data"))

	if out, err := s.compose("up", "-d"); err != nil {
		t.Fatalf("bringing %s up: %v\n%s", name, err, out)
	}
	return s
}

func (s *Scenario) down() {
	if out, err := s.compose("down", "-v", "--remove-orphans", "-t", "1"); err != nil {
		s.t.Logf("compose down: %v\n%s", err, out)
	}
	if err := os.RemoveAll(s.Dir); err != nil {
		s.t.Logf("removing the testbed: %v", err)
	}
}

// compose runs `docker compose` in the testbed under the fixed project name.
func (s *Scenario) compose(args ...string) (string, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project}, args...)...)
	cmd.Dir = s.Dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Logs returns a service's output so far, for diagnostics and assertions.
func (s *Scenario) Logs(service string) string {
	out, _ := s.compose("logs", "--no-color", service)
	return out
}

// Restart restarts a service in place, keeping its volumes: a process restart
// as an operator would do it.
func (s *Scenario) Restart(service string) {
	s.t.Helper()
	if out, err := s.compose("restart", "-t", "1", service); err != nil {
		s.t.Fatalf("restarting %s: %v\n%s", service, err, out)
	}
	s.forget()
}

// StartService starts a service the fixture declared but did not start by
// itself (one under a compose profile), the way an IdP "comes up later".
func (s *Scenario) StartService(service string) {
	s.t.Helper()
	if out, err := s.compose("up", "-d", service); err != nil {
		s.t.Fatalf("starting %s: %v\n%s", service, err, out)
	}
	s.forget()
}

func (s *Scenario) forget() {
	s.mu.Lock()
	s.hosts = map[string]string{}
	s.mu.Unlock()
}

func (s *Scenario) containerID(service string) string {
	out, _ := s.compose("ps", "-aq", service)
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}

// Exited reports whether a service's container has stopped, and with what code.
func (s *Scenario) Exited(service string) (bool, string) {
	id := s.containerID(service)
	if id == "" {
		return false, ""
	}
	out, err := docker("inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", id)
	if err != nil {
		return false, ""
	}
	f := strings.Fields(out)
	if len(f) == 2 && f[0] == "exited" {
		return true, f[1]
	}
	return false, ""
}

// CopyOut copies a path out of a service's container into a fresh directory,
// preserving the modes the process gave it, and returns where it landed.
func (s *Scenario) CopyOut(service, path string) string {
	s.t.Helper()
	id := s.containerID(service)
	if id == "" {
		s.t.Fatalf("no container for %s", service)
	}
	dest := s.t.TempDir()
	if out, err := docker("cp", id+":"+path, dest); err != nil {
		s.t.Fatalf("copying %s out of %s: %v\n%s", path, service, err, out)
	}
	return dest
}

// hostPort finds where a container port is published on this host.
func (s *Scenario) hostPort(service, port string) (string, bool) {
	out, err := s.compose("port", service, port)
	if err != nil || out == "" {
		return "", false
	}
	line := strings.Split(out, "\n")[0]
	_, p, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		return "", false
	}
	return net.JoinHostPort("127.0.0.1", p), true
}

// resolve maps a container-network address a browser would use to the host
// port it is published on. Not cached across restarts: random host ports can
// change when a container restarts.
func (s *Scenario) resolve(addr string) string {
	service, port, err := net.SplitHostPort(addr)
	if err != nil || (service != "subject" && service != "fakeidp") {
		return addr
	}
	s.mu.Lock()
	cached, ok := s.hosts[addr]
	s.mu.Unlock()
	if ok {
		return cached
	}
	hp, ok := s.hostPort(service, port)
	if !ok {
		return "127.0.0.1:1" // not up: refuse, like a host that is down
	}
	s.mu.Lock()
	s.hosts[addr] = hp
	s.mu.Unlock()
	return hp
}

// WaitReady waits until the subject answers its public health check.
func (s *Scenario) WaitReady() {
	s.t.Helper()
	b := s.Browser()
	waitFor(s.t, "the subject to answer /healthz", 30*time.Second, func() bool {
		r, err := b.try("GET", "/healthz", nil, nil)
		return err == nil && r.Status == 200
	}, func() string { return s.Logs("subject") })
}

// --- browser -------------------------------------------------------------

// Browser is an HTTP client that behaves like a browser on the compose
// network: it keeps cookies and follows redirects, and it reaches
// subject:8080 and fakeidp:8080 through their published ports.
type Browser struct {
	s      *Scenario
	c      *http.Client
	Jar    http.CookieJar
	follow bool
}

// Browser returns a fresh browser with its own cookie jar.
func (s *Scenario) Browser() *Browser {
	jar, _ := cookiejar.New(nil)
	return s.browserWith(jar, true)
}

func (s *Scenario) browserWith(jar http.CookieJar, follow bool) *Browser {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, s.resolve(addr))
		},
	}
	c := &http.Client{Jar: jar, Transport: tr, Timeout: 20 * time.Second}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Browser{s: s, c: c, Jar: jar, follow: follow}
}

// Still returns a browser sharing this one's cookies that does NOT follow
// redirects, for asserting where a request is sent.
func (b *Browser) Still() *Browser { return b.s.browserWith(b.Jar, false) }

// Resp is what a request came back with, after any redirects it followed.
type Resp struct {
	Status int
	Body   string
	URL    *url.URL
	Header http.Header
}

// Nav marks a request as a browser page load, which is what makes the gate
// redirect instead of answering 401.
var Nav = map[string]string{"Sec-Fetch-Mode": "navigate"}

// FetchAPI marks a request as a script's fetch(), which the gate answers with 401.
var FetchAPI = map[string]string{"Sec-Fetch-Mode": "same-origin"}

func (b *Browser) try(method, target string, form url.Values, hdr map[string]string) (*Resp, error) {
	if strings.HasPrefix(target, "/") {
		target = subjectURL + target
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return &Resp{Status: res.StatusCode, Body: string(raw), URL: res.Request.URL, Header: res.Header}, nil
}

// Get fetches a path on the subject (or an absolute URL) and fails the test on
// a transport error.
func (b *Browser) Get(target string, hdr map[string]string) *Resp {
	b.s.t.Helper()
	r, err := b.try("GET", target, nil, hdr)
	if err != nil {
		b.s.t.Fatalf("GET %s: %v", target, err)
	}
	return r
}

// Post submits a form.
func (b *Browser) Post(target string, form url.Values) *Resp {
	b.s.t.Helper()
	r, err := b.try("POST", target, form, nil)
	if err != nil {
		b.s.t.Fatalf("POST %s: %v", target, err)
	}
	return r
}

// Cookie returns a cookie the browser holds for the subject, if any.
func (b *Browser) Cookie(name string) *http.Cookie {
	u, _ := url.Parse(subjectURL)
	for _, c := range b.Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// --- fixtures ------------------------------------------------------------

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	})
}

// openPermissions makes a tree readable and writable by any user, so the
// container's process can use files the host created.
func openPermissions(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o777)
		} else {
			_ = os.Chmod(p, 0o666)
		}
		return nil
	})
}
