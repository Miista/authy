package local

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestMain lowers the bcrypt cost: at the production cost every hash takes
// noticeable time, especially under the race detector. Only this package can
// touch bcryptCost, which keeps it that way.
func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

func TestStoreCreateAndVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.hasAccount() {
		t.Fatal("a fresh store must have no account")
	}
	if s.verify("alice", "correct horse") {
		t.Fatal("verify must fail with no account")
	}
	if err := s.createAccount("alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if !s.hasAccount() {
		t.Fatal("account not recorded")
	}

	for name, tc := range map[string]struct {
		user, pass string
		want       bool
	}{
		"correct":                 {"alice", "correct horse", true},
		"trimmed username":        {"  alice  ", "correct horse", true},
		"wrong password":          {"alice", "correct hors3", false},
		"wrong username":          {"bob", "correct horse", false},
		"username case-sensitive": {"ALICE", "correct horse", false},
		"empty password":          {"alice", "", false},
	} {
		if got := s.verify(tc.user, tc.pass); got != tc.want {
			t.Errorf("%s: verify = %v, want %v", name, got, tc.want)
		}
	}

	if err := s.createAccount("mallory", "hunter2hunter2"); err != errAccountExists {
		t.Errorf("a second account must be refused, got %v", err)
	}
	if s.verify("mallory", "hunter2hunter2") || !s.verify("alice", "correct horse") {
		t.Error("the refused second account must not change anything")
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.createAccount("alice", "correct horse"); err != nil {
		t.Fatal(err)
	}

	s2, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.hasAccount() || !s2.verify("alice", "correct horse") {
		t.Error("the account must survive a reopen")
	}
	if err := s2.createAccount("mallory", "hunter2hunter2"); err != errAccountExists {
		t.Errorf("setup must stay closed after a reopen, got %v", err)
	}
}

func TestStoreFileIsPrivateAndHoldsNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.createAccount("alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "local.json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("local.json mode %v, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"username": "alice"`) || !strings.Contains(string(raw), "password_hash") {
		t.Errorf("unexpected contents: %s", raw)
	}
	if strings.Contains(string(raw), "correct horse") {
		t.Error("the password must never be stored in the clear")
	}
	if !strings.Contains(string(raw), "$2a$") && !strings.Contains(string(raw), "$2b$") {
		t.Errorf("the hash should be bcrypt: %s", raw)
	}
}

func TestStoreRefusesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(dir); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("a corrupt store must refuse to open, got %v", err)
	}
}

func TestValidateCredentials(t *testing.T) {
	long := strings.Repeat("x", 73)
	for name, tc := range map[string]struct {
		user, pass string
		want       string // "" means valid
	}{
		"valid":              {"alice", "correct horse", ""},
		"empty username":     {"", "correct horse", "Enter a username"},
		"long username":      {strings.Repeat("u", 65), "correct horse", "at most 64"},
		"control characters": {"al\nice", "correct horse", "not allowed"},
		"short password":     {"alice", "short", "at least 8"},
		"long password":      {"alice", long, "at most 72"},
	} {
		err := validateCredentials(tc.user, tc.pass)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func TestCreateAccountValidationLeavesNoAccount(t *testing.T) {
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.createAccount("", "correct horse"); err == nil {
		t.Fatal("expected a validation error")
	}
	if err := s.createAccount("alice", "short"); err == nil {
		t.Fatal("expected a validation error")
	}
	if s.hasAccount() {
		t.Error("a failed creation must not leave an account")
	}
}

// The limiter's clock is a parameter, so no test sleeps.
func TestLimiter(t *testing.T) {
	l := newLimiter()
	t0 := time.Now()

	if b, _ := l.blocked(t0); b {
		t.Fatal("a fresh limiter must not block")
	}
	for i := 0; i < l.max-1; i++ {
		l.fail(t0)
	}
	if b, _ := l.blocked(t0); b {
		t.Fatalf("%d failures must not block yet", l.max-1)
	}
	l.fail(t0)
	b, wait := l.blocked(t0)
	if !b || wait <= 0 || wait > l.window {
		t.Fatalf("after %d failures: blocked=%v wait=%v", l.max, b, wait)
	}
	// Still blocked just inside the window; free again once it has passed.
	if b, _ := l.blocked(t0.Add(l.window - time.Millisecond)); !b {
		t.Error("must stay blocked inside the window")
	}
	if b, _ := l.blocked(t0.Add(l.window)); b {
		t.Error("must unblock once the window has passed")
	}

	l.fail(t0.Add(l.window))
	l.reset()
	if b, _ := l.blocked(t0.Add(l.window)); b {
		t.Error("reset must clear the failures")
	}
}
