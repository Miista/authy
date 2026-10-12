package local

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/miista/authy/internal/testhook"
)

const (
	storeFile    = "local.json"
	minPassword  = 8
	maxPassword  = 72 // bcrypt silently ignores bytes past 72, so refuse them instead
	maxUsernameN = 64
	// maxUsernameB keeps "local:"+username within the shell's 255-byte subject
	// cap, so an account that can be created can always sign in.
	maxUsernameB = 249
)

var errAccountExists = errors.New("an account already exists")

// storeData is persisted as local.json (0600) inside the gate's 0700 data
// directory, next to the shell's auth.json.
type storeData struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// store holds the single local account.
type store struct {
	path string

	mu   sync.RWMutex
	data storeData

	dummyHash []byte // compared against when the username is wrong, to equalise timing
}

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &store{path: filepath.Join(dir, storeFile)}

	raw, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("%s is not valid JSON: %w", s.path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// No account yet; setup creates it.
	default:
		return nil, err
	}

	if s.dummyHash, err = bcrypt.GenerateFromPassword([]byte("authy-timing-equaliser"), testhook.BcryptCost); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *store) hasAccount() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Username != ""
}

// createAccount stores the single account. It fails if one already exists, so
// two simultaneous setups cannot both win.
func (s *store) createAccount(username, password string) error {
	username = strings.TrimSpace(username)
	if err := validateCredentials(username, password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), testhook.BcryptCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Username != "" {
		return errAccountExists
	}
	prev := s.data
	s.data.Username, s.data.PasswordHash = username, string(hash)
	if err := s.saveLocked(); err != nil {
		s.data = prev
		return err
	}
	return nil
}

// verify checks a username and password. It does the same bcrypt work whether
// or not the username matches, so timing does not reveal the username.
func (s *store) verify(username, password string) bool {
	s.mu.RLock()
	stored, hash := s.data.Username, []byte(s.data.PasswordHash)
	s.mu.RUnlock()
	if stored == "" {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(username)), []byte(stored)) == 1
	if !userOK {
		hash = s.dummyHash
	}
	passOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return userOK && passOK
}

func validateCredentials(username, password string) error {
	switch {
	case username == "":
		return errors.New("Enter a username.")
	case utf8.RuneCountInString(username) > maxUsernameN || len(username) > maxUsernameB:
		return fmt.Errorf("The username can be at most %d characters.", maxUsernameN)
	case !utf8.ValidString(username) || strings.ContainsFunc(username, unicode.IsControl):
		// The shell strips control characters from the subject it seals, so a
		// username containing any would diverge from its own session identity.
		return errors.New("The username contains characters that are not allowed.")
	case len(password) < minPassword:
		return fmt.Errorf("The password must be at least %d characters.", minPassword)
	case len(password) > maxPassword:
		return fmt.Errorf("The password can be at most %d bytes.", maxPassword)
	}
	return nil
}

// saveLocked writes local.json atomically (temp file, fsync, rename) with 0600.
func (s *store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".local-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
