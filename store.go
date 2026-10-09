package oidcgate

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is a variable only so tests can lower it; nothing else changes it.
var bcryptCost = 12

const (
	storeFile    = "auth.json"
	minPassword  = 8
	maxPassword  = 72 // bcrypt silently ignores bytes past 72, so refuse them instead
	maxUsernameN = 64
)

var errAccountExists = errors.New("an account already exists")

// storeData is persisted as auth.json (0600) inside the 0700 data directory.
type storeData struct {
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	SessionKey   string `json:"session_key"` // base64; signs session cookies
}

// store holds the single local account and the key that signs sessions.
// Creating the account rotates the key, which ends every earlier session.
type store struct {
	path string

	mu   sync.RWMutex
	data storeData
	key  []byte

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
		if s.key, err = base64.StdEncoding.DecodeString(s.data.SessionKey); err != nil || len(s.key) < 32 {
			return nil, fmt.Errorf("%s has an invalid session key", s.path)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := s.rotateKeyLocked(); err != nil {
			return nil, err
		}
		// Persist now: it proves the directory is writable at startup rather
		// than at the first login, and keeps sessions valid across restarts.
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	if s.dummyHash, err = bcrypt.GenerateFromPassword([]byte("oidcgate-timing-equaliser"), bcryptCost); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *store) hasAccount() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Username != ""
}

func (s *store) sessionKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}

// createAccount stores the single account. It fails if one already exists, so
// two simultaneous setups cannot both win.
func (s *store) createAccount(username, password string) error {
	username = strings.TrimSpace(username)
	if err := validateCredentials(username, password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Username != "" {
		return errAccountExists
	}
	prev := s.data
	prevKey := s.key
	s.data.Username, s.data.PasswordHash = username, string(hash)
	if err := s.rotateKeyLocked(); err != nil {
		s.data, s.key = prev, prevKey
		return err
	}
	if err := s.saveLocked(); err != nil {
		s.data, s.key = prev, prevKey
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
	case utf8.RuneCountInString(username) > maxUsernameN:
		return fmt.Errorf("The username can be at most %d characters.", maxUsernameN)
	case strings.ContainsAny(username, "\x00\r\n\t"):
		return errors.New("The username contains characters that are not allowed.")
	case len(password) < minPassword:
		return fmt.Errorf("The password must be at least %d characters.", minPassword)
	case len(password) > maxPassword:
		return fmt.Errorf("The password can be at most %d bytes.", maxPassword)
	}
	return nil
}

func (s *store) rotateKeyLocked() error {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return fmt.Errorf("generating session key: %w", err)
	}
	s.key = k
	s.data.SessionKey = base64.StdEncoding.EncodeToString(k)
	return nil
}

// saveLocked writes auth.json atomically (temp file, fsync, rename) with 0600.
func (s *store) saveLocked() error {
	// The signing key is meant to be persisted: it keeps sessions valid across
	// restarts. The file is 0600 inside a 0700 directory (see below).
	raw, err := json.MarshalIndent(s.data, "", "  ") // #nosec G117 -- intentional, see above
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".auth-*.tmp")
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
