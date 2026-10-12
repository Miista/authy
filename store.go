package authy

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const storeFile = "auth.json"

// storeData is persisted as auth.json (0600) inside the 0700 data directory.
type storeData struct {
	SessionKey string `json:"session_key"` // base64; signs session cookies
	// Revoked are signed-out session IDs and when each may be forgotten (the
	// session's absolute end, as a Unix time). Persisted so a sign-out holds
	// across restarts; pruned on every revocation.
	Revoked map[string]int64 `json:"revoked,omitempty"`
}

// store holds the key that signs sessions and the sign-out records. Deleting
// auth.json and restarting rotates the key, which ends every session at once.
type store struct {
	path string

	mu   sync.RWMutex
	data storeData
	key  []byte
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
	return s, nil
}

func (s *store) sessionKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key
}

// revoke remembers that a session may no longer be used, until keepUntil (when
// the cookie could not be valid any more regardless). Expired entries are
// pruned here, so the list only ever holds live sign-outs.
func (s *store) revoke(sid string, keepUntil int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for id, e := range s.data.Revoked {
		if e <= now {
			delete(s.data.Revoked, id)
		}
	}
	if s.data.Revoked == nil {
		s.data.Revoked = map[string]int64{}
	}
	s.data.Revoked[sid] = keepUntil
	return s.saveLocked()
}

func (s *store) isRevoked(sid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	exp, ok := s.data.Revoked[sid]
	return ok && exp > time.Now().Unix()
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
