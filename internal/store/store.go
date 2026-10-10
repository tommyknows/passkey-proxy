// Package store persists accounts and passkeys in a JSON file.
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
)

// User is an account with its passkeys.
type User struct {
	Name     string   `json:"name"`
	Passkeys []string `json:"passkeys"`
}

// Store holds accounts indexed by user ID. Its methods are safe for concurrent use.
type Store struct {
	path string

	mu    sync.Mutex
	users map[string]User
}

// Load reads path. A missing or empty file yields an empty store.
func Load(path string) (*Store, error) {
	s := &Store{path: path, users: map[string]User{}}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}

	if len(bytes.TrimSpace(b)) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.users); err != nil {
		return nil, err
	}
	return s, nil
}

// Lookup returns the account for userID.
// It has no passkeys until enrollment completes.
func (s *Store) Lookup(userID string) (user User, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	return u, ok
}

// User returns an account's ID, creating the account if needed.
// Note that new accounts cannot log in until [AddPasskey] succeeds.
func (s *Store) User(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, u := range s.users {
		if u.Name == name {
			return id
		}
	}
	// Authenticators retain this ID; use a stable value without personal information.
	userID := rand.Text()
	s.users[userID] = User{Name: name}
	return userID
}

// AddPasskey adds a passkey to the account and saves the store.
// If replace is set, it first removes the account's other passkeys.
// It returns the account's new passkey count.
func (s *Store) AddPasskey(userID, record string, replace bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	if !ok {
		return errors.New("store: unknown user ID")
	}
	if replace {
		u.Passkeys = nil
	}
	u.Passkeys = append(u.Passkeys, record)
	s.users[userID] = u

	// Rename a complete file to avoid partial writes.
	b, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
