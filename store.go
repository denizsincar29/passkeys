package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

// --- UserStore Implementation ---

type UserStore struct {
	db *gorm.DB
}

func (s *UserStore) Create(username string) (passkey.User, error) {
	u := &User{Name: username}
	if err := s.db.Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserStore) Update(u passkey.User) error {
	return s.db.Save(u.(*User)).Error
}

func (s *UserStore) Get(userID []byte) (passkey.User, error) {
	var u User
	if err := s.db.First(&u, "id = ?", userID).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *UserStore) GetByName(username string) (passkey.User, error) {
	var u User
	if err := s.db.First(&u, "name = ?", username).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// --- SessionStore Implementation ---

type MemorySessionStore[T webauthn.SessionData | passkey.UserSessionData] struct {
	mu   sync.RWMutex
	data map[string]T
}

func (s *MemorySessionStore[T]) Create(data T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	s.data[token] = data
	return token, nil
}

func (s *MemorySessionStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, token)
}

func (s *MemorySessionStore[T]) Get(token string) (*T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.data[token]
	if !ok {
		return nil, false
	}
	return &val, true
}
