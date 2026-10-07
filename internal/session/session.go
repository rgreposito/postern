package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("session: not found")

type State string

const (
	StateActive  State = "active"
	StateExpired State = "expired"
	StateRevoked State = "revoked"
)

type Session struct {
	ID        string
	GrantID   string
	Principal string
	Kind      string
	Action    string
	Resource  string
	State     State
	Record    bool
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
}

// Store is an in-memory map. Swap for postgres when this leaves the
// laptop; the interface is the whole point.
type Store struct {
	mu   sync.RWMutex
	byID map[string]*Session
	now  func() time.Time
}

func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{byID: make(map[string]*Session), now: now}
}

func (s *Store) Issue(sess Session) (Session, error) {
	id, err := newID()
	if err != nil {
		return Session{}, err
	}
	now := s.now()
	sess.ID = id
	sess.State = StateActive
	sess.IssuedAt = now
	if sess.ExpiresAt.IsZero() {
		return Session{}, errors.New("session: missing expiry")
	}
	s.mu.Lock()
	s.byID[id] = &sess
	s.mu.Unlock()
	return sess, nil
}

func (s *Store) Get(id string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	s.expireLocked(sess)
	return *sess, nil
}

func (s *Store) Revoke(id string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if sess.State == StateActive {
		sess.State = StateRevoked
		sess.RevokedAt = s.now()
	}
	return *sess, nil
}

func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sess := range s.byID {
		if s.expireLocked(sess) {
			n++
		}
	}
	return n
}

func (s *Store) ListActive() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.byID))
	for _, sess := range s.byID {
		s.expireLocked(sess)
		if sess.State == StateActive {
			out = append(out, *sess)
		}
	}
	return out
}

func (s *Store) expireLocked(sess *Session) bool {
	if sess.State == StateActive && !s.now().Before(sess.ExpiresAt) {
		sess.State = StateExpired
		return true
	}
	return false
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Jitter shortens ttl by up to 10%. Without this, a fleet that
// connected in the same second reconnects in the same second.
// I watched that take a control plane down in 2019. Once is enough.
func Jitter(ttl time.Duration, now time.Time) time.Duration {
	if ttl < 2*time.Second {
		return ttl
	}
	// cheap, deterministic-enough jitter from the clock. not for
	// crypto. we just don't want a thundering herd.
	n := now.UnixNano()
	cut := time.Duration(n%int64(ttl/10)) + ttl/20
	return ttl - cut
}
