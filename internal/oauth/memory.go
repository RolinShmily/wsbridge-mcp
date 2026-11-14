package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// authCode is a single-use, 60-second authorization code kept only in memory.
type authCode struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	GrantID       string
	ExpiresAt     time.Time
}

type usedCode struct {
	record authCode
	usedAt time.Time
}

type codeStore struct {
	mu     sync.Mutex
	active map[string]authCode
	used   map[string]usedCode
	now    func() time.Time
}

func newCodeStore(now func() time.Time) *codeStore {
	return &codeStore{active: make(map[string]authCode), used: make(map[string]usedCode), now: now}
}

// Issue creates a 32-byte random authorization code bound to rec.
func (s *codeStore) Issue(rec authCode) (string, error) {
	raw, err := randomToken("", 32)
	if err != nil {
		return "", err
	}
	rec.ExpiresAt = s.now().Add(AuthCodeTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	s.active[hashToken(raw)] = rec
	return raw, nil
}

// Take atomically removes an active code and records it for replay
// detection. Expired codes are removed and treated as missing.
func (s *codeStore) Take(raw string) (authCode, bool) {
	key := hashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.active[key]
	if !ok {
		return authCode{}, false
	}
	delete(s.active, key)
	now := s.now()
	if !rec.ExpiresAt.After(now) {
		return authCode{}, false
	}
	s.used[key] = usedCode{record: rec, usedAt: now}
	return rec, true
}

// Used returns the recorded grant for a code exchanged within the replay
// window.
func (s *codeStore) Used(raw string) (authCode, bool) {
	key := hashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.used[key]
	if !ok || s.now().Sub(u.usedAt) > AuthCodeReplayTTL {
		if ok {
			delete(s.used, key)
		}
		return authCode{}, false
	}
	return u.record, true
}

func (s *codeStore) purgeLocked() {
	now := s.now()
	for k, rec := range s.active {
		if !rec.ExpiresAt.After(now) {
			delete(s.active, k)
		}
	}
	for k, u := range s.used {
		if now.Sub(u.usedAt) > AuthCodeReplayTTL {
			delete(s.used, k)
		}
	}
}

// authRequest is one rendered consent form context. It is not a cookie: the
// random ID and CSRF token bind the POST to the GET that produced it.
type authRequest struct {
	ClientID      string
	ClientName    string
	RedirectURI   string
	CodeChallenge string
	State         string
	Resource      string
	Scope         string
	CSRF          string
	ExpiresAt     time.Time
}

type authRequestStore struct {
	mu  sync.Mutex
	m   map[string]authRequest
	now func() time.Time
}

func newAuthRequestStore(now func() time.Time) *authRequestStore {
	return &authRequestStore{m: make(map[string]authRequest), now: now}
}

func (s *authRequestStore) Create(ar authRequest) (id string, err error) {
	idRaw := make([]byte, 18)
	csrfRaw := make([]byte, 32)
	if _, err := rand.Read(idRaw); err != nil {
		return "", err
	}
	if _, err := rand.Read(csrfRaw); err != nil {
		return "", err
	}
	id = base64.RawURLEncoding.EncodeToString(idRaw)
	ar.CSRF = base64.RawURLEncoding.EncodeToString(csrfRaw)
	ar.ExpiresAt = s.now().Add(AuthRequestTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if !v.ExpiresAt.After(s.now()) {
			delete(s.m, k)
		}
	}
	s.m[id] = ar
	return id, nil
}

func (s *authRequestStore) Get(id string) (authRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ar, ok := s.m[id]
	if !ok {
		return authRequest{}, false
	}
	if !ar.ExpiresAt.After(s.now()) {
		delete(s.m, id)
		return authRequest{}, false
	}
	return ar, true
}

func (s *authRequestStore) Consume(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// lockout is a global consecutive-failure lock shared by all authorization
// submissions, as required by the deployment threat model.
type lockout struct {
	mu       sync.Mutex
	failures int
	until    time.Time
	now      func() time.Time
}

func newLockout(now func() time.Time) *lockout {
	return &lockout{now: now}
}

// Locked reports whether submissions are currently blocked and, if so, the
// remaining whole seconds.
func (l *lockout) Locked() (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.until.IsZero() || !now.Before(l.until) {
		l.until = time.Time{}
		return 0, false
	}
	remaining := int((l.until.Sub(now) + time.Second - 1) / time.Second)
	if remaining < 1 {
		remaining = 1
	}
	return remaining, true
}

func (l *lockout) Failure() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.until.IsZero() && now.Before(l.until) {
		return
	}
	l.failures++
	if l.failures >= LockoutThreshold {
		l.until = now.Add(LockoutDuration)
		l.failures = 0
	}
}

func (l *lockout) Success() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = 0
	l.until = time.Time{}
}

// splitScopes turns a space-separated scope parameter into a slice.
func splitScopes(scope string) []string {
	return strings.Fields(scope)
}
