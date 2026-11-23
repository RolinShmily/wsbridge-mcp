package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"wsbridge/internal/ws"
)

// Protocol lifetimes and limits from docs/architecture/02-oauth-and-grant-model.md.
const (
	AccessTokenTTL     = time.Hour
	RefreshTokenTTL    = 30 * 24 * time.Hour
	AuthCodeTTL        = 60 * time.Second
	AuthCodeReplayTTL  = 5 * time.Minute
	AuthRequestTTL     = 10 * time.Minute
	RefreshGraceTTL    = 30 * time.Second
	LockoutThreshold   = 5
	LockoutDuration    = 5 * time.Minute
	MaxClients         = 200
	MaxRedirectURIs    = 10
	ZombieClientMaxAge = 24 * time.Hour
	GCInterval         = 10 * time.Minute
	SchemaVersion      = "1"
	AccessTokenPrefix  = "wsb_at_"
	RefreshTokenPrefix = "wsb_rt_"
	ClientIDPrefix     = "wsb_cli_"
	GrantIDPrefix      = "wsb_grt_"
	// WildcardWorkspace in GrantRecord.Workspaces authorizes whichever workspace(s)
	// are currently active on the local wsbridge server.
	WildcardWorkspace  = "*"
	authorizationScope = "mcp:tools"
	offlineAccessScope = "offline_access"
	codeHashRetention  = 5 * time.Minute
)

// Store errors. Handlers map these to OAuth error codes.
var (
	ErrNotFound       = errors.New("oauth: record not found")
	ErrClientLimit    = errors.New("oauth: client registration limit reached")
	ErrInvalidToken   = errors.New("oauth: invalid access token")
	ErrInvalidGrant   = errors.New("oauth: invalid grant")
	ErrRefreshReplay  = errors.New("oauth: refresh token replay detected")
	ErrResourceTarget = errors.New("oauth: resource does not match this server")
	ErrInvalidSecret  = errors.New("oauth: malformed secret hash")
)

var (
	bucketMeta    = []byte("meta")
	bucketClients = []byte("clients")
	bucketGrants  = []byte("grants")
	bucketTokens  = []byte("tokens")

	keySchemaVersion = []byte("schema_version")
	keyIssuer        = []byte("issuer")
	keyAdminPassHash = []byte("admin_pass_hash")
)

// ClientRecord is an RFC 7591 dynamically registered client.
type ClientRecord struct {
	ClientID                string    `json:"client_id"`
	ClientName              string    `json:"client_name"`
	RedirectURIs            []string  `json:"redirect_uris"`
	ApplicationType         string    `json:"application_type"`
	GrantTypes              []string  `json:"grant_types"`
	ResponseTypes           []string  `json:"response_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method"`
	CreatedAt               time.Time `json:"created_at"`
	Activated               bool      `json:"activated"`
}

// GrantRecord is one user-approved authorization instance.
type GrantRecord struct {
	GrantID    string                   `json:"grant_id"`
	ClientID   string                   `json:"client_id"`
	ClientName string                   `json:"client_name"`
	Scopes     []string                 `json:"scopes"`
	Workspaces map[string]ws.Permission `json:"workspaces"`
	CreatedAt  time.Time                `json:"created_at"`
	ExpiresAt  time.Time                `json:"expires_at"`
	Revoked    bool                     `json:"revoked"`
}

// Status returns the CLI-facing grant status.
func (g *GrantRecord) Status(now time.Time) string {
	switch {
	case g.Revoked:
		return "revoked"
	case !g.ExpiresAt.After(now):
		return "expired"
	default:
		return "active"
	}
}

// TokenRecord is stored by SHA-256 hash; raw token values never reach bbolt.
type TokenRecord struct {
	Type                  string    `json:"token_type"`
	GrantID               string    `json:"grant_id"`
	ClientID              string    `json:"client_id"`
	Resource              string    `json:"resource"`
	PairID                string    `json:"pair_id"`
	ExpiresAt             time.Time `json:"expires_at"`
	RotatedAt             time.Time `json:"rotated_at,omitempty"`
	ReplacedByAccessHash  string    `json:"replaced_by_access_hash,omitempty"`
	ReplacedByRefreshHash string    `json:"replaced_by_refresh_hash,omitempty"`
	Revoked               bool      `json:"revoked"`
}

// TokenPair is a freshly issued access/refresh pair.
type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int
	RefreshExpiresIn int
	GrantID          string
	ClientID         string
	PairID           string

	accessHash  string
	refreshHash string
	resource    string

	accessExpiresAt  time.Time
	refreshExpiresAt time.Time
}

// GrantPrincipal is what the MCP layer learns about an authenticated token.
type GrantPrincipal struct {
	GrantID    string
	ClientID   string
	ClientName string
	Workspaces map[string]ws.Permission
	Scopes     []string
	ExpiresAt  time.Time
}

// TokenVerifier verifies bearer tokens for the MCP transport.
type TokenVerifier interface {
	VerifyAccessToken(rawToken string, expectedResource string) (*GrantPrincipal, error)
}

// StoreOptions configures a Store.
type StoreOptions struct {
	Issuer string
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Store persists clients, grants, and token hashes in bbolt.
type Store struct {
	db     *bolt.DB
	now    func() time.Time
	issuer string

	issuerChanged bool

	graceMu sync.Mutex
	grace   map[string]graceEntry
}

type graceEntry struct {
	pair  *TokenPair
	until time.Time
}

// OpenStore opens (or creates) the bbolt database at path.
func OpenStore(path string, opts StoreOptions) (*Store, error) {
	issuer := strings.TrimRight(strings.TrimSpace(opts.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("oauth: issuer is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("oauth: create data directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("oauth: open database %q: %w", path, err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := &Store{db: db, now: now, issuer: issuer, grace: make(map[string]graceEntry)}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketMeta, bucketClients, bucketGrants, bucketTokens} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bucketMeta)
		schema := meta.Get(keySchemaVersion)
		if schema == nil {
			if err := meta.Put(keySchemaVersion, []byte(SchemaVersion)); err != nil {
				return err
			}
		} else if string(schema) != SchemaVersion {
			return fmt.Errorf("oauth: unsupported database schema version %q", schema)
		}
		oldIssuer := meta.Get(keyIssuer)
		if oldIssuer == nil {
			return meta.Put(keyIssuer, []byte(s.issuer))
		}
		if string(oldIssuer) == s.issuer {
			return nil
		}
		// The public URL changed. Tokens and grants are bound to the issuer,
		// so every prior authorization becomes invalid.
		if err := revokeAllInTx(tx, now()); err != nil {
			return err
		}
		s.issuerChanged = true
		return meta.Put(keyIssuer, []byte(s.issuer))
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("oauth: initialize database: %w", err)
	}
	return s, nil
}

// IssuerChanged reports whether OpenStore invalidated prior grants because the
// configured issuer differs from the stored one.
func (s *Store) IssuerChanged() bool { return s.issuerChanged }

// Issuer returns the configured issuer without a trailing slash.
func (s *Store) Issuer() string { return s.issuer }

// Close closes the database.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.graceMu.Lock()
	s.grace = nil
	s.graceMu.Unlock()
	return err
}

// SetAdminHash stores the argon2id administrator passphrase hash.
func (s *Store) SetAdminHash(encoded string) error {
	if strings.TrimSpace(encoded) == "" {
		return fmt.Errorf("oauth: empty administrator passphrase hash")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyAdminPassHash, []byte(encoded))
	})
}

// AdminHash returns the stored administrator passphrase hash (may be empty).
func (s *Store) AdminHash() (string, error) {
	var out string
	err := s.db.View(func(tx *bolt.Tx) error {
		out = string(tx.Bucket(bucketMeta).Get(keyAdminPassHash))
		return nil
	})
	return out, err
}

// MetaInfo is a read-only snapshot of database metadata for diagnostics.
type MetaInfo struct {
	Issuer             string
	AdminPassphraseSet bool
	SchemaVersion      string
}

// PeekMeta reads database metadata without modifying it. It returns
// bolt.ErrTimeout if a running server holds the database write lock.
func PeekMeta(path string) (*MetaInfo, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 500 * time.Millisecond})
	if err != nil {
		return nil, fmt.Errorf("oauth: open database for inspection: %w", err)
	}
	defer db.Close()
	info := &MetaInfo{}
	err = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta == nil {
			return fmt.Errorf("oauth: database is missing the meta bucket")
		}
		info.SchemaVersion = string(meta.Get(keySchemaVersion))
		info.Issuer = string(meta.Get(keyIssuer))
		info.AdminPassphraseSet = len(meta.Get(keyAdminPassHash)) > 0
		return nil
	})
	if err != nil {
		return nil, err
	}
	if info.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("oauth: unsupported database schema version %q", info.SchemaVersion)
	}
	return info, nil
}

// RegisterClient stores a new client, enforcing the 200-client limit after
// removing unactivated clients older than 24 hours.
func (s *Store) RegisterClient(c *ClientRecord) error {
	if c == nil || c.ClientID == "" {
		return fmt.Errorf("oauth: client id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		now := s.now()
		if err := deleteZombieClients(b, now); err != nil {
			return err
		}
		if b.Stats().KeyN >= MaxClients {
			return ErrClientLimit
		}
		return putJSON(b, c.ClientID, c)
	})
}

// GetClient returns a registered client.
func (s *Store) GetClient(id string) (*ClientRecord, error) {
	var out ClientRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketClients), id, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// CountClients returns the number of registered clients.
func (s *Store) CountClients() (int, error) {
	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bucketClients).Stats().KeyN
		return nil
	})
	return n, err
}

// ActivateClient marks a client as having completed at least one authorization.
func (s *Store) ActivateClient(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		var c ClientRecord
		if err := getJSON(b, id, &c); err != nil {
			return err
		}
		if c.Activated {
			return nil
		}
		c.Activated = true
		return putJSON(b, id, &c)
	})
}

// CreateGrant stores a new grant.
func (s *Store) CreateGrant(g *GrantRecord) error {
	if g == nil || g.GrantID == "" {
		return fmt.Errorf("oauth: grant id is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketGrants), g.GrantID, g)
	})
}

// GetGrant returns a grant.
func (s *Store) GetGrant(id string) (*GrantRecord, error) {
	var out GrantRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketGrants), id, &out)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListGrants returns all grants, newest first.
func (s *Store) ListGrants() ([]*GrantRecord, error) {
	var out []*GrantRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketGrants).ForEach(func(_, v []byte) error {
			var g GrantRecord
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, &g)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].GrantID < out[j].GrantID
	})
	return out, nil
}

// RevokeGrant revokes one grant and all of its tokens. It reports whether the
// grant existed.
func (s *Store) RevokeGrant(id string) (bool, error) {
	found := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketGrants).Get([]byte(id)) == nil {
			return nil
		}
		found = true
		return revokeGrantTx(tx, id)
	})
	if err == nil && found {
		s.purgeGraceForGrant(id)
	}
	return found, err
}

// RevokeAll revokes every grant and token, returning the number of grants.
func (s *Store) RevokeAll() (int, error) {
	count := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		var ids []string
		if err := tx.Bucket(bucketGrants).ForEach(func(k, _ []byte) error {
			ids = append(ids, string(k))
			return nil
		}); err != nil {
			return err
		}
		for _, id := range ids {
			if err := revokeGrantTx(tx, id); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err == nil {
		s.graceMu.Lock()
		s.grace = make(map[string]graceEntry)
		s.graceMu.Unlock()
	}
	return count, err
}

// Prune permanently deletes revoked or expired grants and their tokens. It
// returns the removed grant IDs and the number of removed token records.
func (s *Store) Prune() ([]string, int, error) {
	var grants []string
	tokens := 0
	now := s.now()
	err := s.db.Update(func(tx *bolt.Tx) error {
		gb := tx.Bucket(bucketGrants)
		var toDelete []string
		if err := gb.ForEach(func(k, v []byte) error {
			var g GrantRecord
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			if g.Revoked || !g.ExpiresAt.After(now) {
				toDelete = append(toDelete, string(k))
			}
			return nil
		}); err != nil {
			return err
		}
		remove := make(map[string]bool, len(toDelete))
		for _, id := range toDelete {
			remove[id] = true
			if err := gb.Delete([]byte(id)); err != nil {
				return err
			}
			grants = append(grants, id)
		}
		tb := tx.Bucket(bucketTokens)
		var tokenKeys [][]byte
		if err := tb.ForEach(func(k, v []byte) error {
			var tr TokenRecord
			if err := json.Unmarshal(v, &tr); err != nil {
				return err
			}
			if remove[tr.GrantID] || (!tr.ExpiresAt.After(now) && (tr.RotatedAt.IsZero() || now.Sub(tr.RotatedAt) > RefreshGraceTTL)) {
				key := append([]byte(nil), k...)
				tokenKeys = append(tokenKeys, key)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range tokenKeys {
			if err := tb.Delete(k); err != nil {
				return err
			}
			tokens++
		}
		return nil
	})
	if err == nil {
		for _, id := range grants {
			s.purgeGraceForGrant(id)
		}
	}
	return grants, tokens, err
}

// IssueTokens creates a new access/refresh pair for an active grant.
func (s *Store) IssueTokens(grantID, clientID, resource string) (*TokenPair, error) {
	var pair *TokenPair
	err := s.db.Update(func(tx *bolt.Tx) error {
		g, err := getGrantTx(tx, grantID)
		if err != nil {
			return err
		}
		if g.Revoked || !g.ExpiresAt.After(s.now()) {
			return ErrInvalidGrant
		}
		p, err := newTokenPair(s.now(), grantID, clientID, resource)
		if err != nil {
			return err
		}
		if err := storeTokenPair(tx, p); err != nil {
			return err
		}
		pair = p
		return nil
	})
	return pair, err
}

// VerifyAccessToken checks a raw bearer token, its grant, and its resource
// binding. Every failure is reported as ErrInvalidToken to avoid an oracle.
func (s *Store) VerifyAccessToken(rawToken, expectedResource string) (*GrantPrincipal, error) {
	if rawToken == "" {
		return nil, ErrInvalidToken
	}
	hash := hashToken(rawToken)
	var principal *GrantPrincipal
	err := s.db.View(func(tx *bolt.Tx) error {
		tr, err := getTokenTx(tx, hash)
		if err != nil {
			return ErrInvalidToken
		}
		now := s.now()
		if tr.Type != "access" || tr.Revoked || !tr.ExpiresAt.After(now) {
			return ErrInvalidToken
		}
		if expectedResource != "" && tr.Resource != expectedResource {
			return ErrInvalidToken
		}
		g, err := getGrantTx(tx, tr.GrantID)
		if err != nil {
			return ErrInvalidToken
		}
		if g.Revoked || !g.ExpiresAt.After(now) {
			return ErrInvalidToken
		}
		principal = &GrantPrincipal{
			GrantID:    g.GrantID,
			ClientID:   g.ClientID,
			ClientName: g.ClientName,
			Workspaces: cloneWorkspaces(g.Workspaces),
			Scopes:     append([]string(nil), g.Scopes...),
			ExpiresAt:  tr.ExpiresAt,
		}
		return nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}
	return principal, nil
}

// RotateRefresh rotates a refresh token, or returns the same pair inside the
// 30-second grace window. A replay outside the window revokes the grant.
func (s *Store) RotateRefresh(rawToken, clientID, expectedResource string) (*TokenPair, error) {
	if rawToken == "" {
		return nil, ErrInvalidGrant
	}
	key := hashToken(rawToken)
	now := s.now()
	var pair *TokenPair
	var replay error
	rotated := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		tr, err := getTokenTx(tx, key)
		if err != nil {
			return ErrInvalidGrant
		}
		if tr.Type != "refresh" || tr.Revoked {
			return ErrInvalidGrant
		}
		if clientID != "" && tr.ClientID != clientID {
			return ErrInvalidGrant
		}
		if expectedResource != "" && tr.Resource != expectedResource {
			return ErrResourceTarget
		}
		g, err := getGrantTx(tx, tr.GrantID)
		if err != nil || g.Revoked || !g.ExpiresAt.After(now) {
			return ErrInvalidGrant
		}

		if tr.RotatedAt.IsZero() {
			p, err := newTokenPair(now, tr.GrantID, tr.ClientID, tr.Resource)
			if err != nil {
				return err
			}
			if err := storeTokenPair(tx, p); err != nil {
				return err
			}
			// The access token from the old pair is invalid immediately.
			if err := revokeAccessPairTx(tx, tr.GrantID, tr.PairID); err != nil {
				return err
			}
			tr.RotatedAt = now
			tr.ReplacedByAccessHash = p.accessHash
			tr.ReplacedByRefreshHash = p.refreshHash
			if err := putJSON(tx.Bucket(bucketTokens), key, tr); err != nil {
				return err
			}
			pair = p
			rotated = true
			return nil
		}

		if now.Sub(tr.RotatedAt) <= RefreshGraceTTL {
			s.graceMu.Lock()
			cached, ok := s.grace[key]
			s.graceMu.Unlock()
			if !ok || !now.Before(cached.until) {
				return ErrInvalidGrant
			}
			pair = cached.pair
			return nil
		}

		// Outside the grace window: treat the old refresh token as stolen.
		if err := revokeGrantTx(tx, tr.GrantID); err != nil {
			return err
		}
		replay = &ReplayError{GrantID: tr.GrantID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replay != nil {
		s.purgeGraceForGrant(replay.(*ReplayError).GrantID)
		return nil, replay
	}
	if pair != nil && rotated {
		s.graceMu.Lock()
		for k, v := range s.grace {
			if !now.Before(v.until) {
				delete(s.grace, k)
			}
		}
		s.grace[key] = graceEntry{pair: pair, until: now.Add(RefreshGraceTTL)}
		s.graceMu.Unlock()
	}
	return pair, nil
}

// ReplayError reports a refresh-token replay and the revoked grant.
type ReplayError struct {
	GrantID string
}

func (e *ReplayError) Error() string { return "oauth: refresh token replay detected" }
func (e *ReplayError) Is(target error) bool {
	return target == ErrRefreshReplay
}

// RevokeTokenByValue revokes the grant owning rawToken, if it exists. Unknown
// or expired tokens are a successful no-op per RFC 7009.
func (s *Store) RevokeTokenByValue(rawToken string) (grantID string, found bool, err error) {
	if rawToken == "" {
		return "", false, nil
	}
	key := hashToken(rawToken)
	err = s.db.Update(func(tx *bolt.Tx) error {
		tr, err := getTokenTx(tx, key)
		if err != nil {
			return nil
		}
		grantID = tr.GrantID
		found = true
		return revokeGrantTx(tx, grantID)
	})
	if err == nil && found {
		s.purgeGraceForGrant(grantID)
	}
	return grantID, found, err
}

// GC removes stale unactivated clients and expired token records. Expired
// grants remain for audit until "grants prune".
func (s *Store) GC() (clients int, tokens int, err error) {
	now := s.now()
	err = s.db.Update(func(tx *bolt.Tx) error {
		cb := tx.Bucket(bucketClients)
		var clientKeys [][]byte
		if err := cb.ForEach(func(k, v []byte) error {
			var c ClientRecord
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			if !c.Activated && now.Sub(c.CreatedAt) > ZombieClientMaxAge {
				clientKeys = append(clientKeys, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range clientKeys {
			if err := cb.Delete(k); err != nil {
				return err
			}
			clients++
		}
		tb := tx.Bucket(bucketTokens)
		var tokenKeys [][]byte
		if err := tb.ForEach(func(k, v []byte) error {
			var tr TokenRecord
			if err := json.Unmarshal(v, &tr); err != nil {
				return err
			}
			if tr.ExpiresAt.After(now) {
				return nil
			}
			if !tr.RotatedAt.IsZero() && now.Sub(tr.RotatedAt) <= RefreshGraceTTL {
				return nil
			}
			tokenKeys = append(tokenKeys, append([]byte(nil), k...))
			return nil
		}); err != nil {
			return err
		}
		for _, k := range tokenKeys {
			if err := tb.Delete(k); err != nil {
				return err
			}
			tokens++
		}
		return nil
	})
	if err == nil {
		s.graceMu.Lock()
		for k, v := range s.grace {
			if !now.Before(v.until) {
				delete(s.grace, k)
			}
		}
		s.graceMu.Unlock()
	}
	return clients, tokens, err
}

// StartGC runs GC every interval until stop is called.
func (s *Store) StartGC(interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = GCInterval
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _, _ = s.GC()
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

func (s *Store) purgeGraceForGrant(grantID string) {
	s.graceMu.Lock()
	defer s.graceMu.Unlock()
	for k, v := range s.grace {
		if v.pair != nil && v.pair.GrantID == grantID {
			delete(s.grace, k)
		}
	}
}

func revokeAllInTx(tx *bolt.Tx, _ time.Time) error {
	gb := tx.Bucket(bucketGrants)
	if err := gb.ForEach(func(k, v []byte) error {
		var g GrantRecord
		if err := json.Unmarshal(v, &g); err != nil {
			return err
		}
		if g.Revoked {
			return nil
		}
		g.Revoked = true
		return putJSON(gb, g.GrantID, &g)
	}); err != nil {
		return err
	}
	tb := tx.Bucket(bucketTokens)
	return tb.ForEach(func(k, v []byte) error {
		var tr TokenRecord
		if err := json.Unmarshal(v, &tr); err != nil {
			return err
		}
		if tr.Revoked {
			return nil
		}
		tr.Revoked = true
		return putJSON(tb, string(k), &tr)
	})
}

func revokeGrantTx(tx *bolt.Tx, grantID string) error {
	gb := tx.Bucket(bucketGrants)
	var g GrantRecord
	if err := getJSON(gb, grantID, &g); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if !g.Revoked {
		g.Revoked = true
		if err := putJSON(gb, grantID, &g); err != nil {
			return err
		}
	}
	tb := tx.Bucket(bucketTokens)
	return tb.ForEach(func(k, v []byte) error {
		var tr TokenRecord
		if err := json.Unmarshal(v, &tr); err != nil {
			return err
		}
		if tr.GrantID != grantID || tr.Revoked {
			return nil
		}
		tr.Revoked = true
		return putJSON(tb, string(k), &tr)
	})
}

func revokeAccessPairTx(tx *bolt.Tx, grantID, pairID string) error {
	tb := tx.Bucket(bucketTokens)
	return tb.ForEach(func(k, v []byte) error {
		var tr TokenRecord
		if err := json.Unmarshal(v, &tr); err != nil {
			return err
		}
		if tr.GrantID != grantID || tr.PairID != pairID || tr.Type != "access" || tr.Revoked {
			return nil
		}
		tr.Revoked = true
		return putJSON(tb, string(k), &tr)
	})
}

func deleteZombieClients(b *bolt.Bucket, now time.Time) error {
	var keys [][]byte
	if err := b.ForEach(func(k, v []byte) error {
		var c ClientRecord
		if err := json.Unmarshal(v, &c); err != nil {
			return err
		}
		if !c.Activated && now.Sub(c.CreatedAt) > ZombieClientMaxAge {
			keys = append(keys, append([]byte(nil), k...))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func newTokenPair(now time.Time, grantID, clientID, resource string) (*TokenPair, error) {
	access, err := randomToken(AccessTokenPrefix, 32)
	if err != nil {
		return nil, err
	}
	refresh, err := randomToken(RefreshTokenPrefix, 32)
	if err != nil {
		return nil, err
	}
	pairID, err := randomID(12)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		RefreshToken:     refresh,
		ExpiresIn:        int(AccessTokenTTL / time.Second),
		RefreshExpiresIn: int(RefreshTokenTTL / time.Second),
		GrantID:          grantID,
		ClientID:         clientID,
		PairID:           pairID,
		accessHash:       hashToken(access),
		refreshHash:      hashToken(refresh),
		resource:         resource,
		accessExpiresAt:  now.Add(AccessTokenTTL),
		refreshExpiresAt: now.Add(RefreshTokenTTL),
	}, nil
}

func storeTokenPair(tx *bolt.Tx, p *TokenPair) error {
	b := tx.Bucket(bucketTokens)
	access := &TokenRecord{
		Type:      "access",
		GrantID:   p.GrantID,
		ClientID:  p.ClientID,
		Resource:  p.resource,
		PairID:    p.PairID,
		ExpiresAt: p.accessExpiresAt,
	}
	refresh := &TokenRecord{
		Type:      "refresh",
		GrantID:   p.GrantID,
		ClientID:  p.ClientID,
		Resource:  p.resource,
		PairID:    p.PairID,
		ExpiresAt: p.refreshExpiresAt,
	}
	if err := putJSON(b, p.accessHash, access); err != nil {
		return err
	}
	return putJSON(b, p.refreshHash, refresh)
}

func getGrantTx(tx *bolt.Tx, grantID string) (*GrantRecord, error) {
	var g GrantRecord
	if err := getJSON(tx.Bucket(bucketGrants), grantID, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func getTokenTx(tx *bolt.Tx, hash string) (*TokenRecord, error) {
	var tr TokenRecord
	if err := getJSON(tx.Bucket(bucketTokens), hash, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

func getJSON(b *bolt.Bucket, key string, out any) error {
	raw := b.Get([]byte(key))
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, out)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomToken(prefix string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: generate random token: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: generate random id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func cloneWorkspaces(in map[string]ws.Permission) map[string]ws.Permission {
	out := make(map[string]ws.Permission, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ScopeStrings returns the default scopes when the client did not request any.
func ScopeStrings(requested []string) []string {
	out := make([]string, 0, len(requested)+1)
	seen := make(map[string]bool, len(requested)+1)
	for _, s := range requested {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if !seen[authorizationScope] {
		out = append(out, authorizationScope)
	}
	if !seen[offlineAccessScope] {
		out = append(out, offlineAccessScope)
	}
	return out
}
