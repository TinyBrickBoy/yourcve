// Package auth handles accounts: open registration with email confirmation,
// magic link and passkey login, sessions, API keys, ALTCHA captcha and
// per-IP rate limits.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/altcha-org/altcha-lib-go"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

const (
	SessionCookie = "yc_session"
	sessionTTL    = 30 * 24 * time.Hour
	magicLinkTTL  = 30 * time.Minute
	apiKeyPrefix  = "yc_"
)

type User struct {
	ID         int64     `json:"id"`
	Email      string    `json:"email"`
	Role       string    `json:"role"`
	Plan       string    `json:"plan"`
	CreatedAt  time.Time `json:"created_at"`
	webauthnID []byte
	creds      []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.webauthnID }
func (u *User) WebAuthnName() string                       { return u.Email }
func (u *User) WebAuthnDisplayName() string                { return u.Email }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.creds }

type Service struct {
	Pool          *pgxpool.Pool
	BaseURL       string
	HMACKey       string
	SecureCookies bool
	AdminEmails   func(string) bool
	WebAuthn      *webauthn.WebAuthn

	limiters sync.Map // key → *limiterEntry
}

func NewService(pool *pgxpool.Pool, baseURL, secret string, secure bool, isAdmin func(string) bool) (*Service, error) {
	host := baseURL
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, ":/"); i >= 0 {
		host = host[:i]
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "yourcve",
		RPID:          host,
		RPOrigins:     []string{baseURL},
	})
	if err != nil {
		return nil, err
	}
	return &Service{Pool: pool, BaseURL: baseURL, HMACKey: secret, SecureCookies: secure, AdminEmails: isAdmin, WebAuthn: wa}, nil
}

// ---------------------------------------------------------------- tokens

func RandomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// NormalizeEmail validates and lowercases an address.
func NormalizeEmail(s string) (string, error) {
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil || !strings.Contains(a.Address, "@") || len(a.Address) > 254 {
		return "", errors.New("invalid email address")
	}
	return strings.ToLower(a.Address), nil
}

// ---------------------------------------------------------------- captcha

func (s *Service) Challenge() (altcha.Challenge, error) {
	exp := time.Now().Add(10 * time.Minute)
	return altcha.CreateChallenge(altcha.ChallengeOptions{HMACKey: s.HMACKey, MaxNumber: 100000, Expires: &exp})
}

// VerifyCaptcha checks the ALTCHA payload and prevents its reuse.
func (s *Service) VerifyCaptcha(ctx context.Context, payload string) bool {
	if payload == "" {
		return false
	}
	ok, err := altcha.VerifySolutionSafe(payload, s.HMACKey, true)
	if err != nil || !ok {
		return false
	}
	// replay protection: remember the payload until its challenge expires
	key := "altcha:" + base64.RawURLEncoding.EncodeToString(Hash(payload))
	if _, loaded := s.limiters.LoadOrStore(key, &limiterEntry{seen: time.Now()}); loaded {
		return false
	}
	return true
}

// ---------------------------------------------------------------- rate limiting

type limiterEntry struct {
	l    *rate.Limiter
	seen time.Time
}

// Allow is a token bucket per key (e.g. "register:"+ip).
func (s *Service) Allow(key string, every time.Duration, burst int) bool {
	v, _ := s.limiters.LoadOrStore(key, &limiterEntry{l: rate.NewLimiter(rate.Every(every), burst)})
	e := v.(*limiterEntry)
	e.seen = time.Now()
	if e.l == nil {
		return false
	}
	return e.l.Allow()
}

// GC drops idle limiters and old captcha payloads.
func (s *Service) GC() {
	cut := time.Now().Add(-30 * time.Minute)
	s.limiters.Range(func(k, v any) bool {
		if v.(*limiterEntry).seen.Before(cut) {
			s.limiters.Delete(k)
		}
		return true
	})
}

// ClientIP returns the caller's IP (X-Forwarded-For first hop when trusted).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := r.Header.Get("X-Real-Ip"); v != "" {
			return strings.TrimSpace(v)
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------------------------------------------------------------- magic links

// CreateMagicLink stores a one time token and returns the link.
func (s *Service) CreateMagicLink(ctx context.Context, email, purpose string) (string, error) {
	tok := RandomToken(32)
	_, err := s.Pool.Exec(ctx, `INSERT INTO magic_links (token_hash, email, purpose, expires_at) VALUES ($1,$2,$3,$4)`,
		Hash(tok), email, purpose, time.Now().Add(magicLinkTTL))
	return s.BaseURL + "/v1/auth/verify?token=" + tok, err
}

// ConsumeMagicLink validates the token, creates the user on registration and
// returns the user.
func (s *Service) ConsumeMagicLink(ctx context.Context, tok string) (*User, error) {
	var u *User
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var email, purpose string
		err := tx.QueryRow(ctx, `UPDATE magic_links SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()
			RETURNING email, purpose`, Hash(tok)).Scan(&email, &purpose)
		if err != nil {
			return errors.New("invalid or expired link")
		}
		role := "user"
		if s.AdminEmails != nil && s.AdminEmails(email) {
			role = "admin"
		}
		var id int64
		err = tx.QueryRow(ctx, `INSERT INTO users (email, verified, role) VALUES ($1, true, $2)
			ON CONFLICT (email) DO UPDATE SET verified = true, last_login = now(),
				role = CASE WHEN $2 = 'admin' THEN 'admin' ELSE users.role END
			RETURNING id`, email, role).Scan(&id)
		if err != nil {
			return err
		}
		u, err = loadUser(ctx, tx, id)
		return err
	})
	return u, err
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func loadUser(ctx context.Context, q querier, id int64) (*User, error) {
	u := &User{}
	err := q.QueryRow(ctx, `SELECT id, email, role, plan, created_at, webauthn_id FROM users WHERE id=$1`, id).
		Scan(&u.ID, &u.Email, &u.Role, &u.Plan, &u.CreatedAt, &u.webauthnID)
	return u, err
}

func (s *Service) UserExists(ctx context.Context, email string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email=$1 AND verified)`, email).Scan(&ok)
	return ok, err
}

// ---------------------------------------------------------------- sessions

func (s *Service) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64) error {
	tok := RandomToken(32)
	_, err := s.Pool.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent) VALUES ($1,$2,$3,$4,$5)`,
		Hash(tok), userID, time.Now().Add(sessionTTL), ClientIP(r, true), truncate(r.UserAgent(), 300))
	if err != nil {
		return err
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE users SET last_login=now() WHERE id=$1`, userID)
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
	return nil
}

func (s *Service) EndSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		_, _ = s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.SecureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// Via tells how a request was authenticated.
type Via int

const (
	ViaNone Via = iota
	ViaSession
	ViaAPIKey
)

// Authenticate resolves the user from the session cookie or a Bearer API key.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*User, Via, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		key := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		var id int64
		err := s.Pool.QueryRow(ctx, `UPDATE api_keys SET last_used_at=now() WHERE key_hash=$1 RETURNING user_id`, Hash(key)).Scan(&id)
		if err != nil {
			return nil, ViaNone, nil
		}
		u, err := loadUser(ctx, s.Pool, id)
		return u, ViaAPIKey, err
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, ViaNone, nil
	}
	var id int64
	err = s.Pool.QueryRow(ctx, `SELECT user_id FROM sessions WHERE token_hash=$1 AND expires_at > now()`, Hash(c.Value)).Scan(&id)
	if err != nil {
		return nil, ViaNone, nil
	}
	u, err := loadUser(ctx, s.Pool, id)
	return u, ViaSession, err
}

// ---------------------------------------------------------------- API keys

type APIKey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Key        string     `json:"key,omitempty"`
}

func (s *Service) CreateAPIKey(ctx context.Context, userID int64, name string) (*APIKey, error) {
	key := apiKeyPrefix + RandomToken(30)
	k := &APIKey{Name: name, Prefix: key[:8], Key: key}
	err := s.Pool.QueryRow(ctx, `INSERT INTO api_keys (user_id, name, prefix, key_hash) VALUES ($1,$2,$3,$4) RETURNING id, created_at`,
		userID, name, k.Prefix, Hash(key)).Scan(&k.ID, &k.CreatedAt)
	return k, err
}

func (s *Service) ListAPIKeys(ctx context.Context, userID int64) ([]APIKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE user_id=$1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (APIKey, error) {
		var k APIKey
		err := r.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsedAt)
		return k, err
	})
}

// ---------------------------------------------------------------- passkeys

type Passkey struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func (s *Service) loadCredentials(ctx context.Context, u *User) error {
	rows, err := s.Pool.Query(ctx, `SELECT credential FROM passkeys WHERE user_id=$1`, u.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	u.creds = nil
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var c webauthn.Credential
		if json.Unmarshal(raw, &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return rows.Err()
}

func (s *Service) saveWebAuthnSession(ctx context.Context, w http.ResponseWriter, userID *int64, data *webauthn.SessionData) error {
	id := RandomToken(24)
	b, _ := json.Marshal(data)
	_, err := s.Pool.Exec(ctx, `INSERT INTO webauthn_sessions (id, user_id, data, expires_at) VALUES ($1,$2,$3,$4)`,
		id, userID, b, time.Now().Add(5*time.Minute))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "yc_webauthn", Value: id, Path: "/v1/auth/passkey", HttpOnly: true,
		Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	return nil
}

func (s *Service) takeWebAuthnSession(ctx context.Context, r *http.Request) (*webauthn.SessionData, *int64, error) {
	c, err := r.Cookie("yc_webauthn")
	if err != nil {
		return nil, nil, errors.New("passkey session expired")
	}
	var raw []byte
	var uid *int64
	err = s.Pool.QueryRow(ctx, `DELETE FROM webauthn_sessions WHERE id=$1 AND expires_at > now() RETURNING data, user_id`, c.Value).Scan(&raw, &uid)
	if err != nil {
		return nil, nil, errors.New("passkey session expired")
	}
	var d webauthn.SessionData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, nil, err
	}
	return &d, uid, nil
}

func (s *Service) BeginPasskeyRegistration(ctx context.Context, w http.ResponseWriter, u *User) (any, error) {
	if err := s.loadCredentials(ctx, u); err != nil {
		return nil, err
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range u.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := s.WebAuthn.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, err
	}
	id := u.ID
	return opts, s.saveWebAuthnSession(ctx, w, &id, data)
}

func (s *Service) FinishPasskeyRegistration(ctx context.Context, r *http.Request, u *User, name string) error {
	data, uid, err := s.takeWebAuthnSession(ctx, r)
	if err != nil {
		return err
	}
	if uid == nil || *uid != u.ID {
		return errors.New("passkey session mismatch")
	}
	if err := s.loadCredentials(ctx, u); err != nil {
		return err
	}
	cred, err := s.WebAuthn.FinishRegistration(u, *data, r)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(cred)
	if name == "" {
		name = "Passkey"
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO passkeys (user_id, name, credential_id, credential) VALUES ($1,$2,$3,$4)`,
		u.ID, truncate(name, 60), cred.ID, b)
	return err
}

func (s *Service) BeginPasskeyLogin(ctx context.Context, w http.ResponseWriter) (any, error) {
	opts, data, err := s.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}
	return opts, s.saveWebAuthnSession(ctx, w, nil, data)
}

func (s *Service) FinishPasskeyLogin(ctx context.Context, r *http.Request) (*User, error) {
	data, _, err := s.takeWebAuthnSession(ctx, r)
	if err != nil {
		return nil, err
	}
	var found *User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var id int64
		if err := s.Pool.QueryRow(ctx, `SELECT u.id FROM passkeys p JOIN users u ON u.id = p.user_id
			WHERE p.credential_id=$1 AND u.webauthn_id=$2`, rawID, userHandle).Scan(&id); err != nil {
			return nil, errors.New("unknown passkey")
		}
		u, err := loadUser(ctx, s.Pool, id)
		if err != nil {
			return nil, err
		}
		if err := s.loadCredentials(ctx, u); err != nil {
			return nil, err
		}
		found = u
		return u, nil
	}
	cred, err := s.WebAuthn.FinishDiscoverableLogin(handler, *data, r)
	if err != nil || found == nil {
		return nil, errors.New("passkey login failed")
	}
	b, _ := json.Marshal(cred)
	_, _ = s.Pool.Exec(ctx, `UPDATE passkeys SET credential=$2, last_used_at=now() WHERE credential_id=$1`, cred.ID, b)
	return found, nil
}

func (s *Service) ListPasskeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id=$1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Passkey, error) {
		var p Passkey
		err := r.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt)
		return p, err
	})
}

// Cleanup removes expired sessions and tokens.
func (s *Service) Cleanup(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
		WITH a AS (DELETE FROM sessions WHERE expires_at < now()),
		     b AS (DELETE FROM magic_links WHERE expires_at < now() - interval '1 day')
		DELETE FROM webauthn_sessions WHERE expires_at < now()`)
	s.GC()
	return err
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
