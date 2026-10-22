package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dgtl-alv/sela/internal/secure"
)

type Claims struct {
	Iss    string `json:"iss"`
	Aud    any    `json:"aud"`
	Sub    string `json:"sub"`
	Tenant string `json:"tid"`
	Nonce  string `json:"nonce"`
	Email  string `json:"preferred_username"`
	Name   string `json:"name"`
	Exp    int64  `json:"exp"`
	Nbf    int64  `json:"nbf"`
}
type Principal struct {
	UserID, Email, Name, Role string
	Scopes                    []string
	ViaPAT                    bool
	PATID                     string
}
type Config struct{ TenantID, ClientID, ClientSecret, Issuer, AuthorizationURL, TokenURL, JWKSURL, RedirectURL string }
type Flow struct {
	State, Nonce, Verifier, Challenge, ReturnTo string
	Expires                                     time.Time
}
type Manager struct {
	cfg    Config
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	keysAt time.Time
}

func New(cfg Config, client *http.Client) *Manager {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Manager{cfg: cfg, client: client, now: time.Now, keys: map[string]*rsa.PublicKey{}}
}
func (m *Manager) Begin(returnTo string) (Flow, string, error) {
	return m.begin(returnTo, false)
}
func (m *Manager) BeginReauthentication(returnTo string) (Flow, string, error) {
	return m.begin(returnTo, true)
}

func safeReturnTo(raw string) string {
	if raw == "" || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, `\%`) {
		return "/"
	}
	for _, r := range raw {
		if r <= 0x1f || r == 0x7f {
			return "/"
		}
	}
	decoded := raw
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil {
			return "/"
		}
		if next == decoded {
			break
		}
		decoded = next
	}
	if decoded == "" || decoded[0] != '/' || strings.HasPrefix(decoded, "//") || strings.Contains(decoded, `\`) {
		return "/"
	}
	for _, r := range decoded {
		if r <= 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" || u.Path == "" || u.Path[0] != '/' {
		return "/"
	}
	if strings.Contains(u.Path, "@") || strings.Contains(u.RawPath, "@") {
		return "/"
	}
	segments := strings.Split(decoded, "/")
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return "/"
		}
	}
	return raw
}

func (m *Manager) begin(returnTo string, reauth bool) (Flow, string, error) {
	state, e := secure.Random(32)
	if e != nil {
		return Flow{}, "", e
	}
	nonce, e := secure.Random(32)
	if e != nil {
		return Flow{}, "", e
	}
	verifier, e := secure.Random(48)
	if e != nil {
		return Flow{}, "", e
	}
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	returnTo = safeReturnTo(returnTo)
	f := Flow{state, nonce, verifier, challenge, returnTo, m.now().Add(10 * time.Minute)}
	u, e := url.Parse(m.cfg.AuthorizationURL)
	if e != nil {
		return Flow{}, "", e
	}
	q := u.Query()
	q.Set("client_id", m.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", m.cfg.RedirectURL)
	q.Set("response_mode", "query")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if reauth {
		q.Set("prompt", "login")
		q.Set("max_age", "0")
	}
	u.RawQuery = q.Encode()
	return f, u.String(), nil
}
func (m *Manager) Exchange(ctx context.Context, code string, f Flow) (Claims, error) {
	if code == "" || m.now().After(f.Expires) {
		return Claims{}, errors.New("invalid or expired authorization response")
	}
	form := url.Values{"client_id": {m.cfg.ClientID}, "client_secret": {m.cfg.ClientSecret}, "code": {code}, "redirect_uri": {m.cfg.RedirectURL}, "grant_type": {"authorization_code"}, "code_verifier": {f.Verifier}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.TokenURL, strings.NewReader(form.Encode()))
	if e != nil {
		return Claims{}, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := m.client.Do(req)
	if e != nil {
		return Claims{}, fmt.Errorf("token exchange: %w", e)
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if e != nil {
		return Claims{}, e
	}
	if res.StatusCode != 200 {
		return Claims{}, errors.New("identity provider rejected authorization code")
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &tr) != nil || tr.IDToken == "" {
		return Claims{}, errors.New("identity provider response invalid")
	}
	return m.Validate(ctx, tr.IDToken, f.Nonce)
}
func (m *Manager) Validate(ctx context.Context, token, nonce string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid ID token")
	}
	dec := base64.RawURLEncoding
	hb, e := dec.DecodeString(parts[0])
	if e != nil {
		return Claims{}, errors.New("invalid ID token")
	}
	pb, e := dec.DecodeString(parts[1])
	if e != nil {
		return Claims{}, errors.New("invalid ID token")
	}
	sig, e := dec.DecodeString(parts[2])
	if e != nil {
		return Claims{}, errors.New("invalid ID token")
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil || h.Alg != "RS256" || h.Kid == "" {
		return Claims{}, errors.New("unsupported ID token")
	}
	key, e := m.key(ctx, h.Kid)
	if e != nil {
		return Claims{}, e
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, cryptoHashSHA256, digest[:], sig) != nil {
		return Claims{}, errors.New("invalid ID token signature")
	}
	var c Claims
	if json.Unmarshal(pb, &c) != nil {
		return Claims{}, errors.New("invalid ID token claims")
	}
	now := m.now().Unix()
	if c.Iss != m.cfg.Issuer || c.Tenant != m.cfg.TenantID || c.Sub == "" || c.Nonce != nonce || c.Exp <= now || c.Nbf > now+60 || !audience(c.Aud, m.cfg.ClientID) {
		return Claims{}, errors.New("invalid ID token claims")
	}
	return c, nil
}

const cryptoHashSHA256 = 5

func audience(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case []any:
		for _, a := range x {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
func (m *Manager) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.mu.Lock()
	if k := m.keys[kid]; k != nil && m.now().Sub(m.keysAt) < time.Hour {
		m.mu.Unlock()
		return k, nil
	}
	m.mu.Unlock()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.JWKSURL, nil)
	if e != nil {
		return nil, e
	}
	res, e := m.client.Do(req)
	if e != nil {
		return nil, fmt.Errorf("JWKS: %w", e)
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if e != nil || res.StatusCode != 200 {
		return nil, errors.New("JWKS unavailable")
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, X5c string
			X5C                 []string `json:"x5c"`
		} `json:"keys"`
	}
	if json.Unmarshal(b, &set) != nil {
		return nil, errors.New("invalid JWKS")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Kid == "" {
			continue
		}
		var k *rsa.PublicKey
		if len(j.X5C) > 0 {
			der, er := base64.StdEncoding.DecodeString(j.X5C[0])
			if er == nil {
				cert, er := x509.ParseCertificate(der)
				if er == nil {
					k, _ = cert.PublicKey.(*rsa.PublicKey)
				}
			}
		}
		if k == nil {
			nb, er1 := base64.RawURLEncoding.DecodeString(j.N)
			eb, er2 := base64.RawURLEncoding.DecodeString(j.E)
			if er1 == nil && er2 == nil && len(eb) <= 4 {
				k = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(binary.BigEndian.Uint32(append(make([]byte, 4-len(eb)), eb...)))}
			}
		}
		if k != nil {
			keys[j.Kid] = k
		}
	}
	m.mu.Lock()
	m.keys = keys
	m.keysAt = m.now()
	k := keys[kid]
	m.mu.Unlock()
	if k == nil {
		return nil, errors.New("ID token signing key not found")
	}
	return k, nil
}
