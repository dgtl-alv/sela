package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateJWKSClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "k1", "n": n, "e": e}}})
	}))
	defer server.Close()
	now := time.Unix(1700000000, 0)
	m := New(Config{TenantID: "tenant", ClientID: "client", Issuer: "https://issuer.test", JWKSURL: server.URL}, server.Client())
	m.now = func() time.Time { return now }
	header := encodeJSON(map[string]any{"alg": "RS256", "kid": "k1"})
	payload := encodeJSON(map[string]any{"iss": "https://issuer.test", "aud": "client", "sub": "subject", "tid": "tenant", "nonce": "nonce", "exp": now.Unix() + 300, "nbf": now.Unix() - 10})
	digest := sha256.Sum256([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHashSHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
	claims, err := m.Validate(context.Background(), token, "nonce")
	if err != nil || claims.Sub != "subject" {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	if _, err = m.Validate(context.Background(), token, "wrong"); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}
func TestBeginPKCEAndSafeReturn(t *testing.T) {
	m := New(Config{ClientID: "client", AuthorizationURL: "https://login.test/authorize", RedirectURL: "https://app.test/auth/callback"}, nil)
	flow, location, err := m.Begin("https://evil.test")
	if err != nil {
		t.Fatal(err)
	}
	if flow.ReturnTo != "/" || flow.Verifier == "" || flow.Challenge == "" || !strings.Contains(location, "code_challenge_method=S256") {
		t.Fatalf("flow=%+v location=%s", flow, location)
	}
	reauth, reauthLocation, err := m.BeginReauthentication("/settings/tokens?tab=active")
	if err != nil {
		t.Fatal(err)
	}
	if reauth.ReturnTo != "/settings/tokens?tab=active" || !strings.Contains(reauthLocation, "prompt=login") || !strings.Contains(reauthLocation, "max_age=0") {
		t.Fatalf("reauth=%+v location=%s", reauth, reauthLocation)
	}
}

func TestBeginRejectsAmbiguousReturnTargets(t *testing.T) {
	m := New(Config{ClientID: "client", AuthorizationURL: "https://login.test/authorize", RedirectURL: "https://app.test/auth/callback"}, nil)
	unsafe := []string{
		`https://evil.test`, `//evil.test/path`, `/\\evil.test/path`, `\\evil.test\path`,
		`/%2f%2fevil.test`, `/%5cevil.test`, `/%252fevil.test`, `/safe%2f..%2fevil`,
		`http:evil.test`, `https:%2f%2fevil.test`, `/user@evil.test`, `/safe\path`,
		"/safe\x00path", "/safe\r\nLocation:%20https://evil.test", `/./safe`, `/safe/../admin`,
		`/%09/evil.test`, `/ %2f%2fevil.test`, `///evil.test`, `/safe%20path`, `/safe%3fnext`, `/safe%23fragment`,
	}
	for _, target := range unsafe {
		t.Run(target, func(t *testing.T) {
			flow, _, err := m.Begin(target)
			if err != nil {
				t.Fatal(err)
			}
			if flow.ReturnTo != "/" {
				t.Fatalf("unsafe return target accepted: %q", flow.ReturnTo)
			}
		})
	}
	for _, target := range []string{"/", "/services", "/services/42?tab=evidence", "/settings/tokens#active"} {
		t.Run("safe_"+target, func(t *testing.T) {
			flow, _, err := m.Begin(target)
			if err != nil || flow.ReturnTo != target {
				t.Fatalf("safe return target rejected: flow=%+v err=%v", flow, err)
			}
		})
	}
}
func encodeJSON(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}
