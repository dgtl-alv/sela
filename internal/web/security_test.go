package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgtl-alv/sela/internal/config"
)

func TestAuthorizationKindRejectsMalformedWithoutCookieFallback(t *testing.T) {
	for _, h := range []string{"Basic abc", "Bearer", "Bearer  x", "bearer token", "Bearer token extra"} {
		kind, token, err := authorizationKind(h)
		if err == nil || kind != authInvalid || token != "" {
			t.Fatalf("header %q: kind=%v token=%q err=%v", h, kind, token, err)
		}
	}
	kind, token, err := authorizationKind("")
	if err != nil || kind != authCookie || token != "" {
		t.Fatalf("empty header: kind=%v token=%q err=%v", kind, token, err)
	}
	kind, token, err = authorizationKind("Bearer token")
	if err != nil || kind != authBearer || token != "token" {
		t.Fatalf("bearer: kind=%v token=%q err=%v", kind, token, err)
	}
}

func TestCookieMutationNeedsCSRFAndOriginButBearerDoesNot(t *testing.T) {
	if !needsCSRF("POST", authCookie) || !needsCSRF("PATCH", authCookie) || !needsCSRF("DELETE", authCookie) {
		t.Fatal("cookie mutations must require CSRF")
	}
	if needsCSRF("GET", authCookie) || needsCSRF("POST", authBearer) {
		t.Fatal("safe cookie requests and bearer requests must be exempt")
	}
	r := httptest.NewRequest("POST", "https://sela.test/api/v1/test", nil)
	if sameOrigin(r, "https://sela.test") {
		t.Fatal("missing Origin accepted")
	}
	r.Header.Set("Origin", "https://evil.test")
	if sameOrigin(r, "https://sela.test") {
		t.Fatal("cross Origin accepted")
	}
	r.Header.Set("Origin", "https://sela.test")
	if !sameOrigin(r, "https://sela.test") {
		t.Fatal("matching Origin rejected")
	}
}

func TestMalformedAuthorizationDoesNotFallBackToCookie(t *testing.T) {
	h := New(testConfig(), Dependencies{})
	r := httptest.NewRequest("GET", "https://sela.test/api/v1/me", nil)
	r.Header.Set("Authorization", "Basic invalid")
	r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: "cookie"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLoginRateLimitBound(t *testing.T) {
	h := New(testConfig(), Dependencies{})
	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "https://sela.test/login", nil)
		r.RemoteAddr = "192.0.2.20:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status=%d", i, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "https://sela.test/login", nil)
	r.RemoteAddr = "192.0.2.20:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
	}
}

func testConfig() config.Config {
	return config.Config{Environment: "test", AppName: "SELA", ApplicationID: "sela", PublicURL: "https://sela.test"}
}

func TestClientIPUsesPeerAndIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "https://sela.test/", nil)
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := clientIP(r); got != "192.0.2.10" {
		t.Fatalf("clientIP=%q", got)
	}
}

func TestRateLimiterBoundsKeysAndRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newRateLimiter(2, time.Minute, 3, func() time.Time { return now })
	if !l.Allow("one") || !l.Allow("one") || l.Allow("one") {
		t.Fatal("limit not enforced")
	}
	if !l.Allow("two") || !l.Allow("three") || !l.Allow("four") {
		t.Fatal("new keys unexpectedly rejected")
	}
	if got := l.Len(); got > 3 {
		t.Fatalf("key map unbounded: %d", got)
	}
	now = now.Add(time.Minute)
	if !l.Allow("one") {
		t.Fatal("key did not refill")
	}
}

func TestIdempotencyFingerprintIncludesMethodPathAndBody(t *testing.T) {
	a := idempotencyFingerprint("POST", "/api/v1/a", []byte(`{"x":1}`))
	for _, b := range [][3]string{
		{"PATCH", "/api/v1/a", `{"x":1}`},
		{"POST", "/api/v1/b", `{"x":1}`},
		{"POST", "/api/v1/a", `{"x":2}`},
	} {
		other := idempotencyFingerprint(b[0], b[1], []byte(b[2]))
		if a == other {
			t.Fatalf("fingerprint collision for %v", b)
		}
	}
}
