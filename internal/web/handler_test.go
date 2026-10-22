package web_test

import (
	"context"
	"errors"
	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/web"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func cfg() config.Config {
	return config.Config{Environment: "test", AppName: "SELA Service Evidence Uploader", ApplicationID: "sela", GTMContainerID: "GTM-TEST123", PublicURL: "https://sela.test", EntraAuthURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize", TurnstileEnabled: true}
}
func req(h http.Handler, m, p string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(m, p, nil))
	return w
}
func TestHealthProcessOnly(t *testing.T) {
	called := false
	h := web.New(cfg(), web.Dependencies{Ready: func(context.Context) error { called = true; return errors.New("down") }})
	w := req(h, "GET", "/healthz")
	if w.Code != 200 || called {
		t.Fatalf("status=%d called=%v", w.Code, called)
	}
}
func TestReadinessRedacts(t *testing.T) {
	h := web.New(cfg(), web.Dependencies{Ready: func(context.Context) error { return errors.New("password detail") }})
	w := req(h, "GET", "/readyz")
	if w.Code != 503 || strings.Contains(w.Body.String(), "password") {
		t.Fatalf("response=%d %s", w.Code, w.Body.String())
	}
}
func TestLoginHasTurnstileMicrosoftGTMAndNonce(t *testing.T) {
	h := web.New(cfg(), web.Dependencies{Ready: func(context.Context) error { return nil }})
	w := req(h, "GET", "/login")
	body := w.Body.String()
	for _, x := range []string{"Masuk dengan Microsoft", "cf-turnstile", "login_start", "GTM-TEST123", "SELA Service Evidence Uploader"} {
		if !strings.Contains(body, x) {
			t.Errorf("missing %q", x)
		}
	}
	if strings.Count(body, "googletagmanager.com/gtm.js") != 1 {
		t.Errorf("GTM script count wrong")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-") {
		t.Error("missing nonce CSP")
	}
	if !strings.Contains(csp, "form-action 'self' https://login.microsoftonline.com") {
		t.Errorf("missing Entra form-action: %s", csp)
	}
}
func TestCSPDoesNotTrustArbitraryEntraHost(t *testing.T) {
	c := cfg()
	c.EntraAuthURL = "https://evil.example/authorize"
	h := web.New(c, web.Dependencies{})
	w := req(h, "GET", "/login")
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "evil.example") || strings.Contains(csp, "form-action 'self' https://") {
		t.Fatalf("unsafe form-action: %s", csp)
	}
}
func TestStagingLoginOmitsTurnstileWhenDisabled(t *testing.T) {
	c := cfg()
	c.Environment = "staging"
	c.TurnstileEnabled = false
	h := web.New(c, web.Dependencies{Ready: func(context.Context) error { return nil }})
	w := req(h, "GET", "/login")
	body := w.Body.String()
	if w.Code != 200 || strings.Contains(body, "cf-turnstile") || strings.Contains(body, "challenges.cloudflare.com/turnstile") {
		t.Fatalf("status=%d body=%s", w.Code, body)
	}
}
func TestSecurityHeadersAndMethodAllowlist(t *testing.T) {
	h := web.New(cfg(), web.Dependencies{})
	w := req(h, "POST", "/healthz")
	if w.Code != 405 {
		t.Fatalf("status=%d", w.Code)
	}
	for _, x := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"} {
		if w.Header().Get(x) == "" {
			t.Errorf("missing %s", x)
		}
	}
}
func TestUnauthenticatedBrowserRedirects(t *testing.T) {
	h := web.New(cfg(), web.Dependencies{})
	for _, path := range []string{"/", "/guide"} {
		w := req(h, "GET", path)
		if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
			t.Fatalf("path=%s status=%d location=%s", path, w.Code, w.Header().Get("Location"))
		}
	}
}
func TestAPIStableError(t *testing.T) {
	h := web.New(cfg(), web.Dependencies{})
	w := req(h, "GET", "/api/v1/me")
	if w.Code != 401 {
		t.Fatalf("status=%d", w.Code)
	}
	for _, x := range []string{`"error"`, `"code":"unauthorized"`, `"request_id"`} {
		if !strings.Contains(w.Body.String(), x) {
			t.Errorf("missing %s", x)
		}
	}
}
