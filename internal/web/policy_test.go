package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgtl-alv/sela/internal/auth"
	"github.com/dgtl-alv/sela/internal/store"
)

func TestRouteAuthorizationPolicy(t *testing.T) {
	patRead := auth.Principal{ViaPAT: true, Scopes: []string{"evidence:read"}}
	patWrite := auth.Principal{ViaPAT: true, Scopes: []string{"evidence:write"}}
	request := func(p auth.Principal) *http.Request {
		r := httptest.NewRequest("GET", "https://sela.test/api/v1/upload-jobs/id", nil)
		return r.WithContext(context.WithValue(r.Context(), principalKey, p))
	}
	if !scope(request(patRead), "evidence:read") || scope(request(patWrite), "evidence:read") {
		t.Fatal("upload status must require evidence:read")
	}
	a := &App{d: Dependencies{Now: func() time.Time { return time.Unix(2000, 0) }}}
	interactive := request(auth.Principal{Role: "admin"})
	interactive = interactive.WithContext(context.WithValue(interactive.Context(), sessionKey, store.Session{AuthenticatedAt: time.Unix(1000, 0)}))
	if !a.admin(interactive) || a.interactiveCookieSession(request(patRead)) {
		t.Fatal("sensitive routes must require an interactive cookie session")
	}
}

func TestUserAdministrationAndCredentialsRequireInteractiveSession(t *testing.T) {
	a := &App{d: Dependencies{Now: func() time.Time { return time.Unix(2000, 0) }}}
	request := func(p auth.Principal, authenticatedAt time.Time) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://sela.test/api/v1/admin/users", nil)
		ctx := context.WithValue(r.Context(), principalKey, p)
		ctx = context.WithValue(ctx, sessionKey, store.Session{AuthenticatedAt: authenticatedAt})
		return r.WithContext(ctx)
	}
	if !a.admin(request(auth.Principal{Role: "admin"}, time.Unix(1000, 0))) {
		t.Fatal("active admin session rejected because authentication is old")
	}
	if a.admin(request(auth.Principal{Role: "technician"}, time.Unix(1900, 0))) {
		t.Fatal("technician accepted as admin")
	}
	if !a.credentialOwner(request(auth.Principal{Role: "technician"}, time.Unix(1000, 0))) {
		t.Fatal("active interactive owner rejected because authentication is old")
	}
	pat := request(auth.Principal{Role: "technician", ViaPAT: true}, time.Unix(1900, 0))
	if a.credentialOwner(pat) {
		t.Fatal("PAT accepted for credential management")
	}
}

func TestOdooRoutesRequirePerUserCredentials(t *testing.T) {
	for _, path := range []string{"/api/v1/services", "/api/v1/services/1", "/api/v1/services/1/evidence", "/api/v1/services/1/upload-jobs"} {
		if !requiresOdooCredential(path) {
			t.Errorf("route %s did not require credentials", path)
		}
	}
	for _, path := range []string{"/api/v1/me", "/api/v1/credentials/emica", "/api/v1/admin/users"} {
		if requiresOdooCredential(path) {
			t.Errorf("route %s unexpectedly required credentials", path)
		}
	}
}

func TestNormalizeUserInputRejectsInvalidAdminFields(t *testing.T) {
	cases := []struct {
		email, name, role string
	}{
		{"not-an-email", "User", "technician"},
		{"user@example.test", "", "technician"},
		{"user@example.test", "User", "owner"},
	}
	for _, tc := range cases {
		if _, _, _, ok := normalizeUserInput(tc.email, tc.name, tc.role); ok {
			t.Fatalf("accepted email=%q name=%q role=%q", tc.email, tc.name, tc.role)
		}
	}
	email, name, role, ok := normalizeUserInput(" User@Example.Test ", " Operator ", "technician")
	if !ok || email != "user@example.test" || name != "Operator" || role != "technician" {
		t.Fatalf("normalized email=%q name=%q role=%q ok=%v", email, name, role, ok)
	}
}

func TestDecodeJSONStableInvalidJSON(t *testing.T) {
	a := &App{}
	cases := []struct{ name, contentType, body string }{
		{"wrong content type", "application/json; charset=utf-8", `{}`},
		{"unknown field", "application/json", `{"unknown":1}`},
		{"trailing", "application/json", `{} {}`},
		{"oversized", "application/json", `{"name":"` + strings.Repeat("x", 70<<10) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://sela.test/test", bytes.NewBufferString(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			var in struct {
				Name string `json:"name"`
			}
			if a.decodeJSON(w, r, &in) || w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"invalid_json"`) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
