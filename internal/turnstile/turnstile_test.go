package turnstile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyAndReplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("secret") != "secret" {
			t.Error("missing secret")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "hostname": "app.test", "action": "login_start", "challenge_ts": time.Now().UTC()})
	}))
	defer srv.Close()
	v := Verifier{Secret: "secret", URL: srv.URL, Hostnames: []string{"app.test"}, Client: srv.Client()}
	if e := v.Verify(context.Background(), "token", "login_start", ""); e != nil {
		t.Fatal(e)
	}
	if e := v.Verify(context.Background(), "token", "login_start", ""); e == nil {
		t.Fatal("replay accepted")
	}
}
func TestWrongActionFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "hostname": "app.test", "action": "other", "challenge_ts": time.Now().UTC()})
	}))
	defer srv.Close()
	v := Verifier{Secret: "secret", URL: srv.URL, Hostnames: []string{"app.test"}, Client: srv.Client()}
	if e := v.Verify(context.Background(), "token", "login_start", ""); e == nil {
		t.Fatal("wrong action accepted")
	}
}
