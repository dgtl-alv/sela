package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dgtl-alv/sela/internal/auth"
	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/odoo"
	"github.com/dgtl-alv/sela/internal/secure"
	"github.com/dgtl-alv/sela/internal/store"
	"github.com/dgtl-alv/sela/internal/upload"
	"github.com/dgtl-alv/sela/internal/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
)

type uploadOdoo struct {
	readCredentials chan odoo.Credentials
}

func (uploadOdoo) Ready(context.Context) error                                 { return nil }
func (uploadOdoo) Search(context.Context, string, int) ([]odoo.Service, error) { return nil, nil }
func (o uploadOdoo) Read(ctx context.Context, _ int64) (*odoo.Service, error) {
	if o.readCredentials != nil {
		credential, _ := odoo.CredentialsFromContext(ctx)
		o.readCredentials <- credential
	}
	return &odoo.Service{ID: 999, Name: "Test"}, nil
}
func (uploadOdoo) Evidence(context.Context, int64) ([]odoo.Evidence, error) { return nil, nil }

func TestBrowserUploadTargetLookupUsesPerUserCredentials(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := store.Store{DB: pool}
	user := webTestUUID(t)
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Credential upload test')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user)
	sessionKey := []byte("01234567890123456789012345678901")
	credentialKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	ciphertext, err := webhook.EncryptWithAAD(credentialKey, []byte("user-secret"), []byte(user))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutUserCredential(ctx, user, "user@example.test", ciphertext); err != nil {
		t.Fatal(err)
	}
	token, csrf := "session-"+user, "csrf-"+user
	now := time.Now().UTC()
	p := auth.Principal{UserID: user, Email: user + "@example.test", Name: "Credential upload test", Role: "technician"}
	if err = s.CreateSession(ctx, p, secure.Hash(sessionKey, token), secure.Hash(sessionKey, csrf), now, now.Add(time.Hour), now.Add(2*time.Hour), "127.0.0.1", nil); err != nil {
		t.Fatal(err)
	}
	seen := make(chan odoo.Credentials, 1)
	root := filepath.Join(t.TempDir(), "quarantine")
	cfg := config.Config{Environment: "test", AppName: "SELA", ApplicationID: "sela", PublicURL: "https://sela.test", QuarantineDir: root, SessionHashKey: sessionKey, OdooCredentialEncryptionKey: credentialKey, SessionIdle: time.Hour, SessionAbsolute: 2 * time.Hour}
	h := New(cfg, Dependencies{Store: &s, Odoo: uploadOdoo{readCredentials: seen}, Now: func() time.Time { return now }})
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err = writer.WriteField("csrf_token", csrf); err != nil {
		t.Fatal(err)
	}
	filePart, err := writer.CreateFormFile("files", "evidence.webp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = filePart.Write(upload.MagicFixture("image/webp")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/services/998/uploads", bytes.NewReader(body.Bytes()))
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("Origin", cfg.PublicURL)
	r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
	r.AddCookie(&http.Cookie{Name: "sela_csrf", Value: csrf})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	credential := <-seen
	if credential.Username != "user@example.test" || credential.APIKey != "user-secret" {
		t.Fatalf("target lookup credentials=%+v", credential)
	}
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/services/998?queued=1" {
		t.Fatalf("browser multipart status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

func TestBrowserWithoutOdooCredentialRedirectsToSetup(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := store.Store{DB: pool}
	user := webTestUUID(t)
	email := user + "@example.test"
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'First login test')`, user, email); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user)
	sessionKey := []byte("01234567890123456789012345678901")
	token, csrf := "session-"+user, "csrf-"+user
	now := time.Now().UTC()
	p := auth.Principal{UserID: user, Email: email, Name: "First login test", Role: "technician"}
	if err = s.CreateSession(ctx, p, secure.Hash(sessionKey, token), secure.Hash(sessionKey, csrf), now, now.Add(time.Hour), now.Add(2*time.Hour), "127.0.0.1", nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: "test", AppName: "SELA", ApplicationID: "sela", PublicURL: "https://sela.test", SessionHashKey: sessionKey, OdooCredentialEncryptionKey: []byte("abcdefghijklmnopqrstuvwxyz123456"), SessionIdle: time.Hour, SessionAbsolute: 2 * time.Hour}
	h := New(cfg, Dependencies{Store: &s, Odoo: uploadOdoo{}, Now: func() time.Time { return now }})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings/credentials?setup=required" {
		t.Fatalf("status=%d location=%q body=%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}

	r = httptest.NewRequest(http.MethodGet, "/settings/credentials?setup=required", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "API token") || !strings.Contains(body, "Password EMICA") || !strings.Contains(body, "Pengaturan wajib") || !strings.Contains(body, email) {
		t.Fatalf("status=%d body=%s", w.Code, body)
	}

	if _, err = pool.Exec(ctx, `UPDATE sessions SET authenticated_at=$2 WHERE token_hash=$1`, secure.Hash(sessionKey, token), now.Add(-11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/settings/credentials?setup=required", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `name="secret"`) || strings.Contains(body, "Masuk ulang dengan Microsoft") {
		t.Fatalf("active old session status=%d body=%s", w.Code, body)
	}
}

type multipartSpec struct {
	field, name string
	data        []byte
}

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		os.Exit(m.Run())
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(73190521)`); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = conn.Exec(ctx, `TRUNCATE users, domain_events CASCADE`); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(73190521)`)
	conn.Release()
	pool.Close()
	os.Exit(code)
}

func TestMultipartFailuresAreAtomicAndRemoveQuarantine(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := store.Store{DB: pool}
	user := webTestUUID(t)
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Web upload test')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user)

	sessionKey := []byte("01234567890123456789012345678901")
	token := "session-token-" + user
	csrf := "csrf-token-" + user
	now := time.Now().UTC()
	p := auth.Principal{UserID: user, Email: user + "@example.test", Name: "Web upload test", Role: "technician"}
	if err = s.CreateSession(ctx, p, secure.Hash(sessionKey, token), secure.Hash(sessionKey, csrf), now, now.Add(time.Hour), now.Add(2*time.Hour), "127.0.0.1", nil); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "quarantine")
	credentialKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	credentialCiphertext, err := webhook.EncryptWithAAD(credentialKey, []byte("user-api-key"), []byte(user))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutUserCredential(ctx, user, "user@example.test", credentialCiphertext); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: "test", AppName: "SELA", ApplicationID: "sela", PublicURL: "https://sela.test", QuarantineDir: root, SessionHashKey: sessionKey, OdooCredentialEncryptionKey: credentialKey, SessionIdle: time.Hour, SessionAbsolute: 2 * time.Hour}
	h := New(cfg, Dependencies{Store: &s, Odoo: uploadOdoo{}, Now: func() time.Time { return now }})
	valid := upload.MagicFixture("image/webp")

	tests := []struct {
		name      string
		parts     []multipartSpec
		truncate  bool
		dbFailure bool
	}{
		{name: "valid first invalid second", parts: []multipartSpec{{"files", "first.webp", valid}, {"files", "second.jpg", valid}}},
		{name: "extra part", parts: []multipartSpec{{"files", "first.webp", valid}, {"unexpected", "extra.webp", valid}}},
		{name: "truncated request", parts: []multipartSpec{{"files", "first.webp", valid}}, truncate: true},
		{name: "database queue failure", parts: []multipartSpec{{"files", "first.webp", valid}}, dbFailure: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dbFailure {
				_, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION sela_test_reject_upload() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.diagnose_id=999 THEN RAISE EXCEPTION 'simulated queue failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER sela_test_reject_upload BEFORE INSERT ON upload_jobs FOR EACH ROW EXECUTE FUNCTION sela_test_reject_upload()`)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_reject_upload ON upload_jobs; DROP FUNCTION IF EXISTS sela_test_reject_upload()`)
				})
			}
			body, contentType := makeMultipart(t, tc.parts, tc.truncate)
			r := httptest.NewRequest(http.MethodPost, "/services/999/uploads", bytes.NewReader(body))
			r.Header.Set("Content-Type", contentType)
			r.Header.Set("Origin", cfg.PublicURL)
			r.Header.Set("X-CSRF-Token", csrf)
			r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
			r.AddCookie(&http.Cookie{Name: "sela_csrf", Value: csrf})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var jobs, events int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM upload_jobs WHERE user_id=$1 AND diagnose_id=999`, user).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM domain_events WHERE event_name='evidence.upload.queued.v1' AND payload->>'diagnose_id'='999'`).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if jobs != 0 || events != 0 {
				t.Fatalf("jobs=%d events=%d", jobs, events)
			}
			entries, err := os.ReadDir(root)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("quarantine files remain: %v", entries)
			}
		})
	}
}

func TestWebhookCreateUsesRequestTransactionAndRejectsUnknownEvents(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := store.Store{DB: pool}
	user := webTestUUID(t)
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name,role) VALUES($1,$2,'Webhook test','admin')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user)
	sessionKey := []byte("01234567890123456789012345678901")
	webhookKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	token, csrf := "session-"+user, "csrf-"+user
	now := time.Now().UTC()
	p := auth.Principal{UserID: user, Email: user + "@example.test", Name: "Webhook test", Role: "admin"}
	if err = s.CreateSession(ctx, p, secure.Hash(sessionKey, token), secure.Hash(sessionKey, csrf), now, now.Add(time.Hour), now.Add(2*time.Hour), "127.0.0.1", nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Environment: "test", AppName: "SELA", ApplicationID: "sela", PublicURL: "https://sela.test", SessionHashKey: sessionKey, WebhookEncryptionKey: webhookKey, SessionIdle: time.Hour, SessionAbsolute: 2 * time.Hour}
	h := New(cfg, Dependencies{Store: &s, Now: func() time.Time { return now }})
	request := func(idempotency, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/webhook-endpoints", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", cfg.PublicURL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", idempotency)
		r.AddCookie(&http.Cookie{Name: "__Host-sela_session", Value: token})
		r.AddCookie(&http.Cookie{Name: "sela_csrf", Value: csrf})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	unknown := request("unknown-"+user, `{"Description":"unknown","URL":"https://example.com/hook","Events":["pat.created.v1","unknown.event.v1"]}`)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "invalid_events") {
		t.Fatalf("unknown status=%d body=%s", unknown.Code, unknown.Body.String())
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM webhook_endpoints WHERE created_by=$1`, user).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unknown event leaked endpoints=%d err=%v", count, err)
	}

	if _, err = pool.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_fail_webhook_commit ON webhook_endpoints; DROP FUNCTION IF EXISTS sela_test_fail_webhook_commit(); CREATE FUNCTION sela_test_fail_webhook_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.created_by='`+user+`' THEN RAISE EXCEPTION 'forced commit failure'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER sela_test_fail_webhook_commit AFTER INSERT ON webhook_endpoints DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sela_test_fail_webhook_commit()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_fail_webhook_commit ON webhook_endpoints; DROP FUNCTION IF EXISTS sela_test_fail_webhook_commit()`)
	})
	failed := request("commit-"+user, `{"Description":"commit failure","URL":"https://example.com/hook","Events":["pat.created.v1"]}`)
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("commit failure status=%d body=%s", failed.Code, failed.Body.String())
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM webhook_endpoints WHERE created_by=$1`, user).Scan(&count); err != nil || count != 0 {
		t.Fatalf("commit failure leaked endpoints=%d err=%v", count, err)
	}
	var records int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND key=$2`, user, "commit-"+user).Scan(&records); err != nil || records != 0 {
		t.Fatalf("commit failure leaked idempotency records=%d err=%v", records, err)
	}
}

func makeMultipart(t *testing.T, specs []multipartSpec, truncate bool) ([]byte, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, spec := range specs {
		part, err := w.CreateFormFile(spec.field, spec.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = part.Write(spec.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if truncate {
		closing := []byte("--" + w.Boundary() + "--\r\n")
		if !bytes.HasSuffix(out, closing) {
			t.Fatal("multipart closing boundary missing")
		}
		out = out[:len(out)-len(closing)]
	}
	return append([]byte(nil), out...), w.FormDataContentType()
}

func webTestUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var _ = strings.Builder{}
