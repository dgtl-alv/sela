package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/odoo"
	"github.com/dgtl-alv/sela/internal/store"
	"github.com/dgtl-alv/sela/internal/upload"
	"github.com/dgtl-alv/sela/internal/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

func workerStore(t *testing.T) (context.Context, store.Store, string, config.Config) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	user := workerUUID(t)
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Worker test')`, user, user+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user) })
	cfg := config.Config{QuarantineDir: t.TempDir(), OdooCredentialEncryptionKey: []byte("01234567890123456789012345678901")}
	ciphertext, err := webhook.EncryptWithAAD(cfg.OdooCredentialEncryptionKey, []byte("k"), []byte(user))
	if err != nil {
		t.Fatal(err)
	}
	if err = (store.Store{DB: pool}).PutUserCredential(ctx, user, "u", ciphertext); err != nil {
		t.Fatal(err)
	}
	return ctx, store.Store{DB: pool}, user, cfg
}

func addWorkerJob(t *testing.T, ctx context.Context, s store.Store, cfg config.Config, user, status string) store.UploadJob {
	t.Helper()
	id := workerUUID(t)
	j := store.UploadJob{ID: id, UserID: user, DiagnoseID: 42, DisplayName: "proof.webp", StorageKey: id + ".quarantine", MediaType: "image/webp", Size: 4, SHA256: []byte("hash"), ExternalOperationID: id}
	if err := os.WriteFile(filepath.Join(cfg.QuarantineDir, j.StorageKey), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUpload(ctx, j); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		if _, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET status=$2 WHERE id=$1`, id, status); err != nil {
			t.Fatal(err)
		}
	}
	return j
}

func TestProcessScannerTransientRetry(t *testing.T) {
	ctx, s, user, cfg := workerStore(t)
	j := addWorkerJob(t, ctx, s, cfg, user, "pending")
	scanner := scannerFunc(func(context.Context, string) (upload.ScanResult, error) {
		return upload.ScanResult{}, fmt.Errorf("temporary")
	})
	if err := process(ctx, cfg, s, nil, scanner, "worker"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Upload(ctx, j.ID, user)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" || got.Attempts != 1 || got.ClaimToken != "" {
		t.Fatalf("retry state=%+v", got)
	}
}

type scannerFunc func(context.Context, string) (upload.ScanResult, error)

func (f scannerFunc) Ready(context.Context) error { return nil }
func (f scannerFunc) Scan(ctx context.Context, path string) (upload.ScanResult, error) {
	return f(ctx, path)
}

type fakeOdoo struct {
	mu             sync.Mutex
	operationName  string
	evidenceExists bool
	failAfterWrite bool
	writes         int
}

func (f *fakeOdoo) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s := string(body)
	w.Header().Set("Content-Type", "text/xml")
	if strings.Contains(r.URL.Path, "/common") {
		xmlValue(w, "<int>7</int>")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.Contains(s, "<string>fleet.diagnose</string>") && strings.Contains(s, "sharepoint_file"):
		f.writes++
		f.evidenceExists = true
		if f.failAfterWrite {
			f.failAfterWrite = false
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		xmlValue(w, "<boolean>1</boolean>")
	case strings.Contains(s, "<string>fleet.link</string>"):
		name := f.operationName
		if !f.evidenceExists {
			xmlValue(w, "<array><data></data></array>")
			return
		}
		xmlValue(w, "<array><data><value><struct>"+
			member("id", "<int>9001</int>")+member("link", "<string>https://share.example/evidence</string>")+member("file_name", "<string>"+name+"</string>")+"</struct></value></data></array>")
	case strings.Contains(s, "<string>fleet.diagnose</string>") && strings.Contains(s, "fleet_link_ids") && !strings.Contains(s, "x_service_booking_id"):
		ids := ""
		if f.evidenceExists {
			ids = "<value><int>9001</int></value>"
		}
		xmlValue(w, "<array><data><value><struct>"+member("id", "<int>42</int>")+member("fleet_link_ids", "<array><data>"+ids+"</data></array>")+"</struct></value></data></array>")
	default:
		xmlValue(w, "<array><data><value><struct>"+member("id", "<int>42</int>")+member("name", "<string>Job</string>")+member("fleet_link_ids", "<array><data></data></array>")+"</struct></value></data></array>")
	}
}

func member(name, value string) string {
	return "<member><name>" + name + "</name><value>" + value + "</value></member>"
}
func xmlValue(w io.Writer, value string) {
	_, _ = fmt.Fprint(w, `<?xml version="1.0"?><methodResponse><params><param><value>`+value+`</value></param></params></methodResponse>`)
}

func TestProcessReconcilesExternalSuccessWithoutDuplicateWrite(t *testing.T) {
	ctx, s, user, cfg := workerStore(t)
	j := addWorkerJob(t, ctx, s, cfg, user, "processing")
	fake := &fakeOdoo{operationName: j.ExternalOperationID + "--" + j.DisplayName, evidenceExists: true}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	client, err := odoo.New(odoo.Config{URL: srv.URL, DB: "db", Username: "u", APIKey: "k", AllowedSharePointHosts: []string{"share.example"}}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err = process(ctx, cfg, s, client, upload.DevelopmentScanner{}, "worker"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Upload(ctx, j.ID, user)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" || got.EvidenceID == nil || *got.EvidenceID != 9001 || fake.writes != 0 {
		t.Fatalf("job=%+v writes=%d", got, fake.writes)
	}
}

func TestProcessRetryAfterAmbiguousExternalSuccessDoesNotDuplicateWrite(t *testing.T) {
	ctx, s, user, cfg := workerStore(t)
	j := addWorkerJob(t, ctx, s, cfg, user, "processing")
	fake := &fakeOdoo{operationName: j.ExternalOperationID + "--" + j.DisplayName, failAfterWrite: true}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()
	client, err := odoo.New(odoo.Config{URL: srv.URL, DB: "db", Username: "u", APIKey: "k", AllowedSharePointHosts: []string{"share.example"}}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err = process(ctx, cfg, s, client, upload.DevelopmentScanner{}, "worker"); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = s.DB.QueryRow(ctx, `SELECT status FROM upload_jobs WHERE id=$1`, j.ID).Scan(&status); err != nil || status != "processing" {
		t.Fatalf("first retry status=%q err=%v", status, err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE upload_jobs SET available_at=now() WHERE id=$1`, j.ID); err != nil {
		t.Fatal(err)
	}
	if err = process(ctx, cfg, s, client, upload.DevelopmentScanner{}, "worker"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Upload(ctx, j.ID, user)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "succeeded" || fake.writes != 1 {
		t.Fatalf("job=%+v writes=%d", got, fake.writes)
	}
}

func TestSweepQuarantineCleansTerminalAndOrphanPreservesActiveAndRetriesFailure(t *testing.T) {
	ctx, s, user, cfg := workerStore(t)
	terminal := addWorkerJob(t, ctx, s, cfg, user, "failed")
	active := addWorkerJob(t, ctx, s, cfg, user, "pending")
	orphan := workerUUID(t) + ".quarantine"
	orphanPath := filepath.Join(cfg.QuarantineDir, orphan)
	if err := os.WriteFile(orphanPath, []byte("orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(orphanPath, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET delete_after=now()-interval '1 second' WHERE id=$1`, terminal.ID); err != nil {
		t.Fatal(err)
	}
	if err := sweepQuarantine(ctx, cfg.QuarantineDir, s, time.Now(), 25); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(cfg.QuarantineDir, terminal.StorageKey), orphanPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("file not cleaned %s err=%v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.QuarantineDir, active.StorageKey)); err != nil {
		t.Fatalf("active file removed: %v", err)
	}
	var terminalRows int
	var terminalDeleteAfter *time.Time
	if err := s.DB.QueryRow(ctx, `SELECT count(*),max(delete_after) FROM upload_jobs WHERE id=$1`, terminal.ID).Scan(&terminalRows, &terminalDeleteAfter); err != nil || terminalRows != 1 || terminalDeleteAfter != nil {
		t.Fatalf("terminal row count=%d delete_after=%v err=%v", terminalRows, terminalDeleteAfter, err)
	}

	retry := addWorkerJob(t, ctx, s, cfg, user, "failed")
	if _, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET delete_after=now()-interval '1 second' WHERE id=$1`, retry.ID); err != nil {
		t.Fatal(err)
	}
	retryPath := filepath.Join(cfg.QuarantineDir, retry.StorageKey)
	if err := os.Remove(retryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(retryPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(retryPath, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sweepQuarantine(ctx, cfg.QuarantineDir, s, time.Now(), 25); err != nil {
		t.Fatal(err)
	}
	var token *string
	var deleteAfter time.Time
	if err := s.DB.QueryRow(ctx, `SELECT claim_token,delete_after FROM upload_jobs WHERE id=$1`, retry.ID).Scan(&token, &deleteAfter); err != nil || token != nil || !deleteAfter.After(time.Now()) {
		t.Fatalf("cleanup not retried token=%v delete_after=%v err=%v", token, deleteAfter, err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(cfg.QuarantineDir, workerUUID(t)+".quarantine")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := sweepQuarantine(ctx, cfg.QuarantineDir, s, time.Now().Add(2*time.Hour), 25); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "safe" {
		t.Fatalf("symlink target changed: %q err=%v", b, err)
	}
}

func TestValidStorageKeyRejectsTraversal(t *testing.T) {
	if validStorageKey("../x.quarantine") || validStorageKey("x.quarantine") || !validStorageKey("12345678-1234-1234-1234-123456789abc.quarantine") {
		t.Fatal("storage key validation incorrect")
	}
}

func workerUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var _ = time.Second
