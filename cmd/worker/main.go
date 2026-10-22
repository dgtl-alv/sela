package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/database"
	"github.com/dgtl-alv/sela/internal/odoo"
	"github.com/dgtl-alv/sela/internal/secure"
	"github.com/dgtl-alv/sela/internal/store"
	"github.com/dgtl-alv/sela/internal/upload"
	"github.com/dgtl-alv/sela/internal/webhook"
	"github.com/jackc/pgx/v5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := run(ctx); e != nil {
		slog.Error("worker stopped", "error", e)
		os.Exit(1)
	}
}
func run(ctx context.Context) error {
	cfg, e := config.Load(os.Getenv)
	if e != nil {
		return e
	}
	pool, e := database.Open(ctx, cfg.DatabaseURL)
	if e != nil {
		return e
	}
	defer pool.Close()
	od, e := odoo.New(odoo.Config{URL: cfg.OdooURL, DB: cfg.OdooDB, Production: cfg.Environment == "production", AllowedSharePointHosts: cfg.SharePointHosts}, &http.Client{Timeout: 30 * time.Second})
	if e != nil {
		return e
	}
	var scanner upload.Scanner = upload.DevelopmentScanner{}
	if cfg.ScannerMode == "remote" {
		scanner = upload.RemoteScanner{URL: cfg.ScannerURL, Client: &http.Client{Timeout: 30 * time.Second}}
	}
	s := store.Store{DB: pool}
	worker, e := secure.Random(12)
	if e != nil {
		return e
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if e := process(ctx, cfg, s, od, scanner, worker); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				slog.Error("upload job failed", "error", e)
			}
			if e := expandOutbox(ctx, s); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				slog.Error("outbox expansion failed", "error", e)
			}
			if e := deliverWebhook(ctx, cfg, s, worker); e != nil && !errors.Is(e, pgx.ErrNoRows) {
				slog.Error("webhook delivery failed", "error", e)
			}
			if e := sweepQuarantine(ctx, cfg.QuarantineDir, s, time.Now(), 25); e != nil {
				slog.Error("quarantine sweep failed", "error", e)
			}
		}
	}
}
func expandOutbox(ctx context.Context, s store.Store) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, `SELECT id FROM domain_events WHERE dispatched_at IS NULL ORDER BY occurred_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO webhook_deliveries(id,event_id,endpoint_id,status) SELECT gen_random_uuid(),$1,e.id,'pending' FROM webhook_endpoints e JOIN webhook_subscriptions s ON s.endpoint_id=e.id JOIN domain_events d ON d.id=$1 AND d.event_name=s.event_name WHERE e.enabled AND e.deleted_at IS NULL ON CONFLICT(event_id,endpoint_id) DO NOTHING`, id)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE domain_events SET dispatched_at=now() WHERE id=$1`, id)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func deliverWebhook(ctx context.Context, cfg config.Config, s store.Store, worker string) error {
	d, err := s.ClaimWebhookDelivery(ctx, worker)
	if err != nil {
		return err
	}
	secret, err := webhook.Decrypt(cfg.WebhookEncryptionKey, d.SecretCiphertext)
	if err != nil {
		return failDelivery(ctx, s, d, 0, "secret decryption failed")
	}
	body, err := json.Marshal(map[string]any{"id": d.EventID, "name": d.EventName, "version": d.SchemaVersion, "occurred_at": d.Occurred.UTC().Format(time.RFC3339Nano), "attempt": d.Attempts, "payload": json.RawMessage(d.Payload)})
	if err != nil {
		return err
	}
	status, sendErr := (webhook.Deliverer{Timeout: 10 * time.Second}).Deliver(ctx, d.EndpointURL, secret, body, d.EventID)
	if sendErr == nil {
		return s.CompleteWebhookDelivery(ctx, d.ID, d.ClaimToken, d.LeaseOwner, status)
	}
	return failDelivery(ctx, s, d, status, "delivery failed")
}
func failDelivery(ctx context.Context, s store.Store, d store.WebhookDelivery, status int, safe string) error {
	delay := time.Duration(1<<min(d.Attempts, 6)) * time.Minute
	return s.FailWebhookDelivery(ctx, d.ID, d.ClaimToken, d.LeaseOwner, d.Attempts, status, safe, delay)
}
func sweepQuarantine(ctx context.Context, root string, s store.Store, now time.Time, limit int) error {
	claimed, err := s.ClaimQuarantineCleanup(ctx, limit)
	if err != nil {
		return err
	}
	for _, c := range claimed {
		if !validStorageKey(c.StorageKey) {
			if err = s.RetryQuarantineCleanup(ctx, c.ID, c.ClaimToken, time.Hour); err != nil {
				return err
			}
			continue
		}
		path := filepath.Join(root, c.StorageKey)
		info, statErr := os.Lstat(path)
		if statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			statErr = errors.New("refusing symlink")
		}
		if statErr == nil {
			statErr = os.Remove(path)
		}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			if err = s.RetryQuarantineCleanup(ctx, c.ID, c.ClaimToken, time.Hour); err != nil {
				return err
			}
			continue
		}
		if err = s.CompleteQuarantineCleanup(ctx, c.ID, c.ClaimToken); err != nil {
			return err
		}
	}
	keys, err := s.UploadStorageKeys(ctx)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	removed := 0
	for _, entry := range entries {
		if removed >= limit || !validStorageKey(entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if _, active := keys[entry.Name()]; active {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < time.Hour {
			continue
		}
		if err = os.Remove(filepath.Join(root, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
		removed++
	}
	return nil
}

func validStorageKey(key string) bool {
	if filepath.Base(key) != key || key == "." || key == ".." || !strings.HasSuffix(key, ".quarantine") {
		return false
	}
	id := strings.TrimSuffix(key, ".quarantine")
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func process(ctx context.Context, cfg config.Config, s store.Store, od *odoo.Client, scanner upload.Scanner, _ string) error {
	j, err := s.ClaimUpload(ctx)
	if err != nil {
		return err
	}
	path := filepath.Join(cfg.QuarantineDir, j.StorageKey)
	scan := upload.ScanResult{}
	if j.Status == "scanning" {
		scan, err = scanner.Scan(ctx, path)
		if err != nil {
			return s.TransitionUpload(ctx, j.ID, j.ClaimToken, "scanning", "pending", "", "", "", "scanner unavailable", nil, time.Minute)
		}
		if !scan.Clean {
			return s.TransitionUploadWithEvent(ctx, j.ID, j.ClaimToken, "scanning", "rejected", scan.Engine, scan.Version, "", "file rejected by scanner", nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": j.ID, "reason": "scan_rejected"})
		}
		if err = s.TransitionUpload(ctx, j.ID, j.ClaimToken, "scanning", "processing", scan.Engine, scan.Version, "", "", nil, 0); err != nil {
			return err
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "failed", "", "", "", "quarantine read failed", nil, 0)
	}
	credential, credentialErr := s.UserCredential(ctx, j.UserID)
	if credentialErr != nil {
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "failed", "", "", "", "emica credentials missing", nil, 0)
	}
	secret, decryptErr := webhook.DecryptWithAAD(cfg.OdooCredentialEncryptionKey, credential.SecretCiphertext, []byte(j.UserID))
	if decryptErr != nil {
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "failed", "", "", "", "emica credentials unavailable", nil, 0)
	}
	odooCtx := odoo.WithCredentials(ctx, odoo.Credentials{Username: credential.Username, APIKey: string(secret)})
	ev, err := od.Upload(odooCtx, j.DiagnoseID, j.ExternalOperationID, j.DisplayName, data)
	if errors.Is(err, odoo.ErrEvidencePending) {
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "reconciling", "", "", "", "evidence pending reconciliation", nil, time.Minute)
	}
	if err != nil {
		if errors.Is(err, odoo.ErrTargetNotFound) {
			return s.TransitionUploadWithEvent(ctx, j.ID, j.ClaimToken, j.Status, "failed", "", "", "", "Target EMICA tidak ditemukan", nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": j.ID, "reason": "target_not_found"})
		}
		if errors.Is(err, odoo.ErrSuspectMasalahRequired) {
			return s.TransitionUploadWithEvent(ctx, j.ID, j.ClaimToken, j.Status, "failed", "", "", "", err.Error(), nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": j.ID, "reason": "suspect_masalah_required"})
		}
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "processing", "", "", "", "EMICA temporarily unavailable", nil, time.Minute)
	}
	if ev == nil {
		return s.TransitionUpload(ctx, j.ID, j.ClaimToken, j.Status, "reconciling", "", "", "", "evidence pending reconciliation", nil, time.Minute)
	}
	eid := ev.ID
	if err = s.TransitionUploadWithEvent(ctx, j.ID, j.ClaimToken, j.Status, "succeeded", "", "", ev.URL, "", &eid, 0, "evidence.upload.succeeded.v1", map[string]any{"upload_id": j.ID, "diagnose_id": j.DiagnoseID}); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		slog.Warn("quarantine cleanup failed", "upload_id", j.ID)
	}
	return nil
}
