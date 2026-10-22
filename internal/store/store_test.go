package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testStore(t *testing.T) (context.Context, Store, string) {
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
	actorID := testUUID(t)
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Store test')`, actorID, actorID+"@example.test"); err != nil {
		t.Fatalf("database must have current migrations: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, actorID) })
	return ctx, Store{DB: pool}, actorID
}

func TestPostgresIdempotencyLeaseReplayMismatchAndPathIsolation(t *testing.T) {
	ctx, s, actorID := testStore(t)
	key := "test-" + testUUID(t)
	hash := []byte("body hash")
	first, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/api/v1/test", hash)
	if err != nil || !created || first.State != "processing" {
		t.Fatalf("begin: created=%v rec=%+v err=%v", created, first, err)
	}
	inflight, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/api/v1/test", hash)
	if err != nil || created || inflight.State != "processing" || !bytes.Equal(inflight.BodyHash, hash) {
		t.Fatalf("in-flight replay: created=%v rec=%+v err=%v", created, inflight, err)
	}
	if !bytes.Equal(inflight.BodyHash, hash) || bytes.Equal(inflight.BodyHash, []byte("different")) {
		t.Fatal("request mismatch evidence failed")
	}
	other, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/api/v1/other", []byte("different"))
	if err != nil || !created || other.Path != "/api/v1/other" {
		t.Fatalf("path isolation: created=%v rec=%+v err=%v", created, other, err)
	}
	body := []byte(`{"ok":true}`)
	if err = s.CompleteIdempotency(ctx, actorID, key, "POST", "/api/v1/test", first.OwnerToken, 201, body); err != nil {
		t.Fatal(err)
	}
	replay, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/api/v1/test", hash)
	if err != nil || created || replay.State != "complete" || replay.StatusCode != 201 || !bytes.Equal(replay.ResponseBody, body) {
		t.Fatalf("exact replay: created=%v rec=%+v err=%v", created, replay, err)
	}
}

func TestPostgresIdempotencyExpiryTakeoverRejectsStaleOwner(t *testing.T) {
	ctx, s, actorID := testStore(t)
	key := "takeover-" + testUUID(t)
	first, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/takeover", []byte("one"))
	if err != nil || !created {
		t.Fatalf("first begin: %v %v", created, err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE idempotency_records SET lease_expires_at=now()-interval '1 second' WHERE actor_id=$1 AND key=$2`, actorID, key); err != nil {
		t.Fatal(err)
	}
	mismatch, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/takeover", []byte("two"))
	if err != nil || created || !bytes.Equal(mismatch.BodyHash, []byte("one")) {
		t.Fatalf("expired mismatch: created=%v rec=%+v err=%v", created, mismatch, err)
	}
	second, created, err := s.BeginIdempotency(ctx, actorID, key, "POST", "/takeover", []byte("one"))
	if err != nil || !created || second.OwnerToken == first.OwnerToken || !bytes.Equal(second.BodyHash, []byte("one")) {
		t.Fatalf("takeover: created=%v first=%+v second=%+v err=%v", created, first, second, err)
	}
	if err = s.CompleteIdempotency(ctx, actorID, key, "POST", "/takeover", first.OwnerToken, 200, []byte("stale")); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale completion err=%v", err)
	}
	if err = s.CompleteIdempotency(ctx, actorID, key, "POST", "/takeover", second.OwnerToken, 202, []byte("winner")); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresIdempotencyCrashRollbackAndAtomicBusinessCommit(t *testing.T) {
	ctx, s, actorID := testStore(t)
	key := "crash-" + testUUID(t)
	tx, err := s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rec, created, err := s.BeginIdempotencyTx(ctx, tx, actorID, key, "POST", "/atomic", []byte("body"))
	if err != nil || !created {
		t.Fatalf("begin tx: %v %v", created, err)
	}
	txctx := WithTx(ctx, tx)
	if _, err = s.Exec(txctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,outcome) VALUES(gen_random_uuid(),$1,'test','test','ok')`, actorID); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteIdempotency(txctx, actorID, key, "POST", "/atomic", rec.OwnerToken, 200, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var records, events int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND key=$2`, actorID, key).Scan(&records)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_user_id=$1`, actorID).Scan(&events)
	if records != 0 || events != 0 {
		t.Fatalf("crash rollback leaked records=%d events=%d", records, events)
	}

	tx, err = s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rec, created, err = s.BeginIdempotencyTx(ctx, tx, actorID, key, "POST", "/atomic", []byte("body"))
	if err != nil || !created {
		t.Fatalf("retry begin: %v %v", created, err)
	}
	txctx = WithTx(ctx, tx)
	_, err = s.Exec(txctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,outcome) VALUES(gen_random_uuid(),$1,'test','test','ok')`, actorID)
	if err == nil {
		err = s.CompleteIdempotency(txctx, actorID, key, "POST", "/atomic", rec.OwnerToken, 200, []byte("ok"))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM idempotency_records WHERE actor_id=$1 AND key=$2 AND state='complete'`, actorID, key).Scan(&records)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_user_id=$1`, actorID).Scan(&events)
	if records != 1 || events != 1 {
		t.Fatalf("atomic commit records=%d events=%d", records, events)
	}
}

func TestPostgresConcurrentPATQuotaNeverExceedsTen(t *testing.T) {
	ctx, s, actorID := testStore(t)
	const attempts = 30
	start := make(chan struct{})
	var ok, quota, unexpected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := s.CreatePAT(ctx, actorID, fmt.Sprintf("token-%d", i), []byte(fmt.Sprintf("hash-%s-%d", actorID, i)), []string{"services:read"}, time.Now().Add(time.Hour))
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrPATQuota):
				quota.Add(1)
			default:
				unexpected.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	var count int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()`, actorID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if ok.Load() != 10 || quota.Load() != attempts-10 || unexpected.Load() != 0 || count != 10 {
		t.Fatalf("ok=%d quota=%d unexpected=%d db=%d", ok.Load(), quota.Load(), unexpected.Load(), count)
	}
}

func TestPostgresEntraIdentityRequiresAllowlistedUser(t *testing.T) {
	ctx, s, actorID := testStore(t)
	email := actorID + "@example.test"

	p, err := s.UpsertIdentity(ctx, "issuer", "tenant", "first-subject", email, "Allowed user")
	if err != nil || p.UserID != actorID || p.Email != email {
		t.Fatalf("allowlisted identity: principal=%+v err=%v", p, err)
	}
	var links int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1`, actorID).Scan(&links); err != nil || links != 1 {
		t.Fatalf("links=%d err=%v", links, err)
	}

	_, err = s.UpsertIdentity(ctx, "issuer", "tenant", "unknown-subject", "unknown-"+email, "Unknown")
	if !errors.Is(err, ErrUserNotAllowed) {
		t.Fatalf("unknown user error=%v", err)
	}
}

func TestPostgresEntraIdentityDoesNotRebindExistingUserByEmail(t *testing.T) {
	ctx, s, actorID := testStore(t)
	email := actorID + "@example.test"
	if _, err := s.UpsertIdentity(ctx, "issuer", "tenant", "first-subject", email, "Allowed user"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertIdentity(ctx, "issuer", "tenant", "second-subject", email, "Different identity"); !errors.Is(err, ErrIdentityReconciliationRequired) {
		t.Fatalf("second subject error=%v", err)
	}
	var links int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1`, actorID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Fatalf("identity links=%d", links)
	}
}

func TestPostgresEntraConcurrentFirstLoginCreatesOneIdentity(t *testing.T) {
	ctx, s, actorID := testStore(t)
	email := actorID + "@example.test"
	const attempts = 20
	start := make(chan struct{})
	var allowed, reconciled, unexpected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.UpsertIdentity(ctx, "issuer", "tenant", "same-subject", email, "Allowed")
			switch {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, ErrIdentityReconciliationRequired):
				reconciled.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	var links int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1`, actorID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if allowed.Load() == 0 || unexpected.Load() != 0 || links != 1 {
		t.Fatalf("allowed=%d reconciled=%d unexpected=%d links=%d", allowed.Load(), reconciled.Load(), unexpected.Load(), links)
	}
}

func TestPostgresAdminCreatesListsAndUpdatesAllowlistedUsers(t *testing.T) {
	ctx, s, adminID := testStore(t)
	if _, err := s.DB.Exec(ctx, `UPDATE users SET role='admin' WHERE id=$1`, adminID); err != nil {
		t.Fatal(err)
	}
	email := testUUID(t) + "@example.test"
	created, err := s.CreateUser(ctx, adminID, email, "New User", "technician")
	if err != nil || created.Email != email || !created.Active || created.Role != "technician" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	users, err := s.ListUsers(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, user := range users {
		if user.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("created user missing from list")
	}
	updated, err := s.UpdateUser(ctx, adminID, created.ID, "admin", false)
	if err != nil || updated.Role != "admin" || updated.Active {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	var sessions, pats int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, created.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL`, created.ID).Scan(&pats); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || pats != 0 {
		t.Fatalf("active credentials remain sessions=%d pats=%d", sessions, pats)
	}
}

func TestPostgresAdminCannotDisableSelfOrLastAdmin(t *testing.T) {
	ctx, s, adminID := testStore(t)
	if _, err := s.DB.Exec(ctx, `UPDATE users SET role='technician' WHERE role='admin' AND id<>$1`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `UPDATE users SET role='admin' WHERE id=$1`, adminID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(ctx, `UPDATE users SET role='admin',active=true WHERE email='muhammad.hidayat@alvaauto.com'`)
	})
	if _, err := s.UpdateUser(ctx, adminID, adminID, "technician", true); !errors.Is(err, ErrSelfAdminChange) {
		t.Fatalf("self demotion error=%v", err)
	}
	if _, err := s.UpdateUser(ctx, adminID, adminID, "admin", false); !errors.Is(err, ErrSelfAdminChange) {
		t.Fatalf("self disable error=%v", err)
	}
	technician := testUUID(t)
	if _, err := s.DB.Exec(ctx, `INSERT INTO users(id,email,display_name) VALUES($1,$2,'Operator')`, technician, technician+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateUser(ctx, technician, adminID, "technician", true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demotion error=%v", err)
	}
}

func TestPostgresUserCredentialRoundTripAndDelete(t *testing.T) {
	ctx, s, userID := testStore(t)
	cipher := []byte("encrypted credential")
	if err := s.PutUserCredentialWithMode(ctx, userID, "login@example.test", "password", cipher); err != nil {
		t.Fatal(err)
	}
	credential, err := s.UserCredential(ctx, userID)
	if err != nil || credential.Username != "login@example.test" || credential.AuthMode != "password" || !bytes.Equal(credential.SecretCiphertext, cipher) {
		t.Fatalf("credential=%+v err=%v", credential, err)
	}
	if err = s.PutUserCredentialWithMode(ctx, userID, "login@example.test", "invalid", cipher); err == nil {
		t.Fatal("invalid auth mode accepted")
	}
	if err = s.DeleteUserCredential(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UserCredential(ctx, userID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted credential error=%v", err)
	}
}

func TestPostgresUserCredentialChangesAreAuditedWithoutSecret(t *testing.T) {
	ctx, s, userID := testStore(t)
	secret := []byte("ciphertext-must-not-appear-in-audit")
	if err := s.PutUserCredential(ctx, userID, "login@example.test", secret); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUserCredential(ctx, userID); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query(ctx, `SELECT action,metadata::text FROM audit_events WHERE actor_user_id=$1 AND target_type='user_odoo_credential' ORDER BY created_at`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, metadata string
		if err = rows.Scan(&action, &metadata); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(metadata, string(secret)) {
			t.Fatal("credential secret leaked into audit metadata")
		}
		actions = append(actions, action)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(actions) != "[user_odoo_credential.updated user_odoo_credential.deleted]" {
		t.Fatalf("audit actions=%v", actions)
	}
}

func TestPostgresCreateUserAndAuditAreAtomic(t *testing.T) {
	ctx, s, adminID := testStore(t)
	email := testUUID(t) + "@example.test"
	if _, err := s.DB.Exec(ctx, `CREATE OR REPLACE FUNCTION sela_test_reject_user_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='user.created' THEN RAISE EXCEPTION 'simulated audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER sela_test_reject_user_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION sela_test_reject_user_audit()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_reject_user_audit ON audit_events; DROP FUNCTION IF EXISTS sela_test_reject_user_audit()`)
	})
	if _, err := s.CreateUser(ctx, adminID, email, "Atomic User", "technician"); err == nil {
		t.Fatal("expected audit failure")
	}
	var count int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("user persisted without audit: count=%d", count)
	}
}

func TestPostgresCredentialAndAuditAreAtomic(t *testing.T) {
	ctx, s, userID := testStore(t)
	if _, err := s.DB.Exec(ctx, `CREATE OR REPLACE FUNCTION sela_test_reject_credential_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='user_odoo_credential.updated' THEN RAISE EXCEPTION 'simulated audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER sela_test_reject_credential_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION sela_test_reject_credential_audit()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_reject_credential_audit ON audit_events; DROP FUNCTION IF EXISTS sela_test_reject_credential_audit()`)
	})
	if err := s.PutUserCredential(ctx, userID, "login@example.test", []byte("ciphertext")); err == nil {
		t.Fatal("expected audit failure")
	}
	if _, err := s.UserCredential(ctx, userID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("credential persisted without audit: %v", err)
	}
}

func TestPostgresUploadClaimTokenStaleCompletionAndLeaseReclaim(t *testing.T) {
	ctx, s, actorID := testStore(t)
	id := testUUID(t)
	if err := s.AddUpload(ctx, UploadJob{ID: id, UserID: actorID, DiagnoseID: 1, DisplayName: "x.webp", StorageKey: id + ".quarantine", MediaType: "image/webp", Size: 1, SHA256: []byte("hash"), ExternalOperationID: id}); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimUpload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != id || first.ClaimToken == "" || first.Status != "scanning" {
		t.Fatalf("first claim=%+v", first)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE upload_jobs SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimUpload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != id || second.ClaimToken == first.ClaimToken || second.Attempts != 2 {
		t.Fatalf("reclaim first=%+v second=%+v", first, second)
	}
	if err = s.TransitionUpload(ctx, id, first.ClaimToken, "scanning", "processing", "", "", "", "", nil, 0); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale transition err=%v", err)
	}
	if err = s.TransitionUpload(ctx, id, second.ClaimToken, "scanning", "processing", "scanner", "1", "", "", nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE upload_jobs SET claim_token=$2,lease_expires_at=now()+interval '2 minutes' WHERE id=$1`, id, testUUID(t)); err != nil {
		t.Fatal(err)
	}
	var token string
	if err = s.DB.QueryRow(ctx, `SELECT claim_token FROM upload_jobs WHERE id=$1`, id).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if err = s.TransitionUpload(ctx, id, token, "processing", "reconciling", "", "", "", "pending", nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := s.Upload(ctx, id, actorID)
	if err != nil || got.ScannerEngine != "scanner" || got.ScannerVersion != "1" {
		t.Fatalf("scanner metadata lost job=%+v err=%v", got, err)
	}
}

func TestPostgresWebhookClaimTakeoverRejectsStaleOwnerAndSkipsDisabled(t *testing.T) {
	ctx, s, actorID := testStore(t)
	insertDelivery := func(enabled bool) string {
		t.Helper()
		endpoint, event, delivery := testUUID(t), testUUID(t), testUUID(t)
		if _, err := s.DB.Exec(ctx, `INSERT INTO webhook_endpoints(id,description,url,secret_ciphertext,created_by,enabled) VALUES($1,'test','https://example.com/hook','x',$2,$3)`, endpoint, actorID, enabled); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(ctx, `INSERT INTO domain_events(id,event_name,schema_version,aggregate_type,aggregate_id,payload) VALUES($1::uuid,'pat.created.v1',1,'pat',$2,'{}')`, event, event); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(ctx, `INSERT INTO webhook_deliveries(id,event_id,endpoint_id) VALUES($1,$2,$3)`, delivery, event, endpoint); err != nil {
			t.Fatal(err)
		}
		return delivery
	}
	disabled := insertDelivery(false)
	enabled := insertDelivery(true)
	first, err := s.ClaimWebhookDelivery(ctx, "worker-a")
	if err != nil || first.ID != enabled || first.ClaimToken == "" {
		t.Fatalf("first claim=%+v err=%v", first, err)
	}
	if _, err = s.DB.Exec(ctx, `UPDATE webhook_deliveries SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, enabled); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimWebhookDelivery(ctx, "worker-b")
	if err != nil || second.ID != enabled || second.ClaimToken == first.ClaimToken {
		t.Fatalf("takeover=%+v err=%v", second, err)
	}
	if err = s.CompleteWebhookDelivery(ctx, first.ID, first.ClaimToken, first.LeaseOwner, 200); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale complete err=%v", err)
	}
	if err = s.FailWebhookDelivery(ctx, first.ID, first.ClaimToken, first.LeaseOwner, first.Attempts, 500, "stale", time.Minute); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale retry err=%v", err)
	}
	if err = s.CompleteWebhookDelivery(ctx, second.ID, second.ClaimToken, second.LeaseOwner, 204); err != nil {
		t.Fatal(err)
	}
	var disabledStatus string
	if err = s.DB.QueryRow(ctx, `SELECT status FROM webhook_deliveries WHERE id=$1`, disabled).Scan(&disabledStatus); err != nil || disabledStatus != "pending" {
		t.Fatalf("disabled status=%q err=%v", disabledStatus, err)
	}
}

func TestPostgresDisableAndDeleteCancelPendingDeliveries(t *testing.T) {
	ctx, s, actorID := testStore(t)
	makeEndpoint := func() (string, string) {
		t.Helper()
		endpoint, event, delivery := testUUID(t), testUUID(t), testUUID(t)
		if _, err := s.DB.Exec(ctx, `INSERT INTO webhook_endpoints(id,description,url,secret_ciphertext,created_by) VALUES($1,'test','https://example.com/hook','x',$2)`, endpoint, actorID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(ctx, `INSERT INTO domain_events(id,event_name,schema_version,aggregate_type,aggregate_id,payload) VALUES($1,'pat.created.v1',1,'pat',$2,'{}')`, event, event); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(ctx, `INSERT INTO webhook_deliveries(id,event_id,endpoint_id) VALUES($1,$2,$3)`, delivery, event, endpoint); err != nil {
			t.Fatal(err)
		}
		return endpoint, delivery
	}
	disabledEndpoint, disabledDelivery := makeEndpoint()
	no := false
	if err := s.DisableWebhookEndpoint(ctx, disabledEndpoint, "", &no); err != nil {
		t.Fatal(err)
	}
	deletedEndpoint, deletedDelivery := makeEndpoint()
	if err := s.DeleteWebhookEndpoint(ctx, deletedEndpoint); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range []string{disabledDelivery, deletedDelivery} {
		var status string
		if err := s.DB.QueryRow(ctx, `SELECT status FROM webhook_deliveries WHERE id=$1`, delivery).Scan(&status); err != nil || status != "cancelled" {
			t.Fatalf("delivery=%s status=%q err=%v", delivery, status, err)
		}
	}
	var deletedAt *time.Time
	if err := s.DB.QueryRow(ctx, `SELECT deleted_at FROM webhook_endpoints WHERE id=$1`, deletedEndpoint).Scan(&deletedAt); err != nil || deletedAt == nil {
		t.Fatalf("soft delete missing deleted_at=%v err=%v", deletedAt, err)
	}
}

func TestPostgresUploadTransitionAndEventRollbackAndStaleOwner(t *testing.T) {
	ctx, s, actorID := testStore(t)
	id := testUUID(t)
	if err := s.AddUpload(ctx, UploadJob{ID: id, UserID: actorID, DiagnoseID: 1, DisplayName: "x.webp", StorageKey: id + ".quarantine", MediaType: "image/webp", Size: 1, SHA256: []byte("hash"), ExternalOperationID: id}); err != nil {
		t.Fatal(err)
	}
	claim := testUUID(t)
	if _, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET status='scanning',claim_token=$2,lease_expires_at=now()+interval '2 minutes' WHERE id=$1`, id, claim); err != nil {
		t.Fatal(err)
	}
	job := UploadJob{ID: id, ClaimToken: claim}
	var err error
	if _, err = s.DB.Exec(ctx, `CREATE OR REPLACE FUNCTION sela_test_reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.aggregate_id=$q$`+id+`$q$ AND NEW.event_name='evidence.upload.failed.v1' THEN RAISE EXCEPTION 'forced event failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER sela_test_reject_event BEFORE INSERT ON domain_events FOR EACH ROW EXECUTE FUNCTION sela_test_reject_event()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.DB.Exec(ctx, `DROP TRIGGER IF EXISTS sela_test_reject_event ON domain_events; DROP FUNCTION IF EXISTS sela_test_reject_event()`)
	})
	err = s.TransitionUploadWithEvent(ctx, id, job.ClaimToken, "scanning", "rejected", "scanner", "1", "", "rejected", nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": id})
	if err == nil {
		t.Fatal("forced event failure accepted")
	}
	var status, token string
	if err = s.DB.QueryRow(ctx, `SELECT status,claim_token FROM upload_jobs WHERE id=$1`, id).Scan(&status, &token); err != nil || status != "scanning" || token != job.ClaimToken {
		t.Fatalf("transition leaked status=%q token=%q err=%v", status, token, err)
	}
	if _, err = s.DB.Exec(ctx, `DROP TRIGGER sela_test_reject_event ON domain_events`); err != nil {
		t.Fatal(err)
	}
	if err = s.TransitionUploadWithEvent(ctx, id, testUUID(t), "scanning", "rejected", "scanner", "1", "", "rejected", nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": id}); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale owner err=%v", err)
	}
	if err = s.TransitionUploadWithEvent(ctx, id, job.ClaimToken, "scanning", "rejected", "scanner", "1", "", "rejected", nil, 0, "evidence.upload.failed.v1", map[string]any{"upload_id": id}); err != nil {
		t.Fatal(err)
	}
	var events int
	if err = s.DB.QueryRow(ctx, `SELECT count(*) FROM domain_events WHERE aggregate_id=$1 AND event_name='evidence.upload.failed.v1'`, id).Scan(&events); err != nil || events != 1 {
		t.Fatalf("events=%d err=%v", events, err)
	}
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

var _ = pgx.ErrNoRows

func testUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
