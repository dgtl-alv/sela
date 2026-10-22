package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/dgtl-alv/sela/internal/auth"
	"github.com/dgtl-alv/sela/internal/secure"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrIdentityReconciliationRequired = errors.New("identity reconciliation required")
var ErrUserNotAllowed = errors.New("user not allowed")
var ErrStaleOwner = errors.New("stale operation owner")
var ErrPATQuota = errors.New("active token quota reached")
var ErrSelfAdminChange = errors.New("admin cannot change own access")
var ErrLastAdmin = errors.New("at least one active admin required")

type Store struct{ DB *pgxpool.Pool }
type Session struct {
	Principal                    auth.Principal
	TokenHash, CSRFHash          []byte
	AuthenticatedAt              time.Time
	IdleExpires, AbsoluteExpires time.Time
}
type PAT struct {
	ID, Name             string
	Scopes               []string
	CreatedAt, ExpiresAt time.Time
	LastUsedAt           *time.Time
	RevokedAt            *time.Time
}
type User struct {
	ID, Email, DisplayName, Role string
	Active                       bool
	HasCredential                bool
	CreatedAt, UpdatedAt         time.Time
}
type UserCredential struct {
	Username, AuthMode string
	SecretCiphertext   []byte
	UpdatedAt          time.Time
}
type IdempotencyRecord struct {
	ActorID, Key, Method, Path, State, OwnerToken string
	BodyHash                                      []byte
	StatusCode                                    int
	ResponseBody                                  []byte
	LeaseExpires                                  time.Time
}
type UploadJob struct {
	ID, UserID, ClaimToken, ExternalOperationID string
	DiagnoseID                                  int64
	DisplayName, StorageKey, MediaType, Status  string
	ScannerEngine, ScannerVersion               string
	Size                                        int64
	SHA256                                      []byte
	EvidenceID                                  *int64
	EvidenceURL                                 string
	Attempts                                    int
	CreatedAt, UpdatedAt                        time.Time
}

type WebhookDelivery struct {
	ID, EventID, EndpointURL, EventName, ClaimToken, LeaseOwner string
	SchemaVersion, Attempts                                     int
	Occurred                                                    time.Time
	Payload, SecretCiphertext                                   []byte
}

type QuarantineCleanup struct {
	ID, StorageKey, ClaimToken string
}

type dbtx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type txKey struct{}

func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}
func (s Store) q(ctx context.Context) dbtx {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return s.DB
}
func (s Store) Begin(ctx context.Context) (pgx.Tx, error) { return s.DB.Begin(ctx) }
func (s Store) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return s.q(ctx).Exec(ctx, sql, args...)
}
func (s Store) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return s.q(ctx).Query(ctx, sql, args...)
}
func (s Store) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.q(ctx).QueryRow(ctx, sql, args...)
}
func (s Store) Ping(ctx context.Context) error { return s.DB.Ping(ctx) }

func (s Store) UpsertIdentity(ctx context.Context, issuer, tenant, subject, email, name string) (auth.Principal, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return auth.Principal{}, err
	}
	defer tx.Rollback(ctx)
	var p auth.Principal
	err = tx.QueryRow(ctx, `SELECT u.id,u.email,u.display_name,u.role FROM external_identities i JOIN users u ON u.id=i.user_id WHERE i.provider='entra' AND i.issuer=$1 AND i.subject=$2 AND i.tenant=$3 AND u.active`, issuer, subject, tenant).Scan(&p.UserID, &p.Email, &p.Name, &p.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id,email,display_name,role FROM users WHERE email=lower($1) AND active FOR UPDATE`, email).Scan(&p.UserID, &p.Email, &p.Name, &p.Role)
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.Principal{}, ErrUserNotAllowed
		}
		if err == nil {
			var existingLinks int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1`, p.UserID).Scan(&existingLinks); err != nil {
				return auth.Principal{}, err
			}
			if existingLinks != 0 {
				return auth.Principal{}, ErrIdentityReconciliationRequired
			}
			var tag pgconn.CommandTag
			tag, err = tx.Exec(ctx, `INSERT INTO external_identities(id,user_id,provider,issuer,tenant,subject) VALUES(gen_random_uuid(),$1,'entra',$2,$3,$4) ON CONFLICT(provider,issuer,subject) DO NOTHING`, p.UserID, issuer, tenant, subject)
			if err == nil && tag.RowsAffected() == 0 {
				err = tx.QueryRow(ctx, `SELECT u.id,u.email,u.display_name,u.role FROM external_identities i JOIN users u ON u.id=i.user_id WHERE i.provider='entra' AND i.issuer=$1 AND i.subject=$2 AND i.tenant=$3 AND u.active`, issuer, subject, tenant).Scan(&p.UserID, &p.Email, &p.Name, &p.Role)
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.Principal{}, ErrIdentityReconciliationRequired
				}
			}
		}
	}
	if err != nil {
		return auth.Principal{}, err
	}
	return p, tx.Commit(ctx)
}
func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (s Store) CreateUser(ctx context.Context, actorID, email, displayName, role string) (User, error) {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return createUser(ctx, tx, actorID, email, displayName, role)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	u, err := createUser(ctx, tx, actorID, email, displayName, role)
	if err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

func createUser(ctx context.Context, q dbtx, actorID, email, displayName, role string) (User, error) {
	var u User
	err := q.QueryRow(ctx, `INSERT INTO users(id,email,display_name,role) VALUES(gen_random_uuid(),lower($1),$2,$3) RETURNING id,email,display_name,role,active,created_at,updated_at`, email, displayName, role).Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,outcome) VALUES(gen_random_uuid(),$1,'user.created','user',$2,'success')`, actorID, u.ID)
	return u, err
}

func (s Store) ListUsers(ctx context.Context, limit int) ([]User, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.q(ctx).Query(ctx, `SELECT u.id,u.email,u.display_name,u.role,u.active,EXISTS(SELECT 1 FROM user_odoo_credentials c WHERE c.user_id=u.id),u.created_at,u.updated_at FROM users u ORDER BY u.email LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err = rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Active, &u.HasCredential, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s Store) UpdateUser(ctx context.Context, actorID, userID, role string, active bool) (User, error) {
	if actorID == userID && (role != "admin" || !active) {
		return User{}, ErrSelfAdminChange
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(8675309)`); err != nil {
		return User{}, err
	}
	var oldRole string
	var oldActive bool
	if err = tx.QueryRow(ctx, `SELECT role,active FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&oldRole, &oldActive); err != nil {
		return User{}, err
	}
	if oldRole == "admin" && oldActive && (role != "admin" || !active) {
		var admins int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND active`).Scan(&admins); err != nil {
			return User{}, err
		}
		if admins <= 1 {
			return User{}, ErrLastAdmin
		}
	}
	var u User
	err = tx.QueryRow(ctx, `UPDATE users SET role=$2,active=$3,updated_at=now() WHERE id=$1 RETURNING id,email,display_name,role,active,created_at,updated_at`, userID, role, active).Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	if !active {
		if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
			return User{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE personal_access_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
			return User{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,outcome,metadata) VALUES(gen_random_uuid(),$1,'user.updated','user',$2,'success',jsonb_build_object('role',$3::text,'active',$4::boolean))`, actorID, userID, role, active); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

func (s Store) PutUserCredential(ctx context.Context, userID, username string, ciphertext []byte) error {
	return s.PutUserCredentialWithMode(ctx, userID, username, "api_token", ciphertext)
}
func (s Store) PutUserCredentialWithMode(ctx context.Context, userID, username, authMode string, ciphertext []byte) error {
	if authMode != "api_token" && authMode != "password" {
		return errors.New("invalid credential auth mode")
	}
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return putUserCredential(ctx, tx, userID, username, authMode, ciphertext)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = putUserCredential(ctx, tx, userID, username, authMode, ciphertext); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func putUserCredential(ctx context.Context, q dbtx, userID, username, authMode string, ciphertext []byte) error {
	if _, err := q.Exec(ctx, `INSERT INTO user_odoo_credentials(user_id,username,auth_mode,secret_ciphertext) VALUES($1,$2,$3,$4) ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,auth_mode=excluded.auth_mode,secret_ciphertext=excluded.secret_ciphertext,updated_at=now()`, userID, username, authMode, ciphertext); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,outcome,metadata) VALUES(gen_random_uuid(),$1::uuid,'user_odoo_credential.updated','user_odoo_credential',$1::text,'success',jsonb_build_object('username',$2::text,'auth_mode',$3::text))`, userID, username, authMode)
	return err
}
func (s Store) UserCredential(ctx context.Context, userID string) (UserCredential, error) {
	var c UserCredential
	err := s.q(ctx).QueryRow(ctx, `SELECT username,auth_mode,secret_ciphertext,updated_at FROM user_odoo_credentials WHERE user_id=$1`, userID).Scan(&c.Username, &c.AuthMode, &c.SecretCiphertext, &c.UpdatedAt)
	return c, err
}
func (s Store) DeleteUserCredential(ctx context.Context, userID string) error {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return deleteUserCredential(ctx, tx, userID)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteUserCredential(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func deleteUserCredential(ctx context.Context, q dbtx, userID string) error {
	tag, err := q.Exec(ctx, `DELETE FROM user_odoo_credentials WHERE user_id=$1`, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,outcome) VALUES(gen_random_uuid(),$1::uuid,'user_odoo_credential.deleted','user_odoo_credential',$1::text,'success')`, userID)
	return err
}

func (s Store) CreateSession(ctx context.Context, p auth.Principal, tokenHash, csrfHash []byte, authenticatedAt, idle, absolute time.Time, ip string, uaHash []byte) error {
	_, err := s.q(ctx).Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,csrf_hash,created_at,authenticated_at,last_seen_at,idle_expires_at,absolute_expires_at,last_ip,user_agent_hash) VALUES(gen_random_uuid(),$1,$2,$3,$4,$4,$4,$5,$6,$7,$8)`, p.UserID, tokenHash, csrfHash, authenticatedAt, idle, absolute, nullIP(ip), uaHash)
	return err
}
func (s Store) Session(ctx context.Context, tokenHash []byte, now, idle time.Time) (Session, error) {
	var x Session
	err := s.q(ctx).QueryRow(ctx, `UPDATE sessions s SET last_seen_at=$2,idle_expires_at=LEAST($3,s.absolute_expires_at) FROM users u WHERE s.user_id=u.id AND s.token_hash=$1 AND s.revoked_at IS NULL AND s.idle_expires_at>$2 AND s.absolute_expires_at>$2 AND u.active RETURNING u.id,u.email,u.display_name,u.role,s.token_hash,s.csrf_hash,s.authenticated_at,s.idle_expires_at,s.absolute_expires_at`, tokenHash, now, idle).Scan(&x.Principal.UserID, &x.Principal.Email, &x.Principal.Name, &x.Principal.Role, &x.TokenHash, &x.CSRFHash, &x.AuthenticatedAt, &x.IdleExpires, &x.AbsoluteExpires)
	return x, err
}
func (s Store) RevokeSession(ctx context.Context, hash []byte) error {
	_, err := s.q(ctx).Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1 AND revoked_at IS NULL`, hash)
	return err
}

func (s Store) CreatePAT(ctx context.Context, userID, name string, hash []byte, scopes []string, expires time.Time) (PAT, error) {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return createPAT(ctx, tx, userID, name, hash, scopes, expires)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return PAT{}, err
	}
	defer tx.Rollback(ctx)
	p, err := createPAT(ctx, tx, userID, name, hash, scopes, expires)
	if err != nil {
		return PAT{}, err
	}
	return p, tx.Commit(ctx)
}
func createPAT(ctx context.Context, q dbtx, userID, name string, hash []byte, scopes []string, expires time.Time) (PAT, error) {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, userID); err != nil {
		return PAT{}, err
	}
	var count int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM personal_access_tokens WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now()`, userID).Scan(&count); err != nil {
		return PAT{}, err
	}
	if count >= 10 {
		return PAT{}, ErrPATQuota
	}
	var p PAT
	if err := q.QueryRow(ctx, `INSERT INTO personal_access_tokens(id,user_id,name,token_hash,scopes,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5) RETURNING id,name,scopes,created_at,expires_at,last_used_at,revoked_at`, userID, name, hash, scopes, expires).Scan(&p.ID, &p.Name, &p.Scopes, &p.CreatedAt, &p.ExpiresAt, &p.LastUsedAt, &p.RevokedAt); err != nil {
		return PAT{}, err
	}
	return p, nil
}
func (s Store) ListPATs(ctx context.Context, userID string) ([]PAT, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT id,name,scopes,created_at,expires_at,last_used_at,revoked_at FROM personal_access_tokens WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PAT{}
	for rows.Next() {
		var p PAT
		if err = rows.Scan(&p.ID, &p.Name, &p.Scopes, &p.CreatedAt, &p.ExpiresAt, &p.LastUsedAt, &p.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s Store) RevokePAT(ctx context.Context, userID, id string) error {
	tag, err := s.q(ctx).Exec(ctx, `UPDATE personal_access_tokens SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, id, userID)
	if err == nil && tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return err
}
func (s Store) AuthenticatePAT(ctx context.Context, hash []byte) (auth.Principal, error) {
	var p auth.Principal
	err := s.q(ctx).QueryRow(ctx, `SELECT u.id,u.email,u.display_name,u.role,t.scopes,t.id FROM personal_access_tokens t JOIN users u ON t.user_id=u.id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now() AND u.active`, hash).Scan(&p.UserID, &p.Email, &p.Name, &p.Role, &p.Scopes, &p.PATID)
	p.ViaPAT = true
	return p, err
}
func (s Store) TouchPAT(ctx context.Context, id, ip string) error {
	_, err := s.q(ctx).Exec(ctx, `UPDATE personal_access_tokens SET last_used_at=now(),last_used_ip=$2 WHERE id=$1`, id, nullIP(ip))
	return err
}

func (s Store) BeginIdempotency(ctx context.Context, actor, key, method, path string, hash []byte) (IdempotencyRecord, bool, error) {
	return s.beginIdempotency(ctx, s.DB, actor, key, method, path, hash)
}
func (s Store) BeginIdempotencyTx(ctx context.Context, tx pgx.Tx, actor, key, method, path string, hash []byte) (IdempotencyRecord, bool, error) {
	return s.beginIdempotency(ctx, tx, actor, key, method, path, hash)
}
func (s Store) beginIdempotency(ctx context.Context, q dbtx, actor, key, method, path string, hash []byte) (IdempotencyRecord, bool, error) {
	owner, err := secure.UUID()
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	var r IdempotencyRecord
	err = q.QueryRow(ctx, `INSERT INTO idempotency_records(id,actor_id,key,method,path,body_hash,state,owner_token,lease_expires_at,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,'processing',$6,now()+interval '30 seconds',now()+interval '24 hours') ON CONFLICT(actor_id,method,path,key) DO UPDATE SET owner_token=$6,lease_expires_at=now()+interval '30 seconds',created_at=now() WHERE idempotency_records.state='processing' AND idempotency_records.lease_expires_at<=now() AND idempotency_records.body_hash=$5 RETURNING actor_id,key,method,path,body_hash,state,owner_token,lease_expires_at,coalesce(status_code,0),coalesce(response_body,''::bytea)`, actor, key, method, path, hash, owner).Scan(&r.ActorID, &r.Key, &r.Method, &r.Path, &r.BodyHash, &r.State, &r.OwnerToken, &r.LeaseExpires, &r.StatusCode, &r.ResponseBody)
	if err == nil {
		return r, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return r, false, err
	}
	err = q.QueryRow(ctx, `SELECT actor_id,key,method,path,body_hash,state,coalesce(owner_token::text,''),coalesce(lease_expires_at,'epoch'),coalesce(status_code,0),coalesce(response_body,''::bytea) FROM idempotency_records WHERE actor_id=$1 AND method=$2 AND path=$3 AND key=$4 AND expires_at>now()`, actor, method, path, key).Scan(&r.ActorID, &r.Key, &r.Method, &r.Path, &r.BodyHash, &r.State, &r.OwnerToken, &r.LeaseExpires, &r.StatusCode, &r.ResponseBody)
	return r, false, err
}
func (s Store) CompleteIdempotency(ctx context.Context, actor, key, method, path, owner string, status int, body []byte) error {
	tag, err := s.q(ctx).Exec(ctx, `UPDATE idempotency_records SET state='complete',status_code=$6,response_body=$7,owner_token=NULL,lease_expires_at=NULL WHERE actor_id=$1 AND key=$2 AND method=$3 AND path=$4 AND owner_token=$5 AND state='processing'`, actor, key, method, path, owner, status, body)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}
func (s Store) AbandonIdempotency(ctx context.Context, actor, key, method, path, owner string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM idempotency_records WHERE actor_id=$1 AND key=$2 AND method=$3 AND path=$4 AND owner_token=$5 AND state='processing'`, actor, key, method, path, owner)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) AddUploads(ctx context.Context, jobs []UploadJob) error {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return addUploads(ctx, tx, jobs)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = addUploads(ctx, tx, jobs); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func addUploads(ctx context.Context, q dbtx, jobs []UploadJob) error {
	for _, j := range jobs {
		if j.ExternalOperationID == "" {
			j.ExternalOperationID = j.ID
		}
		if _, err := q.Exec(ctx, `INSERT INTO upload_jobs(id,user_id,diagnose_id,display_name,storage_key,media_type,byte_size,sha256,status,external_operation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)`, j.ID, j.UserID, j.DiagnoseID, j.DisplayName, j.StorageKey, j.MediaType, j.Size, j.SHA256, j.ExternalOperationID); err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{"upload_id": j.ID, "diagnose_id": j.DiagnoseID, "media_type": j.MediaType, "bytes": j.Size})
		if err != nil {
			return err
		}
		if _, err = q.Exec(ctx, `INSERT INTO domain_events(id,event_name,schema_version,aggregate_type,aggregate_id,payload) VALUES(gen_random_uuid(),'evidence.upload.queued.v1',1,'upload',$1,$2)`, j.ID, payload); err != nil {
			return err
		}
	}
	return nil
}
func (s Store) AddUpload(ctx context.Context, j UploadJob) error {
	return s.AddUploads(ctx, []UploadJob{j})
}
func (s Store) Upload(ctx context.Context, id, user string) (UploadJob, error) {
	var j UploadJob
	err := s.q(ctx).QueryRow(ctx, `SELECT id,user_id,diagnose_id,display_name,storage_key,media_type,byte_size,sha256,status,coalesce(scanner_engine,''),coalesce(scanner_version,''),evidence_id,coalesce(evidence_url,''),external_operation_id,attempts,created_at,updated_at FROM upload_jobs WHERE id=$1 AND user_id=$2`, id, user).Scan(&j.ID, &j.UserID, &j.DiagnoseID, &j.DisplayName, &j.StorageKey, &j.MediaType, &j.Size, &j.SHA256, &j.Status, &j.ScannerEngine, &j.ScannerVersion, &j.EvidenceID, &j.EvidenceURL, &j.ExternalOperationID, &j.Attempts, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}
func (s Store) ClaimUpload(ctx context.Context) (UploadJob, error) {
	token, err := secure.UUID()
	if err != nil {
		return UploadJob{}, err
	}
	var j UploadJob
	err = s.DB.QueryRow(ctx, `UPDATE upload_jobs SET status=CASE WHEN status='pending' THEN 'scanning' ELSE status END,claim_token=$1,lease_expires_at=now()+interval '2 minutes',attempts=attempts+1,updated_at=now() WHERE id=(SELECT id FROM upload_jobs WHERE status IN ('pending','scanning','processing','reconciling') AND available_at<=now() AND (claim_token IS NULL OR lease_expires_at<now()) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,user_id,diagnose_id,display_name,storage_key,media_type,byte_size,sha256,status,coalesce(scanner_engine,''),coalesce(scanner_version,''),evidence_id,coalesce(evidence_url,''),external_operation_id,claim_token,attempts,created_at,updated_at`, token).Scan(&j.ID, &j.UserID, &j.DiagnoseID, &j.DisplayName, &j.StorageKey, &j.MediaType, &j.Size, &j.SHA256, &j.Status, &j.ScannerEngine, &j.ScannerVersion, &j.EvidenceID, &j.EvidenceURL, &j.ExternalOperationID, &j.ClaimToken, &j.Attempts, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}
func (s Store) TransitionUpload(ctx context.Context, id, token, from, to, engine, version, url, last string, evidenceID *int64, delay time.Duration) error {
	return s.transitionUpload(ctx, s.DB, id, token, from, to, engine, version, url, last, evidenceID, delay)
}

func (s Store) TransitionUploadWithEvent(ctx context.Context, id, token, from, to, engine, version, url, last string, evidenceID *int64, delay time.Duration, event string, payload any) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.transitionUpload(ctx, tx, id, token, from, to, engine, version, url, last, evidenceID, delay); err != nil {
		return err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO domain_events(id,event_name,schema_version,aggregate_type,aggregate_id,payload) VALUES(gen_random_uuid(),$1,1,'upload',$2,$3)`, event, id, b); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s Store) transitionUpload(ctx context.Context, q dbtx, id, token, from, to, engine, version, url, last string, evidenceID *int64, delay time.Duration) error {
	tag, err := q.Exec(ctx, `UPDATE upload_jobs SET status=$4,scanner_engine=coalesce(NULLIF($5,''),scanner_engine),scanner_version=coalesce(NULLIF($6,''),scanner_version),evidence_url=coalesce(NULLIF($7,''),evidence_url),last_error=NULLIF($8,''),evidence_id=coalesce($9,evidence_id),available_at=now()+$10::interval,claim_token=NULL,lease_expires_at=NULL,updated_at=now(),delete_after=CASE WHEN $4 IN ('succeeded','rejected','failed') THEN now()+interval '24 hours' ELSE delete_after END WHERE id=$1 AND claim_token=$2 AND status=$3 AND lease_expires_at>now()`, id, token, from, to, engine, version, url, last, evidenceID, delay.String())
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) ClaimWebhookDelivery(ctx context.Context, owner string) (WebhookDelivery, error) {
	token, err := secure.UUID()
	if err != nil {
		return WebhookDelivery{}, err
	}
	var d WebhookDelivery
	err = s.DB.QueryRow(ctx, `UPDATE webhook_deliveries d SET status='leased',lease_owner=$1,claim_token=$2,lease_expires_at=now()+interval '1 minute',attempts=d.attempts+1 FROM webhook_endpoints w,domain_events e WHERE d.id=(SELECT d2.id FROM webhook_deliveries d2 JOIN webhook_endpoints w2 ON w2.id=d2.endpoint_id AND w2.enabled AND w2.deleted_at IS NULL WHERE d2.status IN ('pending','leased') AND d2.available_at<=now() AND (d2.lease_expires_at IS NULL OR d2.lease_expires_at<now()) ORDER BY d2.available_at FOR UPDATE OF d2 SKIP LOCKED LIMIT 1) AND w.id=d.endpoint_id AND w.enabled AND e.id=d.event_id RETURNING d.id,d.event_id,d.attempts,d.claim_token,d.lease_owner,e.event_name,e.schema_version,e.occurred_at,e.payload,w.url,w.secret_ciphertext`, owner, token).Scan(&d.ID, &d.EventID, &d.Attempts, &d.ClaimToken, &d.LeaseOwner, &d.EventName, &d.SchemaVersion, &d.Occurred, &d.Payload, &d.EndpointURL, &d.SecretCiphertext)
	return d, err
}

func (s Store) CompleteWebhookDelivery(ctx context.Context, id, token, owner string, status int) error {
	tag, err := s.DB.Exec(ctx, `UPDATE webhook_deliveries SET status='succeeded',last_status_code=$4,last_error=NULL,delivered_at=now(),lease_owner=NULL,claim_token=NULL,lease_expires_at=NULL WHERE id=$1 AND claim_token=$2 AND lease_owner=$3 AND status='leased' AND lease_expires_at>now()`, id, token, owner, status)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) DisableWebhookEndpoint(ctx context.Context, id, description string, enabled *bool) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE webhook_endpoints SET description=CASE WHEN $2='' THEN description ELSE $2 END,enabled=coalesce($3,enabled),updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id, description, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if enabled != nil && !*enabled {
		if _, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='cancelled',last_error='endpoint disabled',lease_owner=NULL,claim_token=NULL,lease_expires_at=NULL WHERE endpoint_id=$1 AND status IN ('pending','leased')`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s Store) DeleteWebhookEndpoint(ctx context.Context, id string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE webhook_endpoints SET enabled=false,deleted_at=now(),updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET status='cancelled',last_error='endpoint deleted',lease_owner=NULL,claim_token=NULL,lease_expires_at=NULL WHERE endpoint_id=$1 AND status IN ('pending','leased')`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s Store) FailWebhookDelivery(ctx context.Context, id, token, owner string, attempts, status int, safe string, delay time.Duration) error {
	terminal := attempts >= 5
	state := "pending"
	if terminal {
		state = "failed"
	}
	tag, err := s.DB.Exec(ctx, `UPDATE webhook_deliveries SET status=$4,available_at=CASE WHEN $4='pending' THEN now()+$5::interval ELSE available_at END,last_status_code=NULLIF($6,0),last_error=$7,lease_owner=NULL,claim_token=NULL,lease_expires_at=NULL WHERE id=$1 AND claim_token=$2 AND lease_owner=$3 AND status='leased' AND lease_expires_at>now()`, id, token, owner, state, delay.String(), status, safe)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) ClaimQuarantineCleanup(ctx context.Context, limit int) ([]QuarantineCleanup, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	token, err := secure.UUID()
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, `UPDATE upload_jobs SET claim_token=$1,lease_expires_at=now()+interval '2 minutes',updated_at=now() WHERE id IN (SELECT id FROM upload_jobs WHERE status IN ('succeeded','rejected','failed') AND delete_after<=now() AND (claim_token IS NULL OR lease_expires_at<now()) ORDER BY delete_after FOR UPDATE SKIP LOCKED LIMIT $2) RETURNING id,storage_key,claim_token`, token, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]QuarantineCleanup, 0, limit)
	for rows.Next() {
		var c QuarantineCleanup
		if err = rows.Scan(&c.ID, &c.StorageKey, &c.ClaimToken); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s Store) CompleteQuarantineCleanup(ctx context.Context, id, token string) error {
	tag, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET claim_token=NULL,lease_expires_at=NULL,delete_after=NULL,updated_at=now() WHERE id=$1 AND claim_token=$2 AND status IN ('succeeded','rejected','failed') AND lease_expires_at>now()`, id, token)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) RetryQuarantineCleanup(ctx context.Context, id, token string, delay time.Duration) error {
	tag, err := s.DB.Exec(ctx, `UPDATE upload_jobs SET claim_token=NULL,lease_expires_at=NULL,delete_after=now()+$3::interval,updated_at=now() WHERE id=$1 AND claim_token=$2 AND status IN ('succeeded','rejected','failed') AND lease_expires_at>now()`, id, token, delay.String())
	if err == nil && tag.RowsAffected() != 1 {
		return ErrStaleOwner
	}
	return err
}

func (s Store) UploadStorageKeys(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.DB.Query(ctx, `SELECT storage_key FROM upload_jobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, err
		}
		out[key] = struct{}{}
	}
	return out, rows.Err()
}

func (s Store) Emit(ctx context.Context, event, aggregate, id string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.q(ctx).Exec(ctx, `INSERT INTO domain_events(id,event_name,schema_version,aggregate_type,aggregate_id,payload) VALUES(gen_random_uuid(),$1,1,$2,$3,$4)`, event, aggregate, id, b)
	return err
}
func nullIP(v string) any {
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	return nil
}
func SameHash(a, b []byte) bool { return bytes.Equal(a, b) }
