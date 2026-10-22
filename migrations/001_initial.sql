BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY, email text NOT NULL, display_name text NOT NULL, role text NOT NULL DEFAULT 'technician' CHECK (role IN ('technician','admin')),
 active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT users_email_normalized CHECK (email=lower(email)), CONSTRAINT users_email_unique UNIQUE(email)
);
CREATE TABLE IF NOT EXISTS external_identities (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, provider text NOT NULL,
 issuer text NOT NULL, tenant text NOT NULL, subject text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(provider,issuer,subject)
);
CREATE INDEX IF NOT EXISTS external_identities_user_idx ON external_identities(user_id);
CREATE TABLE IF NOT EXISTS sessions (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash bytea NOT NULL UNIQUE,
 csrf_hash bytea NOT NULL, created_at timestamptz NOT NULL, authenticated_at timestamptz NOT NULL,
 last_seen_at timestamptz NOT NULL, idle_expires_at timestamptz NOT NULL,
 absolute_expires_at timestamptz NOT NULL, revoked_at timestamptz, last_ip inet, user_agent_hash bytea,
 CHECK(idle_expires_at<=absolute_expires_at), CHECK(authenticated_at<=last_seen_at)
);
CREATE INDEX IF NOT EXISTS sessions_active_idx ON sessions(token_hash) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS personal_access_tokens (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 token_hash bytea NOT NULL UNIQUE, scopes text[] NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 last_used_at timestamptz, last_used_ip inet, revoked_at timestamptz, CHECK(expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS pats_user_active_idx ON personal_access_tokens(user_id,created_at DESC) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS idempotency_records (
 id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES users(id), key text NOT NULL, method text NOT NULL, path text NOT NULL,
 body_hash bytea NOT NULL, state text NOT NULL CHECK(state IN ('processing','complete')), owner_token uuid,
 lease_expires_at timestamptz, status_code integer, response_body bytea, created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, CHECK((state='processing' AND owner_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR (state='complete' AND status_code IS NOT NULL)),
 UNIQUE(actor_id,method,path,key)
);
CREATE TABLE IF NOT EXISTS audit_events (
 id uuid PRIMARY KEY, actor_user_id uuid REFERENCES users(id), action text NOT NULL, target_type text NOT NULL,
 target_id text, outcome text NOT NULL, metadata jsonb NOT NULL DEFAULT '{}'::jsonb, request_id text,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at DESC);
CREATE TABLE IF NOT EXISTS domain_events (
 id uuid PRIMARY KEY, event_name text NOT NULL, schema_version integer NOT NULL CHECK(schema_version=1), aggregate_type text NOT NULL,
 aggregate_id text NOT NULL, payload jsonb NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now(), dispatched_at timestamptz
);
CREATE INDEX IF NOT EXISTS domain_events_outbox_idx ON domain_events(occurred_at,id) WHERE dispatched_at IS NULL;
CREATE TABLE IF NOT EXISTS webhook_endpoints (
 id uuid PRIMARY KEY, description text NOT NULL CHECK(length(description) BETWEEN 1 AND 200), url text NOT NULL,
 secret_ciphertext bytea NOT NULL, enabled boolean NOT NULL DEFAULT true, created_by uuid NOT NULL REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz
);
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
 endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE, event_name text NOT NULL,
 PRIMARY KEY(endpoint_id,event_name)
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
 id uuid PRIMARY KEY, event_id uuid NOT NULL REFERENCES domain_events(id) ON DELETE CASCADE,
 endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
 status text NOT NULL CHECK(status IN ('pending','leased','succeeded','failed','cancelled')) DEFAULT 'pending', attempts integer NOT NULL DEFAULT 0,
 available_at timestamptz NOT NULL DEFAULT now(), lease_owner text, claim_token uuid, lease_expires_at timestamptz,
 last_status_code integer, last_error text, delivered_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(event_id,endpoint_id)
);
CREATE INDEX IF NOT EXISTS webhook_delivery_claim_idx ON webhook_deliveries(status,available_at) WHERE status IN ('pending','leased');
CREATE TABLE IF NOT EXISTS upload_jobs (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), diagnose_id bigint NOT NULL CHECK(diagnose_id>0),
 display_name text NOT NULL, storage_key text NOT NULL UNIQUE, media_type text NOT NULL, byte_size bigint NOT NULL CHECK(byte_size BETWEEN 1 AND 26214400),
 sha256 bytea NOT NULL, status text NOT NULL CHECK(status IN ('pending','scanning','processing','reconciling','succeeded','rejected','failed')),
 scanner_engine text, scanner_version text, evidence_id bigint, evidence_url text, external_operation_id uuid NOT NULL UNIQUE,
 attempts integer NOT NULL DEFAULT 0, available_at timestamptz NOT NULL DEFAULT now(), claim_token uuid, lease_expires_at timestamptz, last_error text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), delete_after timestamptz
);
CREATE INDEX IF NOT EXISTS upload_jobs_claim_idx ON upload_jobs(status,available_at) WHERE status IN ('pending','scanning','processing','reconciling');
CREATE INDEX IF NOT EXISTS upload_jobs_user_idx ON upload_jobs(user_id,created_at DESC);
INSERT INTO schema_migrations(version) VALUES (1) ON CONFLICT(version) DO NOTHING;
COMMIT;
