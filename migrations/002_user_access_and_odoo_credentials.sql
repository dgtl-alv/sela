BEGIN;

CREATE TABLE IF NOT EXISTS user_odoo_credentials (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 username text NOT NULL CHECK(length(username) BETWEEN 1 AND 320),
 secret_ciphertext bytea NOT NULL CHECK(octet_length(secret_ciphertext) > 0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO users(id,email,display_name,role,active)
VALUES (gen_random_uuid(),'muhammad.hidayat@alvaauto.com','Muhammad Hidayat','admin',true)
ON CONFLICT(email) DO UPDATE SET role='admin',active=true,updated_at=now();

INSERT INTO schema_migrations(version) VALUES (2) ON CONFLICT(version) DO NOTHING;
COMMIT;
