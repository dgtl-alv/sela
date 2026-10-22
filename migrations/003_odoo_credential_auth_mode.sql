BEGIN;

ALTER TABLE user_odoo_credentials
 ADD COLUMN IF NOT EXISTS auth_mode text;

UPDATE user_odoo_credentials
 SET auth_mode = 'api_token'
 WHERE auth_mode IS NULL;

ALTER TABLE user_odoo_credentials
 ALTER COLUMN auth_mode SET DEFAULT 'api_token';

ALTER TABLE user_odoo_credentials
 ALTER COLUMN auth_mode SET NOT NULL;

DO $$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM pg_constraint
  WHERE conrelid = 'user_odoo_credentials'::regclass
    AND conname = 'user_odoo_credentials_auth_mode_check'
 ) THEN
  ALTER TABLE user_odoo_credentials
   ADD CONSTRAINT user_odoo_credentials_auth_mode_check
   CHECK (auth_mode IN ('api_token','password'));
 END IF;
END $$;

INSERT INTO schema_migrations(version) VALUES (3) ON CONFLICT(version) DO NOTHING;
COMMIT;
