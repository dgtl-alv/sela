package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}
func TestLoadDevelopment(t *testing.T) {
	c, e := Load(env(map[string]string{"APPLICATION_ID": "sela"}))
	if e != nil {
		t.Fatal(e)
	}
	if c.ApplicationID != "sela" || c.ScannerMode != "development" {
		t.Fatalf("unexpected config: %+v", c)
	}
}
func TestDefaultSessionLastsTwelveHours(t *testing.T) {
	cfg, err := Load(env(map[string]string{"APPLICATION_ID": "sela"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionIdle != 12*time.Hour || cfg.SessionAbsolute != 12*time.Hour {
		t.Fatalf("session idle=%v absolute=%v", cfg.SessionIdle, cfg.SessionAbsolute)
	}
}

func TestProductionRejectsMissing(t *testing.T) {
	_, e := Load(env(map[string]string{"APP_ENV": "production", "APPLICATION_ID": "sela"}))
	if e == nil {
		t.Fatal("expected rejection")
	}
}
func TestOdooCredentialEncryptionKeyRequiresExactly32Bytes(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	cfg, err := Load(env(map[string]string{"APPLICATION_ID": "sela", "ODOO_CREDENTIAL_ENCRYPTION_KEY": valid}))
	if err != nil || len(cfg.OdooCredentialEncryptionKey) != 32 {
		t.Fatalf("valid key rejected: len=%d err=%v", len(cfg.OdooCredentialEncryptionKey), err)
	}
	invalid := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 31)))
	if _, err = Load(env(map[string]string{"APPLICATION_ID": "sela", "ODOO_CREDENTIAL_ENCRYPTION_KEY": invalid})); err == nil {
		t.Fatal("31-byte credential key accepted")
	}
}

func TestRemoteScannerRequiresToken(t *testing.T) {
	_, err := Load(env(map[string]string{
		"APPLICATION_ID": "sela",
		"SCANNER_MODE":   "remote",
		"SCANNER_URL":    "https://scanner.internal",
	}))
	if err == nil || !strings.Contains(err.Error(), "SCANNER_TOKEN") {
		t.Fatalf("remote scanner without token error=%v", err)
	}
}

func TestProductionAcceptsSafeConfiguration(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	v := map[string]string{"APP_ENV": "production", "APP_NAME": "SELA", "APPLICATION_ID": "sela", "DATABASE_URL": "postgres://app:password@db/sela?sslmode=verify-full&application_name=sela", "PUBLIC_URL": "https://sela.internal", "GTM_CONTAINER_ID": "GTM-ABC123", "SESSION_HASH_KEY": key, "PAT_HASH_KEY": key, "WEBHOOK_ENCRYPTION_KEY": key, "ODOO_CREDENTIAL_ENCRYPTION_KEY": key, "ENTRA_TENANT_ID": "tenant-id", "ENTRA_CLIENT_ID": "client-id", "ENTRA_CLIENT_SECRET": "strong-client-secret", "ENTRA_ISSUER": "https://login.microsoftonline.com/tenant-id/v2.0", "ENTRA_AUTH_URL": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize", "ENTRA_TOKEN_URL": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token", "ENTRA_JWKS_URL": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys", "TURNSTILE_SITE_KEY": "site-production-key", "TURNSTILE_SECRET_KEY": "secret-production-key", "TURNSTILE_EXPECTED_HOSTNAMES": "sela.internal", "ODOO_URL": "https://odoo.internal", "ODOO_DB": "odoo", "ODOO_USERNAME": "service-account", "ODOO_API_KEY": "strong-api-key", "SHAREPOINT_ALLOWED_HOSTS": "tenant.sharepoint.com", "SCANNER_MODE": "remote", "SCANNER_URL": "https://scanner.internal", "SCANNER_TOKEN": "strong-scanner-token"}
	c, e := Load(env(v))
	if e != nil {
		t.Fatal(e)
	}
	if c.ScannerMode != "remote" {
		t.Fatal("scanner mode")
	}
}
func TestProductionRejectsPlaceholderScannerToken(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	v := map[string]string{"APP_ENV": "production", "APP_NAME": "SELA", "APPLICATION_ID": "sela", "DATABASE_URL": "postgres://app:strong-db-password@db/sela?sslmode=verify-full&application_name=sela", "PUBLIC_URL": "https://sela.internal", "GTM_CONTAINER_ID": "GTM-ABC123", "SESSION_HASH_KEY": key, "PAT_HASH_KEY": key, "WEBHOOK_ENCRYPTION_KEY": key, "ODOO_CREDENTIAL_ENCRYPTION_KEY": key, "ENTRA_TENANT_ID": "tenant-id", "ENTRA_CLIENT_ID": "client-id", "ENTRA_CLIENT_SECRET": "strong-client-secret", "ENTRA_ISSUER": "https://login.microsoftonline.com/tenant-id/v2.0", "ENTRA_AUTH_URL": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize", "ENTRA_TOKEN_URL": "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token", "ENTRA_JWKS_URL": "https://login.microsoftonline.com/tenant-id/discovery/v2.0/keys", "TURNSTILE_SITE_KEY": "site-production-key", "TURNSTILE_SECRET_KEY": "secret-production-key", "TURNSTILE_EXPECTED_HOSTNAMES": "sela.internal", "ODOO_URL": "https://odoo.internal", "ODOO_DB": "odoo", "SHAREPOINT_ALLOWED_HOSTS": "tenant.sharepoint.com", "SCANNER_MODE": "remote", "SCANNER_URL": "https://scanner.internal", "SCANNER_TOKEN": "replace-me"}
	_, err := Load(env(v))
	if err == nil || !strings.Contains(err.Error(), "SCANNER_TOKEN") {
		t.Fatalf("placeholder scanner token error=%v", err)
	}
}

func TestProductionRejectsHTTPAndTestConfig(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	v := map[string]string{"APP_ENV": "production", "APPLICATION_ID": "sela", "SESSION_HASH_KEY": key, "PAT_HASH_KEY": key, "WEBHOOK_ENCRYPTION_KEY": key, "ODOO_CREDENTIAL_ENCRYPTION_KEY": key, "ODOO_URL": "http://odoo.internal"}
	_, e := Load(env(v))
	if e == nil {
		t.Fatal("expected rejection")
	}
}
func TestStagingCanDisableTurnstileButProductionCannot(t *testing.T) {
	c, e := Load(env(map[string]string{"APP_ENV": "staging", "APPLICATION_ID": "sela", "TURNSTILE_ENABLED": "false"}))
	if e != nil || c.TurnstileEnabled {
		t.Fatalf("staging config: enabled=%v error=%v", c.TurnstileEnabled, e)
	}
	_, e = Load(env(map[string]string{"APP_ENV": "production", "APPLICATION_ID": "sela", "TURNSTILE_ENABLED": "false"}))
	if e == nil || !strings.Contains(e.Error(), "TURNSTILE_ENABLED") {
		t.Fatalf("production error=%v", e)
	}
}
