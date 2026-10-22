package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var applicationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
var gtmIDPattern = regexp.MustCompile(`^GTM-[A-Z0-9]+$`)

type Config struct {
	Environment, AppName, ApplicationID, Port, PublicURL, DatabaseURL                                       string
	SessionHashKey, PATHashKey, WebhookEncryptionKey, OdooCredentialEncryptionKey                           []byte
	GTMContainerID                                                                                          string
	EntraTenantID, EntraClientID, EntraClientSecret, EntraIssuer, EntraAuthURL, EntraTokenURL, EntraJWKSURL string
	TurnstileSiteKey, TurnstileSecretKey                                                                    string
	TurnstileHostnames                                                                                      []string
	TurnstileVerifyURL                                                                                      string
	TurnstileEnabled                                                                                        bool
	OdooURL, OdooDB                                                                                         string
	SharePointHosts                                                                                         []string
	QuarantineDir, ScannerMode, ScannerURL, ScannerToken                                                    string
	SessionIdle, SessionAbsolute                                                                            time.Duration
}

func Load(getenv func(string) string) (Config, error) {
	turnstileEnabled, err := strconv.ParseBool(valueOr(getenv("TURNSTILE_ENABLED"), "true"))
	if err != nil {
		return Config{}, errors.New("TURNSTILE_ENABLED must be boolean")
	}
	decodeKey := func(name string) ([]byte, error) {
		raw := getenv(name)
		if raw == "" {
			return nil, nil
		}
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(b) < 32 {
			return nil, fmt.Errorf("%s must be base64 encoding of at least 32 random bytes", name)
		}
		return b, nil
	}
	sessionKey, err := decodeKey("SESSION_HASH_KEY")
	if err != nil {
		return Config{}, err
	}
	patKey, err := decodeKey("PAT_HASH_KEY")
	if err != nil {
		return Config{}, err
	}
	webhookKey, err := decodeKey("WEBHOOK_ENCRYPTION_KEY")
	if err != nil {
		return Config{}, err
	}
	credentialKey, err := decodeKey("ODOO_CREDENTIAL_ENCRYPTION_KEY")
	if err != nil {
		return Config{}, err
	}
	if len(credentialKey) != 0 && len(credentialKey) != 32 {
		return Config{}, errors.New("ODOO_CREDENTIAL_ENCRYPTION_KEY must be base64 encoding of exactly 32 random bytes")
	}
	cfg := Config{
		Environment: valueOr(getenv("APP_ENV"), "development"), AppName: valueOr(getenv("APP_NAME"), "SELA Service Evidence Uploader"),
		ApplicationID: getenv("APPLICATION_ID"), Port: valueOr(getenv("PORT"), "8080"), PublicURL: valueOr(getenv("PUBLIC_URL"), "http://localhost:8080"), DatabaseURL: getenv("DATABASE_URL"),
		SessionHashKey: sessionKey, PATHashKey: patKey, WebhookEncryptionKey: webhookKey, OdooCredentialEncryptionKey: credentialKey, GTMContainerID: getenv("GTM_CONTAINER_ID"),
		EntraTenantID: getenv("ENTRA_TENANT_ID"), EntraClientID: getenv("ENTRA_CLIENT_ID"), EntraClientSecret: getenv("ENTRA_CLIENT_SECRET"),
		EntraIssuer: getenv("ENTRA_ISSUER"), EntraAuthURL: getenv("ENTRA_AUTH_URL"), EntraTokenURL: getenv("ENTRA_TOKEN_URL"), EntraJWKSURL: getenv("ENTRA_JWKS_URL"),
		TurnstileSiteKey: getenv("TURNSTILE_SITE_KEY"), TurnstileSecretKey: getenv("TURNSTILE_SECRET_KEY"), TurnstileHostnames: split(getenv("TURNSTILE_EXPECTED_HOSTNAMES")),
		TurnstileVerifyURL: valueOr(getenv("TURNSTILE_VERIFY_URL"), "https://challenges.cloudflare.com/turnstile/v0/siteverify"), TurnstileEnabled: turnstileEnabled,
		OdooURL: getenv("ODOO_URL"), OdooDB: getenv("ODOO_DB"),
		SharePointHosts: split(getenv("SHAREPOINT_ALLOWED_HOSTS")), QuarantineDir: valueOr(getenv("QUARANTINE_DIR"), "/var/lib/sela/quarantine"),
		ScannerMode: valueOr(getenv("SCANNER_MODE"), "development"), ScannerURL: getenv("SCANNER_URL"), ScannerToken: getenv("SCANNER_TOKEN"), SessionIdle: 12 * time.Hour, SessionAbsolute: 12 * time.Hour,
	}
	if !applicationIDPattern.MatchString(cfg.ApplicationID) {
		return Config{}, errors.New("APPLICATION_ID must use lowercase letters, numbers, and hyphens")
	}
	if cfg.GTMContainerID != "" && !gtmIDPattern.MatchString(cfg.GTMContainerID) {
		return Config{}, errors.New("GTM_CONTAINER_ID has invalid format")
	}
	if _, err := strconv.Atoi(cfg.Port); err != nil {
		return Config{}, errors.New("PORT must be numeric")
	}
	if cfg.ScannerMode == "remote" && strings.TrimSpace(cfg.ScannerToken) == "" {
		return Config{}, errors.New("SCANNER_TOKEN is required when SCANNER_MODE=remote")
	}
	if cfg.Environment == "production" {
		if err := validateProduction(cfg); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func validateProduction(c Config) error {
	if !c.TurnstileEnabled {
		return errors.New("TURNSTILE_ENABLED must be true in production")
	}
	required := map[string]string{"APP_NAME": c.AppName, "APPLICATION_ID": c.ApplicationID, "DATABASE_URL": c.DatabaseURL, "PUBLIC_URL": c.PublicURL, "GTM_CONTAINER_ID": c.GTMContainerID, "ENTRA_TENANT_ID": c.EntraTenantID, "ENTRA_CLIENT_ID": c.EntraClientID, "ENTRA_CLIENT_SECRET": c.EntraClientSecret, "ENTRA_ISSUER": c.EntraIssuer, "ENTRA_AUTH_URL": c.EntraAuthURL, "ENTRA_TOKEN_URL": c.EntraTokenURL, "ENTRA_JWKS_URL": c.EntraJWKSURL, "TURNSTILE_SITE_KEY": c.TurnstileSiteKey, "TURNSTILE_SECRET_KEY": c.TurnstileSecretKey, "ODOO_URL": c.OdooURL, "ODOO_DB": c.OdooDB, "SCANNER_URL": c.ScannerURL}
	for k, v := range required {
		if strings.TrimSpace(v) == "" || placeholder(v) {
			return fmt.Errorf("%s is missing or placeholder", k)
		}
	}
	if len(c.SessionHashKey) < 32 || len(c.PATHashKey) < 32 || len(c.WebhookEncryptionKey) != 32 || len(c.OdooCredentialEncryptionKey) != 32 {
		return errors.New("production cryptographic keys are missing or invalid")
	}
	if !gtmIDPattern.MatchString(c.GTMContainerID) {
		return errors.New("GTM_CONTAINER_ID has invalid format")
	}
	for name, raw := range map[string]string{"PUBLIC_URL": c.PublicURL, "ODOO_URL": c.OdooURL, "ENTRA_ISSUER": c.EntraIssuer, "ENTRA_AUTH_URL": c.EntraAuthURL, "ENTRA_TOKEN_URL": c.EntraTokenURL, "ENTRA_JWKS_URL": c.EntraJWKSURL, "TURNSTILE_VERIFY_URL": c.TurnstileVerifyURL, "SCANNER_URL": c.ScannerURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s must be an HTTPS URL", name)
		}
	}
	u, e := url.Parse(c.DatabaseURL)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return errors.New("DATABASE_URL must be PostgreSQL URL")
	}
	if u.Query().Get("sslmode") == "" || u.Query().Get("sslmode") == "disable" {
		return errors.New("DATABASE_URL must enable TLS in production")
	}
	if u.Query().Get("application_name") != c.ApplicationID {
		return errors.New("DATABASE_URL application_name must equal APPLICATION_ID")
	}
	if len(c.TurnstileHostnames) == 0 {
		return errors.New("TURNSTILE_EXPECTED_HOSTNAMES is required")
	}
	for _, h := range c.TurnstileHostnames {
		if strings.Contains(h, "localhost") {
			return errors.New("localhost Turnstile hostname forbidden in production")
		}
	}
	if strings.Contains(strings.ToLower(c.TurnstileSiteKey), "test") || strings.Contains(strings.ToLower(c.TurnstileSecretKey), "test") {
		return errors.New("Turnstile test keys forbidden in production")
	}
	if c.ScannerMode != "remote" {
		return errors.New("SCANNER_MODE must be remote in production")
	}
	if placeholder(c.ScannerToken) {
		return errors.New("SCANNER_TOKEN is missing or placeholder")
	}
	if len(c.SharePointHosts) == 0 {
		return errors.New("SHAREPOINT_ALLOWED_HOSTS is required")
	}
	return nil
}

func placeholder(v string) bool {
	l := strings.ToLower(v)
	for _, x := range []string{"change-me", "replace-me", "example.com", "***", "development-only", "your-"} {
		if strings.Contains(l, x) {
			return true
		}
	}
	return false
}
func split(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func valueOr(v, f string) string {
	if v == "" {
		return f
	}
	return v
}
func KeyID(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[:6])
}
