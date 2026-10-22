package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dgtl-alv/sela/internal/auth"
	"github.com/dgtl-alv/sela/internal/config"
	"github.com/dgtl-alv/sela/internal/database"
	"github.com/dgtl-alv/sela/internal/odoo"
	appserver "github.com/dgtl-alv/sela/internal/server"
	"github.com/dgtl-alv/sela/internal/store"
	"github.com/dgtl-alv/sela/internal/turnstile"
	"github.com/dgtl-alv/sela/internal/upload"
	"github.com/dgtl-alv/sela/internal/web"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := run(ctx); e != nil {
		slog.Error("application stopped", "error", e)
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
	httpClient := &http.Client{Timeout: 15 * time.Second}
	od, e := odoo.New(odoo.Config{URL: cfg.OdooURL, DB: cfg.OdooDB, Production: cfg.Environment == "production", AllowedSharePointHosts: cfg.SharePointHosts}, httpClient)
	if e != nil {
		return e
	}
	identity := auth.New(auth.Config{TenantID: cfg.EntraTenantID, ClientID: cfg.EntraClientID, ClientSecret: cfg.EntraClientSecret, Issuer: cfg.EntraIssuer, AuthorizationURL: cfg.EntraAuthURL, TokenURL: cfg.EntraTokenURL, JWKSURL: cfg.EntraJWKSURL, RedirectURL: cfg.PublicURL + "/auth/callback"}, httpClient)
	ts := &turnstile.Verifier{Secret: cfg.TurnstileSecretKey, URL: cfg.TurnstileVerifyURL, Hostnames: cfg.TurnstileHostnames, Client: &http.Client{Timeout: 5 * time.Second}}
	var scanner upload.Scanner = upload.DevelopmentScanner{}
	if cfg.ScannerMode == "remote" {
		scanner = upload.RemoteScanner{URL: cfg.ScannerURL, Token: cfg.ScannerToken, Client: &http.Client{Timeout: 30 * time.Second}}
	}
	st := &store.Store{DB: pool}
	ready := func(ctx context.Context) error {
		if e := pool.Ping(ctx); e != nil {
			return e
		}
		return scanner.Ready(ctx)
	}
	handler := web.New(cfg, web.Dependencies{Store: st, Identity: identity, Odoo: od, Turnstile: ts, Scanner: scanner, Ready: ready})
	srv := appserver.New(":"+cfg.Port, handler)
	ch := make(chan error, 1)
	go func() { ch <- srv.ListenAndServe() }()
	slog.Info("server started", "application_id", cfg.ApplicationID, "environment", cfg.Environment, "address", srv.Addr)
	select {
	case e := <-ch:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(c)
	}
}
