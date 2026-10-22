# Compliance Matrix

Canonical policy: `dgtl-alv/alva-web-app-build@ca02a14681ea01250afa3b0bee624e2ac40738d9`.
Imported template: `dgtl-alv/alva-go-web-app-template@e66504189bee618228bf18f70bb05c55673b055c`.

| Policy area | Implementation/evidence | Status |
|---|---|---|
| Bare Go/PostgreSQL/SSR | `cmd/`, `internal/web`, `internal/database`, `go.mod` | Implemented |
| Entra code+PKCE and claim/JWKS checks | `internal/auth`, `/auth/*`; JWKS/claims tests | Implemented; live tenant gate |
| UUID identity mapping/session lifecycle | migration, `internal/auth`, `internal/store` | Implemented: unknown Entra subjects never attach by matching email; collisions require explicit reconciliation; sessions record `authenticated_at` |
| Default-deny roles/record checks | `internal/web`, Odoo target reread | Partial: service authorization treats every active technician/admin as allowed; browser and worker reject missing Odoo targets, but no finer Odoo ownership rule is available |
| Odoo bounded XML-RPC | `internal/odoo` | Implemented; live contract gate |
| Legacy suspect bypass | Not implemented; fail closed, documented | Intentionally disabled |
| Secure upload/quarantine/scanner/job | `internal/upload`, worker, migration | Partial: bounds/type/private quarantine/scanner flow, claim-safe atomic events, scanner metadata preservation, bounded terminal/orphan cleanup, active-file preservation, symlink refusal, and cleanup retry implemented; image re-encoding, quotas, and scanner isolation remain deployment gaps |
| Versioned API/stable errors/PAT | `internal/web`, `internal/store`, `docs/openapi.yaml` | Partial: strict JSON errors, scopes, expiry, revocation, recent-auth and cookie-only PAT lifecycle exist; browser metadata UI remains limited |
| Idempotency/pagination | schema, API limit handling | Implemented for API mutations: canonical fingerprint, short owner lease, stale-owner checks, replay response, and business mutation plus response commit in one PostgreSQL transaction |
| Events/outbox/catalog/schema | migration, `docs/event-catalog.yaml`, `docs/events` | Partial: upload queue events commit atomically with all request jobs and worker outbox expansion exists; PAT/admin audit events and schema validation are not wired |
| Webhook signing/SSRF/retry/encryption | `internal/webhook`, worker | Partial: core delivery and recent-auth cookie-only admin mutation enforcement exist; admin audit and subscription update remain gaps |
| Turnstile/GTM/CSP | `internal/turnstile`, shared templates/middleware | Implemented; live keys/visual brand gate |
| CSRF/origin/headers/request IDs/logs/rate limits | `internal/web` | Partial: browser forms protected and headers/request IDs present; cookie-authenticated API/admin mutations, rate limiting, and complete structured access/audit logs remain gaps |
| Health/readiness | `/healthz`, `/readyz` | Implemented for PostgreSQL/Odoo/scanner; no active Entra/Turnstile/GTM probe by design |
| Hardened image/Compose web+worker | `Dockerfile`, `docker-compose.yml` | Implemented |
| Production config rejection | `internal/config` tests | Implemented |
| Operations/security/API docs | `README.md`, `SECURITY.md`, `docs/` | Implemented with known gaps disclosed |
| CI | `.github/workflows/ci.yml` | Implemented |
| Automated test breadth | package tests | Partial: auth claims/JWKS/reauth, strict JSON, route policy, CSPRNG failure, Turnstile, Odoo XML, upload, webhook SSRF/signature, config, HTTP shell, and PostgreSQL idempotency covered; full worker/Odoo integration, identity/PAT concurrency, lease crash takeover, and multipart rollback integration remain incomplete |
| Live integration verification | Deployment-owner credentials required | Manual gate |
