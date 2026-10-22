# SELA Web App Build Plan

## Purpose and workload
- Problem and primary journeys: internal mobile technicians search Odoo `fleet.diagnose` by partial Service Booking/diagnose number, inspect service metadata/evidence, enqueue photo/video evidence, and follow validated SharePoint evidence links. Admins manage webhooks; users manage PATs.
- Users and exposure: internal ALVA only. Microsoft Entra tenant restricted.
- Profile: internal workflow plus upload/background-job and API/webhook capabilities. No public domain workflow, email, archive upload, inline file preview, or remote URL import.
- Scale: modest interactive traffic; PostgreSQL supports concurrent jobs. Vehicle, customer, file metadata, and evidence are confidential. Deployment owner defines RPO/RTO.

## Stack and data
- Go `net/http`, `html/template`, minimal vanilla JS; PostgreSQL through pgx. Application ID `sela` is PostgreSQL `application_name`.
- UUID tables: users, external identities, sessions, PATs, idempotency records, audit/domain/outbox events, webhook endpoints/subscriptions/deliveries, upload jobs.
- Forward-only migrations. Back up with `pg_dump`; verify isolated `pg_restore`. Code rollback only while schema remains compatible.
- Odoo XML-RPC uses fixed models/methods, bounded responses, HTTPS in production, explicit timeouts, one authentication refresh for safe session faults, and no credential logging.
- Upload contract: authenticated technician/admin; authorized `fleet.diagnose`; max 4 files/request, 25 MiB/file, 101 MiB request. JPEG, PNG, WebP, MP4, QuickTime only; extension, detected MIME, and structural checks must agree. Private 0700 quarantine/0600 files. Worker scanner required in production. Successful Odoo upload deletes quarantine; terminal failures retained 24 hours then cleanup. No archive/download/inline-preview surface.

## Identity and authorization
- Entra Authorization Code + PKCE. Validate state, nonce, RS256 JWKS signature, issuer, tenant, audience, exp, nbf. UUID local users map through `(provider, issuer, subject)`.
- Roles: `technician`, `admin`; default deny. Active role reloaded for each request. Both roles search/read/upload; only admin manages webhooks/retries.
- Opaque server sessions stored as keyed hashes, rotated on login, 30-minute inactivity, 12-hour absolute expiry, revocable. `__Host-sela_session`, Secure, HttpOnly, SameSite=Lax.
- Cookie writes require CSRF and same-origin validation. Login start is POST and requires Turnstile action `login_start`. Logout is POST.
- No Basic/Digest/browser credential modal. No production test bypass.

## Security design
- Attacker-controlled: auth callback, searches, IDs, multipart files, JSON, idempotency keys, PATs, webhook destinations/provider responses, Odoo XML. Privileged operations: role/admin webhooks, token lifecycle, evidence processing.
- Abuse cases: account/session fixation, record guessing, oversized/polyglot file, XML expansion, PAT replay, webhook SSRF/DNS rebinding, Odoo fault leakage, idempotency collision.
- Controls: default deny, reauthorization, bounds, private quarantine, scanner fail closed, rate limits, structured redacted logs, CSP nonce, headers, HTTPS gates, encrypted webhook secrets, exact-body HMAC.
- Suspect bypass: unsupported and absent. Odoo validation failures fail closed. No accepted security deviation.

## REST API and PATs
- `/api/v1`: principal; service search/read/evidence; upload jobs; own PAT list/create/revoke; admin webhook endpoint/subscription/delivery operations.
- Scopes: `services:read`, `evidence:read`, `evidence:write`. Admin webhook routes require browser admin session and CSRF; PATs cannot perform admin operations.
- PAT active limit 10, max lifetime 90 days, keyed SHA-256 hash, plaintext once, last-use only after full validation. Bearer requires HTTPS and malformed Bearer never falls back to cookie.
- Pagination limit default 20/max 100. UTC RFC3339. Retryable mutations require actor/method/path/body-bound `Idempotency-Key`; 409 on mismatch/in-flight; retention 24 hours.
- OpenAPI: `docs/openapi.yaml`.

## Events and webhooks
- Catalog: upload queued/succeeded/failed and PAT created/revoked, version 1; schemas in `docs/events/`.
- Domain event and outbox state commit atomically. Worker expands enabled subscriptions into deliveries.
- HTTPS only. Resolve every attempt, reject private/loopback/link-local/metadata/unspecified/multicast, pin validated IP while preserving TLS name, no redirects, bounded response.
- HMAC-SHA256 signs `timestamp.exact_body`. AES-256-GCM encrypted endpoint secrets require runtime key. Five capped jittered retries then terminal failure; admin manual retry audited.

## Architecture and UI
- `cmd/server` handles SSR/API/auth; `cmd/worker` claims uploads/outbox/webhooks. Same image, separate commands.
- Mobile-first Indonesian workflow, semantic forms, 44px targets, visible focus, DESIGN.md tokens. Client may compress images to JPEG max side 1920 quality .82; server never trusts result.
- Shared shell renders GTM once with nonce and consent-default-denied bootstrap; no PII/data values. Turnstile and GTM origins explicitly in CSP.
- `/healthz` process only. `/readyz` checks PostgreSQL plus configured mandatory scanner/Odoo/identity metadata readiness without detail. Timeouts, shutdown, request IDs, redacted JSON logs.

## Verification and rollout
- Unit/httptest fakes cover auth/JWKS, sessions, CSRF/origin, Turnstile, GTM/CSP, PAT, authorization, Odoo XML/flow, upload validation/quarantine/scanner, API errors/pagination/idempotency, webhook signature/SSRF/retry, config, health/readiness.
- Required commands: gofmt, vet, tests, race, web/worker builds, Compose config, Docker build, policy/design/secret checks.
- Deploy migration once before web/worker. Monitor readiness, auth failures, upload queue age/failure, quarantine size, webhook terminal failures. Roll back compatible image; otherwise roll forward or restore verified backup.

## Confirmation
User approved Go + PostgreSQL + Entra, internal audience, complete rewrite, existing feature branch. Prompt forbids commit/push/PR. External credentials and live Entra/Odoo/Turnstile/GTM/SharePoint validation remain deployment-owner gates.
