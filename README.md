# SELA Service Evidence Uploader

Internal ALVA mobile-first evidence workflow. Bare Go `net/http`/`html/template`, PostgreSQL/pgx, Entra Authorization Code + PKCE, Odoo XML-RPC, private scanned uploads, REST/PATs, transactional events, and admin webhooks.

## Core flow
Technician signs in with Microsoft, searches partial Service Booking/diagnose number, reviews customer/VIN/location/state/evidence count, opens validated evidence links, and queues JPEG/PNG/WebP/MP4/MOV files. Worker scans, writes `sharepoint_file` and `document_upload_name` to validated `fleet.diagnose`, polls `fleet.link`, then deletes quarantine after success.

Legacy `x.service.tag.his` suspect bypass is not present. Odoo policy errors fail closed. Enable no compatibility flag without owner approval, isolated proof tests, and updated threat documentation.

## Local setup
1. Copy `.env.example` to `.env`; replace every placeholder with local-only values. Generate keys: `openssl rand -base64 32`.
2. Register Entra callback `${PUBLIC_URL}/auth/callback`; configure tenant-specific issuer/endpoints.
3. Configure Turnstile test keys only outside production, a valid GTM container, Odoo URL/database, `ODOO_CREDENTIAL_ENCRYPTION_KEY`, SharePoint host allowlist, and scanner. Each user stores own emica credential.
4. Run `docker compose up --build`. Open `http://localhost:8080`; probes are `/healthz` and `/readyz`.

`SCANNER_MODE=development` runs format validators without malware scanning and is accepted only outside production. Remote mode requires `SCANNER_TOKEN`; requests to `SCANNER_URL` use Bearer authentication. Production requires `SCANNER_MODE=remote`, HTTPS `SCANNER_URL`, and a non-placeholder token; scanner outage fails readiness and jobs fail closed. Compose connects web and worker to the external `${SCANNER_NETWORK:-scanner_private}` network as clients; it does not run a dedicated scanner or clamd.

## Database migrations

Fresh Compose databases run every numbered SQL file from `/docker-entrypoint-initdb.d`. Existing databases require explicit forward migration before updated web/worker processes start:

```bash
docker compose exec -T db sh -lc 'psql -v ON_ERROR_STOP=1 -U app -d app -f /docker-entrypoint-initdb.d/001_initial.sql && psql -v ON_ERROR_STOP=1 -U app -d app -f /docker-entrypoint-initdb.d/002_user_access_and_odoo_credentials.sql'
```

Migration `002` idempotently bootstraps approved active admin `muhammad.hidayat@alvaauto.com`. Existing row with this email is promoted/reactivated; other users remain unchanged.

## Commands
```bash
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/server ./cmd/worker
docker compose config --quiet
docker build -t sela:test .
```

## Security and API
- `GET /healthz` checks process only. `GET /readyz` checks PostgreSQL and scanner without requiring global user credentials.
- Browser sessions use `__Host-sela_session`; state changes require CSRF plus same-origin. Anonymous login start requires Turnstile.
- PAT format has random secret, keyed hash storage, explicit scope, max 90-day expiration and 10 active tokens. Plaintext appears once. Bearer requires HTTPS in production and never falls back after malformed input.
- Upload: max 4 files/request and 25 MiB/file; extension, MIME signature, and structural checks; 0700 quarantine/0600 objects; server-generated keys; no public downloads.
- Webhooks: HTTPS, DNS revalidation/IP pinning, blocked internal networks, no redirects, AES-GCM secret storage, `HMAC-SHA256(timestamp + "." + exact_body)`. Creation, subscriptions, idempotency record, and response commit atomically. Unknown event names fail validation. Delivery updates require unique claim token, owner, leased state, and unexpired lease; disabling endpoint atomically cancels pending/leased deliveries.
- Upload worker: state and domain event commit atomically under live claim token. Scanner engine/version survive later transitions. Bounded sweeper removes terminal files after `delete_after` and untracked regular files after one-hour grace; unsafe keys and symlinks are never followed, active files remain, and failed deletion retries.
- OIDC `return_to`: only unambiguous local absolute paths accepted; unsafe scheme/authority/userinfo, backslash, controls, encoded separators, and dot-segment forms fall back to `/`.
- API: `docs/openapi.yaml`; events: `docs/event-catalog.yaml`; plan/compliance: `docs/plan.md`, `docs/compliance-matrix.md`.

## Deployment gates
Deployment owner supplies and validates real Entra, Odoo, Turnstile, GTM, scanner, PostgreSQL TLS, encryption keys, and SharePoint host configuration. Live external integrations were not validated in source development. Visually compare Microsoft button against current official branding on mobile/desktop. Run restore drill and representative login/search/upload/link/webhook smoke tests before release.

See `docs/operations.md` for migration, backup, restore, retention, deployment, and rollback. See `docs/staging-entra.md` for SELA staging Entra registration and idempotent callback configuration.
