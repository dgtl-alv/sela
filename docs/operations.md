# Operations

## Migrate
Run numbered SQL exactly once with PostgreSQL role setting `application_name=sela`. Migration 001 is forward-only and non-destructive on an empty database.

## Backup and restore
1. Pause worker and writes. Run `pg_dump --format=custom --file=sela.dump "$DATABASE_URL"`; snapshot quarantine volume at same recovery point.
2. Restore into isolated PostgreSQL using `pg_restore --clean --if-exists --dbname="$RESTORE_DATABASE_URL" sela.dump`; restore quarantine snapshot privately.
3. Start candidate web/worker, require `/readyz`, test representative user/session/job queries, then approve backup.

## Deploy and rollback
Apply migration once, deploy immutable image to worker then web, inspect readiness and queue age. Schema remains additive; image rollback is supported. If later destructive migration exists, roll forward or restore verified DB/quarantine pair. Never reverse migration 001 by dropping production tables.

## Retention
Successful quarantine is removed immediately; its completed job metadata remains. Rejected/failed quarantine is retained 24 hours for restricted incident review, then the bounded worker sweeper removes the file and keeps terminal job metadata. Untracked regular quarantine files are removed after a one-hour grace period. Unsafe keys and symlinks are never followed; failed cleanup retries after one hour. Sessions, idempotency: 24 hours after expiry. Webhook delivery/audit/domain events: 90 days unless legal hold. Backups follow operator retention and deletion schedule.

## Monitoring
Alert on readiness failure, Odoo/scanner latency, authentication failures, quarantine growth, upload age/rejection, terminal webhook failures, PAT anomalies, PostgreSQL saturation. Logs exclude file bytes, raw names, cookies, authorization, credentials, tokens, secrets, and customer/vehicle fields.
