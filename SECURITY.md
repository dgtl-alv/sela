# Security Policy

## Supported Versions and Reporting
Only current `main` release is supported. Report privately to repository security contacts/owners; acknowledgement target two business days. Never disclose credentials, personal/vehicle data, or exploit details in public issues.

## System and Scope
SELA is internal ALVA software. Web/API, worker, PostgreSQL metadata, private quarantine, Entra, Odoo/SharePoint, scanner, Turnstile, GTM, PATs, and webhook delivery are in scope. Deployment owner controls production infrastructure and credentials.

## Threat Model and Trust Boundaries
Untrusted inputs include browser/API requests, auth responses, multipart files/names/types, Odoo XML/faults/links, DNS/provider responses, webhook URLs, and scanner responses. Sensitive assets include customer/vehicle metadata, evidence, sessions, PATs, identity mappings, Odoo credentials, and webhook secrets. Admins are trusted for endpoint configuration but destinations remain SSRF checked.

## Security Invariants
- Entra code+PKCE validates state, nonce, tenant, issuer, audience, time, and JWKS signature. Production has no auth bypass.
- Every route/action defaults denied; active user/role and target record are server checked.
- Anonymous login write verifies Turnstile. Cookie writes verify CSRF and Origin.
- Upload remains private until bounded validation and mandatory scan; uncertainty fails closed.
- PAT plaintext/webhook secret appears once, never stored or logged. Webhook destinations remain SSRF-safe and exact bodies are signed.
- Remote evidence links require HTTPS and exact host allowlist.
- GTM receives no personal, form, URL-secret, credential, token, UUID, or evidence data.
- Production rejects missing, placeholder, HTTP, test Turnstile, development scanner, bad GTM, absent encryption/auth/Odoo config.

## Out of Scope and Accepted Risk
No approved security deviation. Inline evidence serving, archives, remote imports, email, and legacy suspect bypass are absent. Client image compression is convenience, not security control.

## Known Limitations and Gates
Production owner must validate live Entra/Odoo/SharePoint/Turnstile/GTM/scanner contracts and credentials, scanner isolation/definitions, proxy TLS and trusted-address behavior, backup restore, retention cleanup, egress firewall, and Microsoft branding. Development scanner provides no malware detection and production config rejects it.
