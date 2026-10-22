# Staging Microsoft Entra configuration

SELA staging uses this exact callback:

```text
https://sela.ilectraev.com/auth/callback
```

Application settings:

- Platform: Web
- Supported account type: Accounts in this organizational directory only (`AzureADMyOrg`)
- Authorization flow: Authorization Code with PKCE
- Redirect URI: exact value above; path and case must match
- Front-channel logout URL: not required
- Implicit grant and hybrid flows: disabled
- Public client flow: disabled
- Client secret: private runtime secret, never committed

## Portal setup

1. Open Microsoft Entra ID > App registrations.
2. Select application whose Application (client) ID matches `ENTRA_CLIENT_ID`.
3. Open Authentication.
4. Under Web, add `https://sela.ilectraev.com/auth/callback`.
5. Keep existing approved redirect URIs.
6. Save and wait for propagation.
7. Confirm login from `https://sela.ilectraev.com/login`.

## Idempotent Azure CLI setup

Run only from an administrator workstation with Azure CLI installed and authenticated to expected tenant. Script validates tenant, client ID, single-tenant audience, and public URL. It preserves existing redirect URIs and adds only SELA callback.

```bash
az login --tenant "$ENTRA_TENANT_ID"
node deploy/configure-entra-staging.mjs inspect /path/to/private/sela-staging.env
node deploy/configure-entra-staging.mjs apply /path/to/private/sela-staging.env
node deploy/configure-entra-staging.mjs inspect /path/to/private/sela-staging.env
```

Required Microsoft Graph permission for operator: ability to update application registrations, such as Application Administrator or ownership of target app with suitable directory policy.

Expected inspect result includes:

```json
{
  "redirectURI": "https://sela.ilectraev.com/auth/callback",
  "configured": true
}
```

## Runtime mapping

Use `deploy/staging.env.example` as non-secret template. Keep real file outside Git with mode `0600`. Required values:

```text
APP_ENV=staging
APPLICATION_ID=sela-staging
PUBLIC_URL=https://sela.ilectraev.com
ENTRA_TENANT_ID=<tenant UUID>
ENTRA_CLIENT_ID=<application client UUID>
ENTRA_CLIENT_SECRET=<private secret>
ENTRA_ISSUER=https://login.microsoftonline.com/<tenant UUID>/v2.0
ENTRA_AUTH_URL=https://login.microsoftonline.com/<tenant UUID>/oauth2/v2.0/authorize
ENTRA_TOKEN_URL=https://login.microsoftonline.com/<tenant UUID>/oauth2/v2.0/token
ENTRA_JWKS_URL=https://login.microsoftonline.com/<tenant UUID>/discovery/v2.0/keys
```

Temporary staging Turnstile bypass:

```text
TURNSTILE_ENABLED=false
```

Production rejects disabled Turnstile.
