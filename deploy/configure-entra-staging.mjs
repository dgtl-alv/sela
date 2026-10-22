#!/usr/bin/env node
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';

const [action = 'inspect', envPath = '.env'] = process.argv.slice(2);
if (!['inspect', 'apply'].includes(action)) {
  throw new Error('Usage: configure-entra-staging.mjs [inspect|apply] [ENV_PATH]');
}

function readEnv(path) {
  const values = {};
  for (const line of fs.readFileSync(path, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
    const index = trimmed.indexOf('=');
    values[trimmed.slice(0, index)] = trimmed.slice(index + 1);
  }
  return values;
}

function az(args) {
  return JSON.parse(execFileSync('az', [...args, '--output', 'json'], {
    encoding: 'utf8',
    timeout: 45000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }));
}

const env = readEnv(envPath);
const tenantId = env.ENTRA_TENANT_ID;
const clientId = env.ENTRA_CLIENT_ID;
const publicURL = env.PUBLIC_URL;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
if (!uuid.test(tenantId ?? '') || !uuid.test(clientId ?? '')) {
  throw new Error('ENTRA_TENANT_ID and ENTRA_CLIENT_ID must be UUIDs');
}
if (publicURL !== 'https://sela.ilectraev.com') {
  throw new Error('PUBLIC_URL must equal https://sela.ilectraev.com');
}
const redirectURI = `${publicURL}/auth/callback`;
const account = az(['account', 'show']);
if (account.tenantId !== tenantId) throw new Error('Azure session tenant mismatch');

function getApplication() {
  const matches = az(['rest', '--method', 'get', '--url', `https://graph.microsoft.com/v1.0/applications?$filter=appId%20eq%20'${clientId}'`]);
  if (!Array.isArray(matches.value) || matches.value.length !== 1) {
    throw new Error('Expected exactly one matching Entra application');
  }
  return matches.value[0];
}

let app = getApplication();
if (app.signInAudience !== 'AzureADMyOrg') {
  throw new Error('Entra application must be single-tenant AzureADMyOrg');
}
const existing = Array.isArray(app.web?.redirectUris) ? app.web.redirectUris : [];
const redirectUris = [...new Set([...existing, redirectURI])].sort();

if (action === 'apply' && !existing.includes(redirectURI)) {
  az([
    'rest', '--method', 'patch',
    '--url', `https://graph.microsoft.com/v1.0/applications/${app.id}`,
    '--headers', 'Content-Type=application/json',
    '--body', JSON.stringify({ web: { redirectUris } }),
  ]);
  app = getApplication();
  if (!app.web?.redirectUris?.includes(redirectURI)) {
    throw new Error('Redirect URI verification failed after update');
  }
}

console.log(JSON.stringify({
  action,
  appId: clientId,
  displayName: app.displayName,
  signInAudience: app.signInAudience,
  redirectURI,
  configured: app.web?.redirectUris?.includes(redirectURI) ?? false,
  redirectURISet: action === 'inspect' ? existing : app.web.redirectUris,
}, null, 2));
