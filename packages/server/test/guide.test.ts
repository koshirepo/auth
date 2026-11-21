/**
 * The server from docs/integration-express.md, built the way the guide builds it and driven the
 * way a browser would drive it. PGlite stands in for the `pg` Pool, so the whole stack runs on the
 * Postgres adapter: sessions, refresh rotation, audit events and all.
 *
 * If the guide's code changes, change this file with it.
 */
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { defineRbac, definePolicy, deny, isAuthError } from '@koshi-repo/auth-core';
import { PGlite } from '@electric-sql/pglite';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrate, postgresAdapter } from '../src/adapters/postgres/index.js';
import { expressAuth, getAuth } from '../src/express/index.js';
import { createAuth, type Auth } from '../src/index.js';
import { argon2id } from '../src/password/argon2.js';
import { TestBrowser } from './browser.js';
import { APP_ORIGIN, PASSWORD } from './env.js';
import { createDpopKey, randomDataKey } from './helpers.js';

// ---- access.ts (guide section 2) -------------------------------------------------------------

const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
    admin: { grants: ['invoice:*'] },
  },
});

interface Invoice {
  id: string;
  ownerId: string;
}

const changeOwnInvoiceOnly = definePolicy('change-own-invoice-only', (subject, action, invoice: Invoice | undefined) => {
  if (action !== 'invoice:write' || !invoice) return;
  if (invoice.ownerId !== subject.id && !subject.roles.includes('admin')) {
    return deny('invoice belongs to another user');
  }
});

const policies = [changeOwnInvoiceOnly];

// ---- the rest of the guide's server ----------------------------------------------------------

let pool: PGlite;
let auth: Auth<'invoice:read' | 'invoice:write' | 'invoice:delete'>;
let server: Server;
let baseUrl: string;
const store = new Map<string, Invoice>();
const unexpected: unknown[] = [];

const invoices = {
  get: async (id: string) => store.get(id),
  update: async (id: string, patch: object) => ({ ...store.get(id), ...patch }),
  remove: async (id: string) => void store.delete(id),
};

beforeAll(async () => {
  pool = new PGlite();
  await pool.waitReady;

  // auth.ts (guide section 3)
  await migrate(pool);
  auth = createAuth({
    issuer: 'https://api.example.com',
    audience: 'https://api.example.com',
    adapter: postgresAdapter({ db: pool }),
    dataKeys: [{ id: '2026-11', key: randomDataKey() }],

    password: { hasher: argon2id() },
    passkeys: { rpId: 'example.com', rpName: 'Example', origins: ['https://app.example.com'] },
    access: { rbac, policies },
  });

  // server.ts (guide section 4)
  const app = express();
  app.set('trust proxy', 1);

  const { router, requireAuth, requirePermission, errorHandler } = expressAuth(auth, {
    publicOrigin: 'https://api.example.com',
    allowedOrigins: [APP_ORIGIN],
    onError: (error) => unexpected.push(error),
  });

  app.use(router);

  app.use((req, res, next) => {
    if (req.headers.origin === APP_ORIGIN) {
      res.setHeader('Access-Control-Allow-Origin', APP_ORIGIN);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, DPoP');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
      res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate');
    }
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });
  app.use(express.json());

  app.get('/invoices/:id', requireAuth(), requirePermission('invoice:read'), async (req, res) => {
    res.json(await invoices.get(String(req.params.id)));
  });

  app.put(
    '/invoices/:id',
    requireAuth(),
    requirePermission('invoice:write', { resource: (req) => invoices.get(String(req.params.id)) }),
    async (req, res) => {
      res.json(await invoices.update(String(req.params.id), req.body));
    },
  );

  app.delete(
    '/invoices/:id',
    requireAuth({ assurance: 'aal2', maxAuthAgeSec: 300 }),
    requirePermission('invoice:delete'),
    async (req, res) => {
      await invoices.remove(String(req.params.id));
      res.status(204).end();
    },
  );

  app.get('/me', requireAuth(), (req, res) => {
    const { subject, context } = getAuth(req);
    res.json({ id: subject.id, roles: subject.roles, assurance: context.assurance });
  });

  app.use(errorHandler);

  server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 60_000);

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await pool.close();
});

async function browser(): Promise<TestBrowser> {
  const send = (request: Request) => {
    const url = new URL(request.url);
    return fetch(`${baseUrl}${url.pathname}${url.search}`, {
      method: request.method,
      headers: request.headers,
      ...(request.body ? { body: request.body, duplex: 'half' } : {}),
    } as RequestInit);
  };
  return new TestBrowser(send, await createDpopKey(), Date.now);
}

describe('the server from the Express integration guide', () => {
  it('creates users as section 5 shows, and reports a duplicate and a weak password', async () => {
    const ada = await auth.users.create({ identifier: 'ada@example.com', password: PASSWORD, roles: ['editor'] });
    const vera = await auth.users.create({ identifier: 'vera@example.com', password: PASSWORD, roles: ['viewer'] });
    store.set('ada-1', { id: 'ada-1', ownerId: ada.id });
    store.set('vera-1', { id: 'vera-1', ownerId: vera.id });

    const duplicate = await auth.users.create({ identifier: 'ada@example.com', password: PASSWORD }).catch((error: unknown) => error);
    expect(isAuthError(duplicate) && duplicate.code).toBe('IDENTIFIER_TAKEN');
    const weak = await auth.users.create({ identifier: 'bob@example.com', password: 'short' }).catch((error: unknown) => error);
    expect(isAuthError(weak) && [weak.code, weak.details]).toEqual(['PASSWORD_POLICY_VIOLATION', { reason: 'too_short' }]);
  });

  it('signs in, calls the protected routes, refreshes and signs out, all on Postgres', async () => {
    const client = await browser();

    const login = await client.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(login.status).toBe(200);
    expect(login.json.status).toBe('authenticated');
    expect(login.setCookies[0]).toMatch(/^__Host-rt=[\w-]{43}; Path=\/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict$/);
    let token: string = login.json.accessToken;

    // A permission a role grants.
    const read = await client.get('/invoices/ada-1', { token });
    expect(read.status).toBe(200);
    expect(read.json).toEqual({ id: 'ada-1', ownerId: login.json.user.id });
    expect(read.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);

    // A permission that depends on the object.
    const own = await client.request('PUT', '/invoices/ada-1', { token, body: { note: 'paid' } });
    expect(own.status).toBe(200);
    expect(own.json).toMatchObject({ id: 'ada-1', note: 'paid' });
    const other = await client.request('PUT', '/invoices/vera-1', { token, body: { note: 'mine now' } });
    expect(other.status).toBe(403);
    expect(other.json.error).toEqual({
      code: 'FORBIDDEN',
      message: 'You are not allowed to do that.',
      details: { reason: 'invoice belongs to another user', policy: 'change-own-invoice-only', action: 'invoice:write' },
    });

    // A sensitive action needs two factors.
    const remove = await client.delete('/invoices/ada-1', { token });
    expect(remove.status).toBe(403);
    expect(remove.json.error.code).toBe('STEP_UP_REQUIRED');
    expect(store.has('ada-1')).toBe(true);

    // The verified identity is on the request.
    const me = await client.get('/me', { token });
    expect(me.json).toEqual({ id: login.json.user.id, roles: ['editor'], assurance: 'aal1' });

    // Without a token, and with a token but from another device.
    expect((await client.get('/me')).json.error.code).toBe('TOKEN_MISSING');
    const thief = await browser();
    expect((await thief.get('/me', { token })).json.error.code).toBe('DPOP_KEY_MISMATCH');

    // Refresh rotates the cookie. The old cookie then revokes the session.
    const before = client.cookies.get('__Host-rt')!;
    const refreshed = await client.post('/auth/refresh');
    expect(refreshed.status).toBe(200);
    token = refreshed.json.accessToken;
    expect((await client.get('/me', { token })).status).toBe(200);

    const current = client.cookies.get('__Host-rt')!;
    client.cookies.set('__Host-rt', before);
    expect((await client.post('/auth/refresh')).json.error.code).toBe('REFRESH_TOKEN_REUSED');
    client.cookies.set('__Host-rt', current);
    expect((await client.post('/auth/refresh')).json.error.code).toBe('SESSION_REVOKED');

    // Sign in again and out again.
    await client.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect((await client.post('/auth/logout')).status).toBe(204);
    expect(client.cookies.has('__Host-rt')).toBe(false);
    expect(unexpected).toEqual([]);
  }, 30_000);

  it('answers CORS preflight for the application routes with the headers the client needs', async () => {
    const client = await browser();
    const preflight = await client.request('OPTIONS', '/invoices/ada-1', { proof: false });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);
    expect(preflight.headers.get('access-control-allow-headers')).toBe('Authorization, Content-Type, DPoP');

    // The auth endpoints answer their own preflight.
    const authPreflight = await client.request('OPTIONS', '/auth/refresh', { proof: false });
    expect(authPreflight.status).toBe(204);
    expect(authPreflight.headers.get('access-control-allow-credentials')).toBe('true');
  });

  it('wrote everything to Postgres, with no secret in plain text', async () => {
    const count = async (table: string) => Number((await pool.query<{ n: number }>(`SELECT count(*)::int AS n FROM auth.${table}`)).rows[0]!.n);
    expect(await count('users')).toBe(2);
    expect(await count('sessions')).toBe(2);
    expect(await count('refresh_tokens')).toBe(3);
    expect(await count('signing_keys')).toBe(1);
    expect(await count('audit_events')).toBeGreaterThan(10);

    // Default Argon2id parameters, as the guide configures them.
    const { rows: hashes } = await pool.query<{ hash: string }>('SELECT hash FROM auth.password_credentials');
    for (const { hash } of hashes) expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);

    // The private signing key is encrypted, and the audit log holds no password.
    const { rows: keys } = await pool.query<{ encrypted_private_jwk: string; public_jwk: object }>('SELECT * FROM auth.signing_keys');
    expect(keys[0]!.encrypted_private_jwk.split('.')).toHaveLength(5);
    expect(keys[0]!.public_jwk).not.toHaveProperty('d');
    const { rows: events } = await pool.query<{ event: object }>('SELECT event FROM auth.audit_events');
    expect(JSON.stringify(events)).not.toContain(PASSWORD);

    const types = new Set((events as { event: { type: string } }[]).map((row) => row.event.type));
    for (const type of ['user.created', 'login.succeeded', 'session.created', 'session.refreshed', 'session.refresh_reuse_detected', 'access.denied']) {
      expect(types.has(type)).toBe(true);
    }
  });

  it('runs the scheduled cleanup from section 10', async () => {
    const purged = await auth.maintenance.purgeExpired();
    expect(purged).toEqual({ ephemeral: expect.any(Number), sessions: 0 });
  });

});
