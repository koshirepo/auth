import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { allow, defineRbac, definePolicy, deny } from '@acme/auth-core';
import express, { type Express } from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { expressAuth, getAuth } from '../src/express/index.js';
import { TestBrowser } from './browser.js';
import { API_ORIGIN, APP_ORIGIN, PASSWORD, createAuthEnv, enrollTotp, totpCode, type AuthEnv } from './env.js';
import { createDpopKey } from './helpers.js';

interface Invoice {
  id: string;
  ownerId: string;
}

const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write', 'invoice:delete'] },
  },
});

const changeOwnInvoiceOnly = definePolicy('change-own-invoice-only', (subject, action, resource: Invoice | undefined) => {
  if (action !== 'invoice:write' || !resource) return;
  if (resource.ownerId !== subject.id) return deny('invoice belongs to another user');
  return allow('owner may change their invoice');
});

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
});

async function listen(app: Express): Promise<string> {
  const server = app.listen(0, '127.0.0.1');
  servers.push(server);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function setup(
  configure: (app: Express, env: AuthEnv) => void = () => undefined,
  parseJsonFirst = false,
  /** Registered after the library's error handler, as an application's own final handler would be. */
  afterErrorHandler: (app: Express) => void = () => undefined,
) {
  const env = createAuthEnv({ access: { rbac, policies: [changeOwnInvoiceOnly] } });
  const ada = await env.auth.users.create({ identifier: 'ada@example.com', password: PASSWORD, roles: ['editor'] });
  const vera = await env.auth.users.create({ identifier: 'vera@example.com', password: PASSWORD, roles: ['viewer'] });
  const invoices: Record<string, Invoice> = { 'ada-1': { id: 'ada-1', ownerId: ada.id }, 'bob-1': { id: 'bob-1', ownerId: 'someone-else' } };
  const unexpected: unknown[] = [];

  const app = express();
  if (parseJsonFirst) app.use(express.json());
  const auth = expressAuth(env.auth, {
    publicOrigin: API_ORIGIN,
    allowedOrigins: [APP_ORIGIN],
    onError: (error) => unexpected.push(error),
  });
  app.use(auth.router);

  app.get('/health', (_req, res) => {
    res.json({ ok: true });
  });
  app.get('/invoices/:id', auth.requireAuth(), auth.requirePermission('invoice:read'), (req, res) => {
    res.json({ id: req.params.id, viewer: getAuth(req).subject.id });
  });
  app.put(
    '/invoices/:id',
    auth.requireAuth(),
    auth.requirePermission('invoice:write', { resource: async (req) => invoices[String(req.params.id)] }),
    (req, res) => {
      res.json({ updated: req.params.id });
    },
  );
  app.delete('/invoices/:id', auth.requireAuth({ assurance: 'aal2' }), auth.requirePermission('invoice:delete'), (req, res) => {
    res.status(204).end();
  });
  app.post('/invoices/:id/archive', auth.requireAuth(), (req, res) => {
    // Throwing inside a handler: the error handler below turns it into the JSON error format.
    env.auth.authorizer.assert(getAuth(req).subject, 'invoice:delete');
    res.json({ archived: req.params.id });
  });
  app.get('/broken', () => {
    throw new Error('not an auth error');
  });
  configure(app, env);
  app.use(auth.errorHandler);
  afterErrorHandler(app);

  const baseUrl = await listen(app);
  const send = (request: Request) => {
    const url = new URL(request.url);
    return fetch(`${baseUrl}${url.pathname}${url.search}`, {
      method: request.method,
      headers: request.headers,
      ...(request.body ? { body: request.body, duplex: 'half' } : {}),
    } as RequestInit);
  };
  const browser = async () => new TestBrowser(send, await createDpopKey(), env.clock);
  return { env, ada, vera, baseUrl, browser, unexpected };
}

async function login(browser: TestBrowser, identifier = 'ada@example.com') {
  const response = await browser.post('/auth/login/password', { identifier, password: PASSWORD });
  expect(response.status).toBe(200);
  return response.json as { accessToken: string; session: { id: string } };
}

describe('expressAuth router', () => {
  it('serves the auth endpoints: login sets the cookie and refresh rotates it', async () => {
    const { browser } = await setup();
    const client = await browser();
    const response = await client.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.status).toBe(200);
    expect(response.json.status).toBe('authenticated');
    expect(response.setCookies[0]).toMatch(/^__Host-rt=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict$/);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);

    const before = client.cookies.get('__Host-rt');
    const refreshed = await client.post('/auth/refresh');
    expect(refreshed.status).toBe(200);
    expect(client.cookies.get('__Host-rt')).not.toBe(before);
  });

  it('works when a JSON body parser is mounted before it', async () => {
    const { browser } = await setup(undefined, true);
    const client = await browser();
    await login(client);
    expect((await client.post('/auth/refresh')).status).toBe(200);
    const bad = await client.post('/auth/login/password', { identifier: 'ada@example.com' });
    expect(bad.status).toBe(400);
    expect(bad.json.error.details).toEqual({ field: 'password' });
  });

  it('serves the JWKS document', async () => {
    const { browser } = await setup();
    const client = await browser();
    await login(client);
    const response = await client.get('/.well-known/jwks.json', { proof: false });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=600');
    expect(response.json.keys).toHaveLength(1);
  });

  it('leaves other paths to the application', async () => {
    const { browser } = await setup();
    const client = await browser();
    expect((await client.get('/health', { proof: false })).json).toEqual({ ok: true });
    expect((await client.get('/authentic', { proof: false })).status).toBe(404);
  });

  it('answers errors and empty responses in the same format as the Fetch handler', async () => {
    const { browser } = await setup();
    const client = await browser();
    const wrong = await client.post('/auth/login/password', { identifier: 'ada@example.com', password: 'wrong wrong wrong' });
    expect(wrong.status).toBe(401);
    expect(wrong.json).toEqual({ error: { code: 'INVALID_CREDENTIALS', message: 'The credentials are not valid.' } });

    await login(client);
    const logout = await client.post('/auth/logout');
    expect(logout.status).toBe(204);
    expect(logout.text).toBe('');
    expect(logout.setCookies).toEqual(['__Host-rt=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict']);
  });

  it('rejects oversized bodies read from the stream', async () => {
    const { browser } = await setup();
    const client = await browser();
    const response = await client.post('/auth/login/password', { identifier: 'ada@example.com', password: 'x'.repeat(100_000) });
    expect(response.status).toBe(400);
    expect(response.json.error.details).toEqual({ reason: 'body_too_large' });
  });

  it('uses req.ip as the client address by default', async () => {
    const { browser, env } = await setup();
    await login(await browser());
    expect(env.sink.ofType('login.succeeded')[0]!.ip).toMatch(/127\.0\.0\.1$/);
  });

  it('applies cross-site protection', async () => {
    const { browser } = await setup();
    const client = await browser();
    await login(client);
    const response = await client.post('/auth/refresh', undefined, { origin: 'https://evil.example' });
    expect(response.status).toBe(403);
    expect(response.json.error.code).toBe('ORIGIN_NOT_ALLOWED');
  });
});

describe('requireAuth', () => {
  it('lets a valid token through and exposes the verified identity', async () => {
    const { browser, ada } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    const response = await client.get('/invoices/ada-1', { token: accessToken });
    expect(response.status).toBe(200);
    expect(response.json).toEqual({ id: 'ada-1', viewer: ada.id });
  });

  it('checks the proof against the public URL and ignores the query string', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    expect((await client.get('/invoices/ada-1?expand=lines&page=2', { token: accessToken })).status).toBe(200);
  });

  it('rejects a missing token, a missing proof and a proof from another key', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);

    const missing = await client.get('/invoices/ada-1');
    expect(missing.status).toBe(401);
    expect(missing.json).toEqual({ error: { code: 'TOKEN_MISSING', message: 'An access token is required.' } });
    expect(missing.headers.get('www-authenticate')).toBe('DPoP error="invalid_token", algs="ES256"');

    const noProof = await client.get('/invoices/ada-1', { token: accessToken, proof: false });
    expect(noProof.json.error.code).toBe('DPOP_PROOF_REQUIRED');

    const thief = await browser();
    const stolen = await thief.get('/invoices/ada-1', { token: accessToken });
    expect(stolen.status).toBe(401);
    expect(stolen.json.error.code).toBe('DPOP_KEY_MISMATCH');
  });

  it('rejects a proof made for a different route', async () => {
    const { browser, env } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    const { createDpopProof } = await import('./helpers.js');
    const proof = await createDpopProof(client.key, {
      method: 'GET',
      url: `${API_ORIGIN}/invoices/other`,
      nowMs: env.clock(),
      accessToken,
    });
    const response = await client.get('/invoices/ada-1', { token: accessToken, proof: false, headers: { dpop: proof } });
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('DPOP_PROOF_INVALID');
  });

  it('rejects an expired token', async () => {
    const { browser, env } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    env.clock.advanceSec(906);
    const response = await client.get('/invoices/ada-1', { token: accessToken });
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('TOKEN_EXPIRED');
  });

  it('demands step-up when the route needs aal2', async () => {
    const { browser, env, ada } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);

    const weak = await client.delete('/invoices/ada-1', { token: accessToken });
    expect(weak.status).toBe(403);
    expect(weak.json.error).toEqual({
      code: 'STEP_UP_REQUIRED',
      message: 'This action needs a stronger or more recent authentication.',
      details: { required: 'aal2' },
    });

    const { secret } = await enrollTotp(env, ada.id);
    env.clock.advanceSec(30);
    const stepUp = await client.post('/auth/reauthenticate', { method: 'totp', code: await totpCode(env.clock, secret) }, { token: accessToken });
    expect((await client.delete('/invoices/ada-1', { token: stepUp.json.accessToken })).status).toBe(204);
  });
});

describe('requirePermission', () => {
  it('allows what the roles grant and denies the rest, with the reason', async () => {
    const { browser, env, vera } = await setup();
    const client = await browser();
    const { accessToken } = await login(client, 'vera@example.com');

    expect((await client.get('/invoices/ada-1', { token: accessToken })).status).toBe(200);
    const denied = await client.request('PUT', '/invoices/ada-1', { token: accessToken, body: {} });
    expect(denied.status).toBe(403);
    expect(denied.json).toEqual({
      error: {
        code: 'FORBIDDEN',
        message: 'You are not allowed to do that.',
        details: { reason: 'invoice belongs to another user', policy: 'change-own-invoice-only', action: 'invoice:write' },
      },
    });
    expect(env.sink.ofType('access.denied')[0]).toMatchObject({
      outcome: 'failure',
      userId: vera.id,
      data: { action: 'invoice:write', policy: 'change-own-invoice-only', decisionReason: 'invoice belongs to another user' },
    });
  });

  it('passes the loaded resource to the policies', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    expect((await client.request('PUT', '/invoices/ada-1', { token: accessToken, body: {} })).json).toEqual({ updated: 'ada-1' });
    const other = await client.request('PUT', '/invoices/bob-1', { token: accessToken, body: {} });
    expect(other.status).toBe(403);
    expect(other.json.error.details.reason).toBe('invoice belongs to another user');
  });
});

describe('errorHandler', () => {
  it('formats auth errors thrown in a handler', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client, 'vera@example.com');
    const response = await client.post('/invoices/ada-1/archive', undefined, { token: accessToken });
    expect(response.status).toBe(403);
    expect(response.json.error).toMatchObject({ code: 'FORBIDDEN', details: { policy: 'default', action: 'invoice:delete' } });
  });

  it('leaves other errors to the application', async () => {
    const { browser } = await setup(undefined, false, (app) => {
      app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        res.status(418).json({ handledBy: 'application', message: error instanceof Error ? error.message : '' });
      });
    });
    const client = await browser();
    const response = await client.get('/broken', { proof: false });
    expect(response.status).toBe(418);
    expect(response.json).toEqual({ handledBy: 'application', message: 'not an auth error' });
  });

});
