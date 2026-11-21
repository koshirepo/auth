import { allow, defineRbac, definePolicy, deny, isAuthError } from '@koshi-repo/auth-core';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { getAuth, honoAuth, type AuthEnv, type HonoAuthOptions } from '../src/hono/index.js';
import { TestBrowser } from './browser.js';
import { API_ORIGIN, APP_ORIGIN, PASSWORD, createAuthEnv, enrollTotp, totpCode } from './env.js';
import { createDpopKey, createDpopProof } from './helpers.js';

interface Invoice {
  id: string;
  ownerId: string;
}

type AppEnv = AuthEnv & { Bindings: { remoteAddress?: string } };

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

interface SetupOptions {
  /** Registered before the auth routes, as an application's own early middleware would be. */
  before?: (app: Hono<AppEnv>) => void;
  adapter?: Partial<HonoAuthOptions>;
  /** Replaces the library's error handler, to test composing it with an application's own. */
  onError?: (parts: ReturnType<typeof honoAuth>) => Parameters<Hono<AppEnv>['onError']>[0];
}

async function setup(options: SetupOptions = {}) {
  const env = createAuthEnv({ access: { rbac, policies: [changeOwnInvoiceOnly] } });
  const ada = await env.auth.users.create({ identifier: 'ada@example.com', password: PASSWORD, roles: ['editor'] });
  const vera = await env.auth.users.create({ identifier: 'vera@example.com', password: PASSWORD, roles: ['viewer'] });
  const invoices: Record<string, Invoice> = { 'ada-1': { id: 'ada-1', ownerId: ada.id }, 'bob-1': { id: 'bob-1', ownerId: 'someone-else' } };
  const unexpected: unknown[] = [];

  const parts = honoAuth(env.auth, {
    publicOrigin: API_ORIGIN,
    allowedOrigins: [APP_ORIGIN],
    clientIp: (c) => (c.env as { remoteAddress?: string } | undefined)?.remoteAddress,
    onError: (error) => unexpected.push(error),
    ...options.adapter,
  });
  const { routes, requireAuth, requirePermission } = parts;

  const app = new Hono<AppEnv>();
  options.before?.(app);
  app.use(routes);

  app.get('/health', (c) => c.json({ ok: true }));
  app.get('/invoices/:id', requireAuth(), requirePermission('invoice:read'), (c) => {
    return c.json({ id: c.req.param('id'), viewer: c.get('auth').subject.id });
  });
  app.put(
    '/invoices/:id',
    requireAuth(),
    // The loader's context does not carry the route's path type, so the parameter may be undefined to TypeScript.
    requirePermission('invoice:write', { resource: async (c) => invoices[c.req.param('id') ?? ''] }),
    async (c) => c.json({ updated: c.req.param('id'), received: await c.req.json() }),
  );
  app.delete('/invoices/:id', requireAuth({ assurance: 'aal2' }), requirePermission('invoice:delete'), (c) => c.body(null, 204));
  app.post('/invoices/:id/archive', requireAuth(), (c) => {
    // Throwing inside a handler: onError turns it into the JSON error format.
    env.auth.authorizer.assert(getAuth(c).subject, 'invoice:delete');
    return c.json({ archived: c.req.param('id') });
  });
  app.get('/recent', requireAuth({ maxAuthAgeSec: 300 }), (c) => c.json({ ok: true }));
  app.get('/broken', () => {
    throw new Error('not an auth error');
  });
  app.get('/who', (c) => c.json(getAuth(c).subject));
  app.onError(options.onError ? options.onError(parts) : parts.onError);

  // The server sees an internal address. Browsers, and therefore the proofs, use the public origin.
  const send = async (request: Request) => {
    const url = new URL(request.url);
    const body = request.body ? await request.text() : undefined;
    const internal = new Request(`http://10.0.0.5:3000${url.pathname}${url.search}`, {
      method: request.method,
      headers: request.headers,
      ...(body !== undefined ? { body } : {}),
    });
    return app.fetch(internal, { remoteAddress: '198.51.100.7' });
  };
  const browser = async () => new TestBrowser(send, await createDpopKey(), env.clock);
  return { env, ada, vera, app, browser, unexpected };
}

async function login(browser: TestBrowser, identifier = 'ada@example.com') {
  const response = await browser.post('/auth/login/password', { identifier, password: PASSWORD });
  expect(response.status).toBe(200);
  return response.json as { accessToken: string; session: { id: string } };
}

describe('honoAuth routes', () => {
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
    expect((await client.get('/auth', { proof: false })).status).toBe(404);
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

  it('applies cross-site protection', async () => {
    const { browser } = await setup();
    const client = await browser();
    await login(client);
    const response = await client.post('/auth/refresh', undefined, { origin: 'https://evil.example' });
    expect(response.status).toBe(403);
    expect(response.json.error.code).toBe('ORIGIN_NOT_ALLOWED');
  });

  it('takes the client address from the function you give it, and has none otherwise', async () => {
    const withIp = await setup();
    await login(await withIp.browser());
    expect(withIp.env.sink.ofType('login.succeeded')[0]!.ip).toBe('198.51.100.7');

    const without = await setup({ adapter: { clientIp: undefined } });
    await login(await without.browser());
    expect(without.env.sink.ofType('login.succeeded')[0]).not.toHaveProperty('ip');
  });

  it('still works when an earlier middleware has already read the body through Hono', async () => {
    const { browser } = await setup({
      before: (app) => {
        app.use(async (c, next) => {
          if (c.req.method === 'POST') await c.req.json().catch(() => undefined);
          await next();
        });
      },
    });
    const client = await browser();
    await login(client);
    expect((await client.post('/auth/refresh')).status).toBe(200);
    const bad = await client.post('/auth/login/password', { identifier: 'ada@example.com' });
    expect(bad.status).toBe(400);
    expect(bad.json.error.details).toEqual({ field: 'password' });
  });

  it('serves under a custom base path and honours the body limit', async () => {
    const { browser } = await setup({ adapter: { basePath: '/api/v1/auth', maxBodyBytes: 300 } });
    const client = await browser();
    const ok = await client.post('/api/v1/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(ok.status).toBe(200);
    expect((await client.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD })).status).toBe(404);
    const big = await client.post('/api/v1/auth/login/password', { identifier: 'ada@example.com', password: 'x'.repeat(1000) });
    expect(big.status).toBe(400);
    expect(big.json.error.details).toEqual({ reason: 'body_too_large' });
  });

  it('reports unexpected failures to onError and hides them from the caller', async () => {
    const { browser, env, unexpected } = await setup();
    env.adapter.users.findByIdentifier = async () => {
      throw new Error('database "prod-secret-host" is unreachable');
    };
    const response = await (await browser()).post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.status).toBe(500);
    expect(response.json).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
    expect(response.text).not.toContain('prod-secret-host');
    expect(unexpected).toHaveLength(1);
  });

  it('answers the preflight a browser sends from an allowed origin, and refuses others', async () => {
    const { browser } = await setup();
    const client = await browser();
    const preflight = { proof: false, headers: { 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type,dpop' } };

    const allowed = await client.request('OPTIONS', '/auth/refresh', preflight);
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);
    expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
    expect(allowed.headers.get('access-control-allow-headers')).toBe('Authorization, Content-Type, DPoP');

    const refused = await client.request('OPTIONS', '/auth/refresh', { ...preflight, origin: 'https://evil.example' });
    expect(refused.status).toBe(403);
    expect(refused.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('answers with a 500 and reports it when clientIp throws, instead of carrying on without an address', async () => {
    let broken = false;
    const { browser, unexpected } = await setup({
      adapter: {
        clientIp: () => {
          if (broken) throw new TypeError('no connection information');
          return '198.51.100.7';
        },
      },
    });
    const client = await browser();
    const { accessToken } = await login(client);
    broken = true;

    const endpoint = await client.post('/auth/refresh');
    expect(endpoint.status).toBe(500);
    expect(endpoint.json).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
    const route = await client.get('/invoices/ada-1', { token: accessToken });
    expect(route.status).toBe(500);
    expect(route.json).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
    expect(unexpected).toHaveLength(2);
    expect(unexpected.every((error) => error instanceof TypeError)).toBe(true);

    // The failed attempts consumed nothing: the same refresh token still works.
    broken = false;
    expect((await client.post('/auth/refresh')).status).toBe(200);
  });
});

describe('honoAuth requireAuth', () => {
  it('lets a valid token through and exposes the verified identity, typed, on the context', async () => {
    const { browser, ada } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    const response = await client.get('/invoices/ada-1', { token: accessToken });
    expect(response.status).toBe(200);
    expect(response.json).toEqual({ id: 'ada-1', viewer: ada.id });
  });

  it('checks the proof against the public origin, not the address the server sees, and ignores the query string', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    // The test delivers every request to http://10.0.0.5:3000. The proof names https://api.example.com.
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
    const proof = await createDpopProof(client.key, { method: 'GET', url: `${API_ORIGIN}/invoices/other`, nowMs: env.clock(), accessToken });
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

  it('demands step-up when the route needs aal2, and accepts the token afterwards', async () => {
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

  it('demands step-up when the sign-in is older than the route allows', async () => {
    const { browser, env } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    expect((await client.get('/recent', { token: accessToken })).status).toBe(200);
    env.clock.advanceSec(301);
    const stale = await client.get('/recent', { token: accessToken });
    expect(stale.status).toBe(403);
    expect(stale.json.error.details).toEqual({ required: 'recent_authentication', maxAuthAgeSec: 300 });
  });

  it('leaves the request body for the route handler', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    const response = await client.request('PUT', '/invoices/ada-1', { token: accessToken, body: { note: 'paid' } });
    expect(response.json).toEqual({ updated: 'ada-1', received: { note: 'paid' } });
  });
});

describe('honoAuth requirePermission', () => {
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
      ip: '198.51.100.7',
      data: { action: 'invoice:write', policy: 'change-own-invoice-only', decisionReason: 'invoice belongs to another user' },
    });
  });

  it('passes the loaded resource to the policies', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client);
    expect((await client.request('PUT', '/invoices/ada-1', { token: accessToken, body: {} })).status).toBe(200);
    const other = await client.request('PUT', '/invoices/bob-1', { token: accessToken, body: {} });
    expect(other.status).toBe(403);
    expect(other.json.error.details.reason).toBe('invoice belongs to another user');
  });
});

describe('honoAuth onError and getAuth', () => {
  it('formats auth errors thrown in a handler', async () => {
    const { browser } = await setup();
    const client = await browser();
    const { accessToken } = await login(client, 'vera@example.com');
    const response = await client.post('/invoices/ada-1/archive', undefined, { token: accessToken });
    expect(response.status).toBe(403);
    expect(response.json.error).toMatchObject({ code: 'FORBIDDEN', details: { policy: 'default', action: 'invoice:delete' } });
  });

  it('answers other errors with a generic 500 and reports them', async () => {
    const { browser, unexpected } = await setup();
    const response = await (await browser()).get('/broken', { proof: false });
    expect(response.status).toBe(500);
    expect(response.json).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
    expect(String(unexpected[0])).toContain('not an auth error');
  });

  it('can be combined with an application’s own error handling', async () => {
    const { browser, unexpected } = await setup({
      onError: (parts) => (error, c) => (isAuthError(error) ? parts.onError(error, c) : c.json({ handledBy: 'application' }, 418)),
    });
    const client = await browser();
    const mine = await client.get('/broken', { proof: false });
    expect(mine.status).toBe(418);
    expect(mine.json).toEqual({ handledBy: 'application' });
    expect(unexpected).toEqual([]);

    const { accessToken } = await login(client, 'vera@example.com');
    const theirs = await client.post('/invoices/ada-1/archive', undefined, { token: accessToken });
    expect(theirs.status).toBe(403);
    expect(theirs.json.error.code).toBe('FORBIDDEN');
  });

  it('getAuth throws TOKEN_MISSING on a route that did not use requireAuth', async () => {
    const { browser } = await setup();
    const response = await (await browser()).get('/who', { proof: false });
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('TOKEN_MISSING');
  });
});
