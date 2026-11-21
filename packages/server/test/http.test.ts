import { describe, expect, it } from 'vitest';
import type { AuthConfig } from '../src/config.js';
import { createAuthHandler, createHttpAuthContext, type AuthHandlerOptions } from '../src/http/index.js';
import { SoftwareAuthenticator } from './authenticator.js';
import { TestBrowser } from './browser.js';
import { API_ORIGIN, APP_ORIGIN, PASSWORD, createAuthEnv, createUser, enrollTotp, totpCode, type AuthEnv } from './env.js';
import { createDpopKey, createDpopProof } from './helpers.js';

const COOKIE = '__Host-rt';

async function setup(config: Partial<AuthConfig> = {}, handlerOptions: Partial<AuthHandlerOptions> = {}) {
  const env = createAuthEnv(config);
  const user = await createUser(env);
  const errors: unknown[] = [];
  const handler = createAuthHandler(env.auth, {
    publicOrigin: API_ORIGIN,
    allowedOrigins: [APP_ORIGIN],
    clientIp: (request) => request.headers.get('x-real-ip') ?? '203.0.113.10',
    onError: (error) => errors.push(error),
    ...handlerOptions,
  });
  const browser = new TestBrowser(handler, await createDpopKey(), env.clock);
  return { env, user, handler, browser, errors };
}

async function newBrowser(env: AuthEnv, handler: (request: Request) => Promise<Response>) {
  return new TestBrowser(handler, await createDpopKey(), env.clock);
}

async function login(browser: TestBrowser, identifier = 'ada@example.com', password = PASSWORD) {
  const response = await browser.post('/auth/login/password', { identifier, password });
  expect(response.status).toBe(200);
  return response.json as { accessToken: string; accessTokenExpiresAt: number; user: { id: string }; session: { id: string } };
}

describe('login over HTTP', () => {
  it('returns the access token in the body and the refresh token only in a cookie', async () => {
    const { browser, user } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });

    expect(response.status).toBe(200);
    expect(Object.keys(response.json).sort()).toEqual(['accessToken', 'accessTokenExpiresAt', 'session', 'status', 'user']);
    expect(response.json).toMatchObject({ status: 'authenticated', user: { id: user.id, identifier: 'ada@example.com' } });

    expect(response.setCookies).toHaveLength(1);
    const cookie = response.setCookies[0]!;
    expect(cookie).toMatch(/^__Host-rt=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=604800; HttpOnly; Secure; SameSite=Strict$/);
    const refreshToken = browser.cookies.get(COOKIE)!;
    expect(response.text).not.toContain(refreshToken);
    expect(response.text).not.toContain('refreshToken');
  });

  it('marks responses as not cacheable and as JSON', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toBe('application/json; charset=utf-8');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('sends errors in a fixed envelope with the right status', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: 'not the password' });
    expect(response.status).toBe(401);
    expect(response.json).toEqual({ error: { code: 'INVALID_CREDENTIALS', message: 'The credentials are not valid.' } });
    expect(response.setCookies).toEqual([]);
  });

  it('passes the client address and user agent through to risk scoring and the audit log', async () => {
    const { browser, env } = await setup();
    await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD }, { headers: { 'x-real-ip': '198.51.100.44' } });
    expect(env.sink.ofType('login.succeeded')[0]).toMatchObject({ ip: '198.51.100.44', userAgent: 'test-browser' });
  });

  it('answers 429 with Retry-After when throttled', async () => {
    const { browser } = await setup({ risk: { signals: [] } });
    for (let attempt = 0; attempt < 5; attempt++) {
      await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: 'wrong wrong wrong' });
    }
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('30');
    expect(response.json.error).toEqual({ code: 'RATE_LIMITED', message: 'Too many attempts. Try again later.', details: { retryAfterSec: 30 } });
  });

  it('completes a login with a second factor, setting the cookie only at the end', async () => {
    const { browser, env, user } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    env.clock.advanceSec(30);

    const first = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(first.status).toBe(200);
    expect(Object.keys(first.json).sort()).toEqual(['expiresAt', 'methods', 'reason', 'status', 'ticket']);
    expect(first.json).toMatchObject({ status: 'mfa_required', methods: ['totp', 'recovery_code'], reason: 'enrolled' });
    expect(first.setCookies).toEqual([]);

    const wrong = await browser.post('/auth/mfa/verify', { ticket: first.json.ticket, method: 'totp', code: '000000' });
    expect(wrong.status).toBe(401);
    expect(wrong.json.error.code).toBe('MFA_CODE_INVALID');

    const done = await browser.post('/auth/mfa/verify', { ticket: first.json.ticket, method: 'totp', code: await totpCode(env.clock, secret) });
    expect(done.status).toBe(200);
    expect(done.json.session).toMatchObject({ assurance: 'aal2', methods: ['pwd', 'otp'] });
    expect(browser.cookies.has(COOKIE)).toBe(true);
  });

  it('rejects a login without a DPoP proof, and one with two proofs', async () => {
    const { browser, env } = await setup();
    const none = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD }, { proof: false });
    expect(none.status).toBe(401);
    expect(none.json.error.code).toBe('DPOP_PROOF_REQUIRED');
    expect(none.headers.get('www-authenticate')).toBe('DPoP error="invalid_dpop_proof", algs="ES256"');

    const url = `${API_ORIGIN}/auth/login/password`;
    const one = await createDpopProof(browser.key, { method: 'POST', url, nowMs: env.clock() });
    const two = await createDpopProof(browser.key, { method: 'POST', url, nowMs: env.clock() });
    const doubled = await browser.post(
      '/auth/login/password',
      { identifier: 'ada@example.com', password: PASSWORD },
      { proof: false, headers: { dpop: `${one}, ${two}` } },
    );
    expect(doubled.status).toBe(401);
    expect(doubled.json.error.code).toBe('DPOP_PROOF_INVALID');
  });
});

describe('refresh over HTTP', () => {
  it('rotates the cookie and returns a new access token', async () => {
    const { browser } = await setup();
    const first = await login(browser);
    const before = browser.cookies.get(COOKIE)!;

    const response = await browser.post('/auth/refresh');
    expect(response.status).toBe(200);
    expect(response.json.status).toBe('authenticated');
    expect(response.json.accessToken).not.toBe(first.accessToken);
    expect(response.json.session.id).toBe(first.session.id);
    const after = browser.cookies.get(COOKIE)!;
    expect(after).not.toBe(before);
    expect(response.text).not.toContain(after);
  });

  it('revokes the session and clears the cookie when an old cookie is replayed', async () => {
    const { browser } = await setup();
    await login(browser);
    const stolen = browser.cookies.get(COOKIE)!;
    await browser.post('/auth/refresh');
    const current = browser.cookies.get(COOKIE)!;

    // The attacker replays the old cookie. They also need the device key, which here they have.
    browser.cookies.set(COOKIE, stolen);
    const replay = await browser.post('/auth/refresh');
    expect(replay.status).toBe(401);
    expect(replay.json.error.code).toBe('REFRESH_TOKEN_REUSED');
    expect(replay.setCookies).toEqual(['__Host-rt=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict']);
    expect(browser.cookies.has(COOKIE)).toBe(false);

    // The legitimate cookie is now useless too.
    browser.cookies.set(COOKIE, current);
    const legit = await browser.post('/auth/refresh');
    expect(legit.status).toBe(401);
    expect(legit.json.error.code).toBe('SESSION_REVOKED');
  });

  it('fails without a cookie', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/refresh');
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('REFRESH_TOKEN_MISSING');
  });

  it('keeps the cookie when the proof is missing, so the real device can still refresh', async () => {
    const { browser } = await setup();
    await login(browser);
    const withoutProof = await browser.post('/auth/refresh', undefined, { proof: false });
    expect(withoutProof.status).toBe(401);
    expect(withoutProof.json.error.code).toBe('DPOP_PROOF_REQUIRED');
    expect(withoutProof.setCookies).toEqual([]);
    expect((await browser.post('/auth/refresh')).status).toBe(200);
  });

  it('is useless to another device that has stolen the cookie', async () => {
    const { browser, env, handler } = await setup();
    await login(browser);
    const thief = await newBrowser(env, handler);
    thief.cookies.set(COOKIE, browser.cookies.get(COOKIE)!);
    const response = await thief.post('/auth/refresh');
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('DPOP_KEY_MISMATCH');
  });

  it('restores a session on page load: a fresh page with only the cookie gets an access token', async () => {
    const { browser } = await setup();
    const first = await login(browser);
    // A reload loses everything held in memory. The cookie and the device key survive.
    const restored = await browser.post('/auth/refresh');
    expect(restored.status).toBe(200);
    expect(restored.json.user.id).toBe(first.user.id);
  });
});

describe('cross-site request protection', () => {
  it('rejects cookie-authenticated requests from other origins or without an Origin header', async () => {
    const { browser } = await setup();
    await login(browser);
    for (const origin of ['https://evil.example', 'https://app.example.com.evil.example', 'null', null]) {
      for (const path of ['/auth/refresh', '/auth/logout', '/auth/logout/all']) {
        const response = await browser.post(path, undefined, { origin });
        expect(response.status).toBe(403);
        expect(response.json.error.code).toBe('ORIGIN_NOT_ALLOWED');
        expect(response.setCookies).toEqual([]);
      }
    }
    // Nothing above logged the user out or consumed the token.
    expect((await browser.post('/auth/refresh')).status).toBe(200);
  });

  it('rejects any request that names a foreign origin', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD }, { origin: 'https://evil.example' });
    expect(response.status).toBe(403);
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('allows non-browser clients, which send no Origin, on endpoints that do not use the cookie', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD }, { origin: null });
    expect(response.status).toBe(200);
  });

  it('only accepts JSON bodies, which a cross-site HTML form cannot send', async () => {
    const { browser } = await setup();
    for (const contentType of ['application/x-www-form-urlencoded', 'text/plain', 'multipart/form-data']) {
      const response = await browser.post('/auth/login/password', undefined, {
        rawBody: 'identifier=ada@example.com&password=x',
        headers: { 'content-type': contentType },
      });
      expect(response.status).toBe(400);
      expect(response.json.error).toEqual({
        code: 'REQUEST_INVALID',
        message: 'The request is not valid.',
        details: { reason: 'content_type_must_be_json' },
      });
    }
  });

  it('answers CORS preflight for allowed origins only', async () => {
    const { browser } = await setup();
    const allowed = await browser.request('OPTIONS', '/auth/refresh', { proof: false });
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);
    expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
    expect(allowed.headers.get('access-control-allow-methods')).toBe('GET, POST, DELETE');
    expect(allowed.headers.get('access-control-allow-headers')).toBe('Authorization, Content-Type, DPoP');
    expect(allowed.headers.get('vary')).toContain('Origin');

    const denied = await browser.request('OPTIONS', '/auth/refresh', { proof: false, origin: 'https://evil.example' });
    expect(denied.status).toBe(403);
    expect(denied.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('adds CORS headers to responses for allowed origins, and never a wildcard with credentials', async () => {
    const { browser } = await setup();
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.headers.get('access-control-allow-origin')).toBe(APP_ORIGIN);
    expect(response.headers.get('access-control-allow-credentials')).toBe('true');
    expect(response.headers.get('access-control-expose-headers')).toBe('Retry-After, WWW-Authenticate');
  });
});

describe('request validation', () => {
  it('rejects bodies that are not a JSON object', async () => {
    const { browser } = await setup();
    const cases: [string, string][] = [
      ['{not json', 'body_is_not_json'],
      ['[1,2,3]', 'body_must_be_an_object'],
      ['"text"', 'body_must_be_an_object'],
      ['null', 'body_must_be_an_object'],
    ];
    for (const [rawBody, reason] of cases) {
      const response = await browser.post('/auth/login/password', undefined, { rawBody, headers: { 'content-type': 'application/json' } });
      expect(response.status).toBe(400);
      expect(response.json.error.details).toEqual({ reason });
    }
  });

  it('rejects missing and mistyped fields, naming the field', async () => {
    const { browser } = await setup();
    const missing = await browser.post('/auth/login/password', { identifier: 'ada@example.com' });
    expect(missing.status).toBe(400);
    expect(missing.json.error.details).toEqual({ field: 'password' });
    const mistyped = await browser.post('/auth/login/password', { identifier: ['ada@example.com'], password: PASSWORD });
    expect(mistyped.json.error.details).toEqual({ field: 'identifier' });
    const method = await browser.post('/auth/mfa/verify', { ticket: 't', method: 'sms', code: '1' });
    expect(method.json.error.details).toEqual({ field: 'method' });
  });

  it('rejects oversized bodies', async () => {
    const { browser } = await setup({}, { maxBodyBytes: 200 });
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: 'x'.repeat(500) });
    expect(response.status).toBe(400);
    expect(response.json.error.details).toEqual({ reason: 'body_too_large' });
  });

  it('answers 404 for unknown paths and wrong methods', async () => {
    const { browser } = await setup();
    for (const [method, path] of [
      ['POST', '/auth/nope'],
      ['GET', '/auth/login/password'],
      ['POST', '/auth/session'],
      ['GET', '/other'],
      ['GET', '/auth'],
      ['POST', '/.well-known/jwks.json'],
      ['DELETE', '/auth/sessions/'],
    ] as const) {
      const response = await browser.request(method, path);
      expect(response.status).toBe(404);
      expect(response.json).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found.' } });
    }
  });

  it('hides unexpected failures behind a generic 500 and reports them to the application', async () => {
    const { browser, env, errors } = await setup();
    env.adapter.users.findByIdentifier = async () => {
      throw new Error('connection to database "prod-secret-host" failed');
    };
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.status).toBe(500);
    expect(response.json).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
    expect(response.text).not.toContain('prod-secret-host');
    expect(errors).toHaveLength(1);
    expect(String(errors[0])).toContain('prod-secret-host');
  });

  it('validates its own options', () => {
    const env = createAuthEnv();
    expect(() => createAuthHandler(env.auth, { publicOrigin: 'https://api.example.com/' })).toThrow(/bare origin/);
    expect(() => createAuthHandler(env.auth, { publicOrigin: 'https://api.example.com/auth' })).toThrow(/bare origin/);
    expect(() => createAuthHandler(env.auth, { publicOrigin: 'api.example.com' })).toThrow(/not a URL/);
    expect(() => createAuthHandler(env.auth, { publicOrigin: API_ORIGIN, allowedOrigins: ['*'] })).toThrow(/not a URL/);
    expect(() => createAuthHandler(env.auth, { publicOrigin: API_ORIGIN, basePath: 'auth' })).toThrow(/basePath/);
    expect(() => createAuthHandler(env.auth, { publicOrigin: API_ORIGIN, basePath: '/auth/' })).toThrow(/basePath/);
  });

  it('serves under a custom base path', async () => {
    const { browser } = await setup({}, { basePath: '/api/v1/auth' });
    const response = await browser.post('/api/v1/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.status).toBe(200);
    expect((await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD })).status).toBe(404);
  });
});

describe('authenticated endpoints', () => {
  it('returns the current user, session and factors', async () => {
    const { browser, user } = await setup();
    const { accessToken, session } = await login(browser);
    const response = await browser.get('/auth/session', { token: accessToken });
    expect(response.status).toBe(200);
    expect(response.json).toMatchObject({
      user: { id: user.id, identifier: 'ada@example.com', roles: ['editor'] },
      session: { id: session.id, current: true, assurance: 'aal1' },
      security: { totp: false, recoveryCodes: 0, passkeys: 0 },
    });
  });

  it('requires an access token', async () => {
    const { browser } = await setup();
    const response = await browser.get('/auth/session');
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('TOKEN_MISSING');
    expect(response.headers.get('www-authenticate')).toBe('DPoP error="invalid_token", algs="ES256"');

    for (const header of ['Basic abc', 'DPoP', 'Bearer a b', 'token']) {
      const bad = await browser.get('/auth/session', { headers: { authorization: header } });
      expect(bad.json.error.code).toBe('TOKEN_MISSING');
    }
  });

  it('rejects a stolen access token: without the device key it cannot be used', async () => {
    const { browser, env, handler } = await setup();
    const { accessToken } = await login(browser);

    const noProof = await browser.get('/auth/session', { token: accessToken, proof: false });
    expect(noProof.status).toBe(401);
    expect(noProof.json.error.code).toBe('DPOP_PROOF_REQUIRED');

    const thief = await newBrowser(env, handler);
    const wrongKey = await thief.get('/auth/session', { token: accessToken });
    expect(wrongKey.status).toBe(401);
    expect(wrongKey.json.error.code).toBe('DPOP_KEY_MISMATCH');

    // Downgrading the scheme to Bearer does not get around the binding.
    const bearer = await thief.get('/auth/session', { token: accessToken, scheme: 'Bearer', proof: false });
    expect(bearer.json.error.code).toBe('DPOP_PROOF_REQUIRED');
  });

  it('rejects the access token of a revoked session at once on these endpoints', async () => {
    const { browser, env } = await setup();
    const { accessToken, session } = await login(browser);
    await env.auth.sessions.revoke(session.id);
    const response = await browser.get('/auth/session', { token: accessToken });
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('SESSION_REVOKED');
  });

  it('accepts Bearer for tokens that are not bound to a key', async () => {
    const { browser } = await setup({ dpop: { mode: 'off' } });
    const { accessToken } = await login(browser);
    const response = await browser.get('/auth/session', { token: accessToken, scheme: 'Bearer', proof: false });
    expect(response.status).toBe(200);
    expect(response.json.session.deviceBound).toBe(false);
  });

  it('lists sessions and revokes one, but only the caller’s own', async () => {
    const { browser, env, handler } = await setup();
    const laptop = await login(browser);
    const phoneBrowser = await newBrowser(env, handler);
    const phone = await login(phoneBrowser);

    const list = await browser.get('/auth/sessions', { token: laptop.accessToken });
    expect(list.json.sessions.map((session: { id: string; current: boolean }) => [session.id, session.current]).sort()).toEqual(
      [
        [laptop.session.id, true],
        [phone.session.id, false],
      ].sort(),
    );

    const revoked = await browser.delete(`/auth/sessions/${phone.session.id}`, { token: laptop.accessToken });
    expect(revoked.status).toBe(204);
    expect(revoked.text).toBe('');
    expect((await phoneBrowser.post('/auth/refresh')).json.error.code).toBe('SESSION_REVOKED');

    await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    const bobBrowser = await newBrowser(env, handler);
    const bob = await login(bobBrowser, 'bob@example.com');
    const foreign = await bobBrowser.delete(`/auth/sessions/${laptop.session.id}`, { token: bob.accessToken });
    expect(foreign.status).toBe(404);
    expect((await browser.post('/auth/refresh')).status).toBe(200);
  });

  it('clears the cookie when the caller revokes their own current session', async () => {
    const { browser } = await setup();
    const { accessToken, session } = await login(browser);
    const response = await browser.delete(`/auth/sessions/${session.id}`, { token: accessToken });
    expect(response.status).toBe(204);
    expect(browser.cookies.has(COOKIE)).toBe(false);
  });

  it('logs out and clears the cookie', async () => {
    const { browser, env, user } = await setup();
    await login(browser);
    const response = await browser.post('/auth/logout');
    expect(response.status).toBe(204);
    expect(response.setCookies).toEqual(['__Host-rt=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict']);
    expect(await env.auth.sessions.list(user.id)).toEqual([]);
    // Logging out twice is harmless.
    expect((await browser.post('/auth/logout')).status).toBe(204);
  });

  it('logs out everywhere', async () => {
    const { browser, env, handler, user } = await setup();
    await login(browser);
    await login(await newBrowser(env, handler));
    expect(await env.auth.sessions.list(user.id)).toHaveLength(2);
    expect((await browser.post('/auth/logout/all')).status).toBe(204);
    expect(await env.auth.sessions.list(user.id)).toEqual([]);
  });

  it('changes the password, keeps this session and ends the others', async () => {
    const { browser, env, handler } = await setup();
    const { accessToken } = await login(browser);
    const other = await newBrowser(env, handler);
    await login(other);

    const wrong = await browser.post('/auth/password', { currentPassword: 'nope nope nope', newPassword: 'a brand new password' }, { token: accessToken });
    expect(wrong.status).toBe(401);
    const weak = await browser.post('/auth/password', { currentPassword: PASSWORD, newPassword: 'short' }, { token: accessToken });
    expect(weak.status).toBe(400);
    expect(weak.json.error).toMatchObject({ code: 'PASSWORD_POLICY_VIOLATION', details: { reason: 'too_short' } });

    const ok = await browser.post('/auth/password', { currentPassword: PASSWORD, newPassword: 'a brand new password' }, { token: accessToken });
    expect(ok.status).toBe(204);
    expect((await browser.post('/auth/refresh')).status).toBe(200);
    expect((await other.post('/auth/refresh')).json.error.code).toBe('SESSION_REVOKED');
  });
});

describe('sensitive account changes need a recent authentication', () => {
  it('asks for step-up after ten minutes and accepts the change after re-authenticating', async () => {
    const { browser, env } = await setup();
    const { accessToken } = await login(browser);

    const fresh = await browser.post('/auth/mfa/totp/enroll', undefined, { token: accessToken });
    expect(fresh.status).toBe(200);

    // Keep the session alive past ten minutes with a refresh, which does not count as authenticating.
    env.clock.advanceSec(601);
    const refreshed = (await browser.post('/auth/refresh')).json;
    const stale = await browser.post('/auth/mfa/totp/enroll', undefined, { token: refreshed.accessToken });
    expect(stale.status).toBe(403);
    expect(stale.json.error).toEqual({
      code: 'STEP_UP_REQUIRED',
      message: 'This action needs a stronger or more recent authentication.',
      details: { required: 'recent_authentication', maxAuthAgeSec: 600 },
    });

    const reauth = await browser.post('/auth/reauthenticate', { method: 'password', password: PASSWORD }, { token: refreshed.accessToken });
    expect(reauth.status).toBe(200);
    expect(reauth.json.status).toBe('authenticated');
    expect(reauth.setCookies).toEqual([]);
    const again = await browser.post('/auth/mfa/totp/enroll', undefined, { token: reauth.json.accessToken });
    expect(again.status).toBe(200);
  });

  it('applies to every endpoint that changes how the account is secured', async () => {
    const { browser, env } = await setup();
    await login(browser);
    env.clock.advanceSec(601);
    const { accessToken } = (await browser.post('/auth/refresh')).json;
    const sensitive: [string, string, unknown?][] = [
      ['POST', '/auth/mfa/totp/enroll'],
      ['POST', '/auth/mfa/totp/confirm', { enrollmentId: 'x', code: '123456' }],
      ['DELETE', '/auth/mfa/totp'],
      ['POST', '/auth/mfa/recovery-codes'],
      ['POST', '/auth/passkeys/options'],
      ['POST', '/auth/passkeys', { challengeId: 'x', response: {} }],
      ['DELETE', '/auth/passkeys/some-id'],
    ];
    for (const [method, path, body] of sensitive) {
      const response = await browser.request(method, path, { token: accessToken, ...(body !== undefined ? { body } : {}) });
      expect([path, response.status, response.json.error.code]).toEqual([path, 403, 'STEP_UP_REQUIRED']);
    }
    // Reading is still allowed.
    expect((await browser.get('/auth/passkeys', { token: accessToken })).status).toBe(200);
    expect((await browser.get('/auth/sessions', { token: accessToken })).status).toBe(200);
  });

  it('rejects a wrong password on re-authentication', async () => {
    const { browser } = await setup();
    const { accessToken } = await login(browser);
    const response = await browser.post('/auth/reauthenticate', { method: 'password', password: 'not it at all' }, { token: accessToken });
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('INVALID_CREDENTIALS');
  });
});

describe('second factor management over HTTP', () => {
  it('enrols TOTP, uses it, regenerates recovery codes and removes it', async () => {
    const { browser, env, user } = await setup();
    const { accessToken } = await login(browser);

    const enrollment = await browser.post('/auth/mfa/totp/enroll', undefined, { token: accessToken });
    expect(Object.keys(enrollment.json).sort()).toEqual(['enrollmentId', 'otpauthUri', 'secret']);

    const confirmed = await browser.post(
      '/auth/mfa/totp/confirm',
      { enrollmentId: enrollment.json.enrollmentId, code: await totpCode(env.clock, enrollment.json.secret) },
      { token: accessToken },
    );
    expect(confirmed.status).toBe(200);
    expect(confirmed.json.recoveryCodes).toHaveLength(10);
    expect((await browser.get('/auth/session', { token: accessToken })).json.security).toEqual({ totp: true, recoveryCodes: 10, passkeys: 0 });

    env.clock.advanceSec(30);
    const stepUp = await browser.post('/auth/reauthenticate', { method: 'totp', code: await totpCode(env.clock, enrollment.json.secret) }, { token: accessToken });
    expect(stepUp.json.session.assurance).toBe('aal2');

    const regenerated = await browser.post('/auth/mfa/recovery-codes', undefined, { token: stepUp.json.accessToken });
    expect(regenerated.json.recoveryCodes).toHaveLength(10);
    expect(regenerated.json.recoveryCodes).not.toEqual(confirmed.json.recoveryCodes);

    const removed = await browser.delete('/auth/mfa/totp', { token: stepUp.json.accessToken });
    expect(removed.status).toBe(204);
    expect(await env.auth.mfa.status(user.id)).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });
  });
});

describe('passkeys over HTTP', () => {
  it('registers a passkey, signs in with it, lists and removes it', async () => {
    const { browser, env, handler, user } = await setup();
    const { accessToken } = await login(browser);
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });

    const options = await browser.post('/auth/passkeys/options', undefined, { token: accessToken });
    expect(options.status).toBe(200);
    const registered = await browser.post(
      '/auth/passkeys',
      { challengeId: options.json.challengeId, response: authenticator.create(options.json.options), name: 'Laptop' },
      { token: accessToken },
    );
    expect(registered.status).toBe(201);
    expect(registered.json).toMatchObject({ name: 'Laptop', backedUp: true });

    const list = await browser.get('/auth/passkeys', { token: accessToken });
    expect(list.json.passkeys.map((passkey: { id: string }) => passkey.id)).toEqual([registered.json.id]);

    // Sign in on a new browser with nothing but the passkey.
    const fresh = await newBrowser(env, handler);
    const loginOptions = await fresh.post('/auth/login/passkey/options', {});
    expect(loginOptions.status).toBe(200);
    const signedIn = await fresh.post('/auth/login/passkey', {
      challengeId: loginOptions.json.challengeId,
      response: authenticator.get(loginOptions.json.options),
    });
    expect(signedIn.status).toBe(200);
    expect(signedIn.json).toMatchObject({ status: 'authenticated', user: { id: user.id }, session: { assurance: 'aal2', methods: ['passkey'] } });
    expect(fresh.cookies.has(COOKIE)).toBe(true);

    const removed = await browser.delete(`/auth/passkeys/${registered.json.id}`, { token: accessToken });
    expect(removed.status).toBe(204);
    const missing = await browser.delete(`/auth/passkeys/${registered.json.id}`, { token: accessToken });
    expect(missing.status).toBe(404);
    expect(missing.json.error.code).toBe('PASSKEY_NOT_FOUND');
  });

  it('rejects a passkey response from the wrong origin', async () => {
    const { browser } = await setup();
    const { accessToken } = await login(browser);
    const phishing = new SoftwareAuthenticator({ origin: 'https://app.example.com.evil.example' });
    const options = await browser.post('/auth/passkeys/options', undefined, { token: accessToken });
    const response = await browser.post(
      '/auth/passkeys',
      { challengeId: options.json.challengeId, response: phishing.create(options.json.options) },
      { token: accessToken },
    );
    expect(response.status).toBe(401);
    expect(response.json.error.code).toBe('PASSKEY_VERIFICATION_FAILED');
  });
});

describe('JWKS endpoint', () => {
  it('serves public keys with caching headers, readable from any origin', async () => {
    const { browser } = await setup();
    await login(browser);
    const response = await browser.get('/.well-known/jwks.json', { proof: false, origin: 'https://files.example.com' });
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=600');
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    expect(response.headers.get('access-control-allow-credentials')).toBeNull();
    expect(response.json.keys).toHaveLength(1);
    expect(Object.keys(response.json.keys[0]).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
    expect(response.setCookies).toEqual([]);
  });
});

describe('cookie configuration', () => {
  it('uses the configured name, SameSite value, path and domain', async () => {
    const { browser } = await setup({
      sessions: { cookie: { name: '__Secure-session', sameSite: 'lax', path: '/auth', domain: 'example.com' } },
    });
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.setCookies[0]).toMatch(
      /^__Secure-session=[A-Za-z0-9_-]{43}; Path=\/auth; Max-Age=604800; HttpOnly; Secure; SameSite=Lax; Domain=example\.com$/,
    );
    expect((await browser.post('/auth/refresh')).status).toBe(200);
  });

  it('gives the cookie the lifetime of the refresh token', async () => {
    const { browser } = await setup({ sessions: { ttlSec: 7200, idleTtlSec: 1800 } });
    const response = await browser.post('/auth/login/password', { identifier: 'ada@example.com', password: PASSWORD });
    expect(response.setCookies[0]).toContain('Max-Age=1800;');
  });
});

describe('the refresh token never appears in a response body', () => {
  it('holds across a whole session, including error responses', async () => {
    const { browser, env, user } = await setup();
    const seen = new Set<string>();
    const remember = () => {
      const value = browser.cookies.get(COOKIE);
      if (value) seen.add(value);
    };

    const { accessToken } = await login(browser);
    remember();
    await browser.get('/auth/session', { token: accessToken });
    await browser.get('/auth/sessions', { token: accessToken });
    for (let index = 0; index < 3; index++) {
      await browser.post('/auth/refresh');
      remember();
    }
    await browser.post('/auth/reauthenticate', { method: 'password', password: PASSWORD }, { token: accessToken });
    const stale = [...seen][0]!;
    const current = browser.cookies.get(COOKIE)!;
    browser.cookies.set(COOKIE, stale);
    await browser.post('/auth/refresh');
    browser.cookies.set(COOKIE, current);
    await browser.post('/auth/refresh');
    await browser.post('/auth/logout');

    expect(seen.size).toBe(4);
    const everything = browser.bodies.join('\n');
    for (const token of seen) expect(everything).not.toContain(token);
    expect(JSON.stringify(env.sink.events)).not.toContain(stale);
    expect(JSON.stringify(await env.adapter.sessions.listByUser(user.id))).not.toContain(stale);
  });
});

describe('createHttpAuthContext', () => {
  it('authenticates requests to your own endpoints against the public URL', async () => {
    const { browser, env } = await setup();
    const { accessToken } = await login(browser);
    const http = createHttpAuthContext(env.auth, { publicOrigin: API_ORIGIN });

    const url = `${API_ORIGIN}/invoices/7`;
    const proof = await createDpopProof(browser.key, { method: 'GET', url, nowMs: env.clock(), accessToken });
    // The server may see an internal URL. Only the path is taken from it.
    const request = new Request('http://10.0.0.5:3000/invoices/7?expand=lines', {
      headers: { authorization: `DPoP ${accessToken}`, dpop: proof },
    });
    const verified = await http.authenticate(request);
    expect(verified.subject.roles).toEqual(['editor']);

    const weak = new Request('http://10.0.0.5:3000/invoices/7', {
      headers: {
        authorization: `DPoP ${accessToken}`,
        dpop: await createDpopProof(browser.key, { method: 'GET', url, nowMs: env.clock(), accessToken }),
      },
    });
    await expect(http.authenticate(weak, { assurance: 'aal2' })).rejects.toMatchObject({ code: 'STEP_UP_REQUIRED', details: { required: 'aal2' } });

    const response = http.errorResponse(new Error('boom'), request);
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong.' } });
  });
});
