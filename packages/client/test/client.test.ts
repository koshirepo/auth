import { isAuthError, type AuthError } from '@koshi-repo/auth-core';
import { EmbeddedJWK, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthClient, AuthState } from '../src/index.js';
import { createAuthClient } from '../src/index.js';
import {
  API_ORIGIN,
  BASE_URL,
  BrowserProfile,
  PASSWORD,
  createTestServer,
  createUser,
  settle,
  setup,
  signedInTab,
  totpCode,
  type TestServer,
} from './harness.js';

const tabs: AuthClient[] = [];

afterEach(() => {
  for (const tab of tabs.splice(0)) tab.dispose();
  vi.unstubAllGlobals();
});

/** Opens a tab and makes sure it is disposed after the test. */
function open(profile: BrowserProfile, options: Parameters<BrowserProfile['openTab']>[0] = {}): AuthClient {
  const tab = profile.openTab(options);
  tabs.push(tab);
  return tab;
}

async function login(profile: BrowserProfile, options: Parameters<BrowserProfile['openTab']>[0] = {}): Promise<AuthClient> {
  const tab = await signedInTab(profile, options);
  tabs.push(tab);
  return tab;
}

async function rejection(promise: Promise<unknown>): Promise<AuthError> {
  try {
    await promise;
  } catch (error) {
    if (!isAuthError(error)) throw error;
    return error;
  }
  throw new Error('Expected the call to be rejected');
}

async function enrolTotp(server: TestServer, userId: string): Promise<string> {
  const enrollment = await server.auth.mfa.beginTotpEnrollment(userId);
  await server.auth.mfa.confirmTotpEnrollment(userId, {
    enrollmentId: enrollment.enrollmentId,
    code: await totpCode(server.clock, enrollment.secret),
  });
  server.clock.advanceSec(30);
  return enrollment.secret;
}

describe('starting up', () => {
  it('starts in the loading state and settles on unauthenticated when there is no session', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    expect(tab.getState()).toEqual({ status: 'loading' });
    expect(await tab.ready()).toEqual({ status: 'unauthenticated' });
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(1);
  });

  it('restores the session from the cookie, as after a page reload', async () => {
    const { profile, user } = await setup();
    await login(profile);

    const reloaded = open(profile);
    const state = await reloaded.ready();
    expect(state).toMatchObject({ status: 'authenticated', user: { id: user.id, identifier: 'ada@example.com', roles: ['editor'] } });
    expect(typeof (await reloaded.getAccessToken())).toBe('string');
  });

  it('never rejects ready(), even when the server cannot be reached', async () => {
    const { profile } = await setup();
    profile.offline = true;
    const tab = open(profile);
    expect(await tab.ready()).toEqual({ status: 'unauthenticated' });
  });

  it('does not touch the network when told not to restore', async () => {
    const { profile } = await setup();
    const tab = open(profile, { restoreOnStart: false });
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
    expect(await tab.ready()).toEqual({ status: 'unauthenticated' });
    expect(profile.sent).toHaveLength(0);
  });

  it('needs an absolute base URL, or a page to resolve a relative one against', async () => {
    expect(() => createAuthClient({ baseUrl: '/auth', restoreOnStart: false, channel: null })).toThrow(/not an absolute URL/);

    const { profile } = await setup();
    vi.stubGlobal('location', { href: `${API_ORIGIN}/app/dashboard` });
    const tab = open(profile, { baseUrl: '/auth/' });
    await tab.ready();
    expect(profile.sent[0]).toMatchObject({ method: 'POST', path: '/auth/refresh' });
  });
});

describe('signing in', () => {
  it('signs in with a password and publishes the new state', async () => {
    const { profile, user } = await setup();
    const tab = open(profile);
    await tab.ready();
    const seen: AuthState[] = [];
    const unsubscribe = tab.subscribe((state) => seen.push(state));

    const state = await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    expect(state).toMatchObject({
      status: 'authenticated',
      user: { id: user.id },
      session: { methods: ['pwd'], assurance: 'aal1', deviceBound: true },
    });
    expect(tab.getState()).toBe(state);
    expect(seen).toEqual([state]);

    unsubscribe();
    await tab.logout();
    expect(seen).toHaveLength(1);
  });

  it('sends the login with a proof and with cookies enabled, and without an Authorization header', async () => {
    const { profile } = await setup();
    await login(profile);
    const [request] = profile.requestsTo('/auth/login/password');
    expect(request!.credentials).toBe('include');
    expect(request!.headers.get('dpop')).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(request!.headers.get('authorization')).toBeNull();
    expect(request!.headers.get('content-type')).toBe('application/json');
    expect(JSON.parse(request!.body!)).toEqual({ identifier: 'ada@example.com', password: PASSWORD });
  });

  it('rejects a wrong password with a typed error and stays signed out', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    const error = await rejection(tab.loginWithPassword({ identifier: 'ada@example.com', password: 'not the password' }));
    expect(error.code).toBe('INVALID_CREDENTIALS');
    expect(error.name).toBe('AuthenticationError');
    expect(error.message).toBe('The credentials are not valid.');
    expect(error.status).toBe(401);
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
  });

  it('reports an unreachable server as a network error', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    await tab.ready();
    profile.offline = true;
    const error = await rejection(tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD }));
    expect(error.code).toBe('NETWORK_ERROR');
    expect(error.name).toBe('NetworkError');
    expect((error.cause as Error).message).toBe('Failed to fetch');
  });

  it('carries server details through, for example how long to wait when throttled', async () => {
    const { profile } = await setup({ risk: { signals: [] } });
    const tab = open(profile);
    for (let attempt = 0; attempt < 5; attempt++) {
      await rejection(tab.loginWithPassword({ identifier: 'ada@example.com', password: 'wrong wrong wrong' }));
    }
    const error = await rejection(tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD }));
    expect(error.code).toBe('RATE_LIMITED');
    expect(error.details).toEqual({ retryAfterSec: 30 });
  });

  it('keeps going when a subscriber throws', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    let healthy = 0;
    tab.subscribe(() => {
      throw new Error('broken listener');
    });
    tab.subscribe(() => healthy++);
    const state = await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    expect(state.status).toBe('authenticated');
    expect(healthy).toBeGreaterThan(0);
  });
});

describe('second factor', () => {
  it('moves through mfa_required to authenticated', async () => {
    const { profile, server, user } = await setup();
    const secret = await enrolTotp(server, user.id);
    const tab = open(profile);

    const pending = await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    expect(pending).toMatchObject({ status: 'mfa_required', methods: ['totp', 'recovery_code'], reason: 'enrolled' });
    // The ticket is kept inside the client. It is not part of the state handed to the interface.
    expect(Object.keys(pending).sort()).toEqual(['expiresAt', 'methods', 'reason', 'status']);
    expect(await tab.getAccessToken()).toBeNull();

    const wrong = await rejection(tab.submitMfa({ method: 'totp', code: '000000' }));
    expect(wrong.code).toBe('MFA_CODE_INVALID');
    expect(tab.getState().status).toBe('mfa_required');

    const done = await tab.submitMfa({ method: 'totp', code: await totpCode(server.clock, secret) });
    expect(done).toMatchObject({ status: 'authenticated', session: { assurance: 'aal2', methods: ['pwd', 'otp'] } });
    expect(typeof (await tab.getAccessToken())).toBe('string');
  });

  it('accepts a recovery code', async () => {
    const { profile, server, user } = await setup();
    const enrollment = await server.auth.mfa.beginTotpEnrollment(user.id);
    const { recoveryCodes } = await server.auth.mfa.confirmTotpEnrollment(user.id, {
      enrollmentId: enrollment.enrollmentId,
      code: await totpCode(server.clock, enrollment.secret),
    });
    const tab = open(profile);
    await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    const done = await tab.submitMfa({ method: 'recovery_code', code: recoveryCodes[0]!.toLowerCase() });
    expect(done).toMatchObject({ status: 'authenticated', session: { methods: ['pwd', 'recovery'] } });
  });

  it('returns to signed out when the ticket has expired', async () => {
    const { profile, server, user } = await setup();
    const secret = await enrolTotp(server, user.id);
    const tab = open(profile);
    await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    server.clock.advanceSec(301);
    const error = await rejection(tab.submitMfa({ method: 'totp', code: await totpCode(server.clock, secret) }));
    expect(error.code).toBe('MFA_TICKET_INVALID');
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
  });

  it('can be cancelled, and refuses a code when no login is waiting', async () => {
    const { profile, server, user } = await setup();
    await enrolTotp(server, user.id);
    const tab = open(profile);
    await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    tab.cancelMfa();
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });

    const before = profile.sent.length;
    const error = await rejection(tab.submitMfa({ method: 'totp', code: '123456' }));
    expect(error.code).toBe('MFA_TICKET_INVALID');
    expect(profile.sent.length).toBe(before);
  });
});

describe('where the tokens are kept', () => {
  it('keeps the access token out of reach: not on the client, not in state, not in any storage', async () => {
    const storage = () => {
      const data = new Map<string, string>();
      return {
        data,
        getItem: vi.fn((key: string) => data.get(key) ?? null),
        setItem: vi.fn((key: string, value: string) => void data.set(key, value)),
        removeItem: vi.fn((key: string) => void data.delete(key)),
        clear: vi.fn(() => data.clear()),
      };
    };
    const local = storage();
    const session = storage();
    let documentCookie = '';
    const cookieWrites: string[] = [];
    vi.stubGlobal('localStorage', local);
    vi.stubGlobal('sessionStorage', session);
    vi.stubGlobal('document', {
      get cookie() {
        return documentCookie;
      },
      set cookie(value: string) {
        cookieWrites.push(value);
        documentCookie = value;
      },
    });

    const { profile } = await setup();
    const tab = await login(profile);
    const token = (await tab.getAccessToken())!;
    await tab.fetch(`${API_ORIGIN}/api/me`);
    profile.server.clock.advanceSec(900);
    const refreshed = (await tab.getAccessToken())!;
    expect(refreshed).not.toBe(token);

    // Nothing reachable from the client object holds a token.
    const reachable: unknown[] = [];
    const walk = (value: unknown, depth = 0) => {
      if (depth > 4 || value === null || (typeof value !== 'object' && typeof value !== 'function')) {
        reachable.push(value);
        return;
      }
      for (const key of Reflect.ownKeys(value as object)) walk((value as Record<PropertyKey, unknown>)[key], depth + 1);
    };
    walk(tab);
    for (const secret of [token, refreshed]) {
      expect(reachable).not.toContain(secret);
      expect(JSON.stringify(tab)).not.toContain(secret);
      expect(JSON.stringify(tab.getState())).not.toContain(secret);
    }

    // Web Storage and document.cookie were never written.
    for (const store of [local, session]) {
      expect(store.setItem).not.toHaveBeenCalled();
      expect(store.data.size).toBe(0);
    }
    expect(cookieWrites).toEqual([]);

    // Other tabs are told that something happened, never what the token is.
    expect(profile.broadcasts).toEqual([{ type: 'signed-in' }]);

    // The only cookie is the refresh cookie, which script cannot read in a real browser.
    expect([...profile.cookies.keys()]).toEqual(['__Host-rt']);
    expect(profile.cookies.get('__Host-rt')).not.toBe(token);
  });

  it('never receives the refresh token in a response body', async () => {
    const { profile } = await setup();
    const bodies: string[] = [];
    const recordingFetch: typeof fetch = async (input, init) => {
      const response = await profile.fetch(input, init);
      bodies.push(await response.clone().text());
      return response;
    };
    const tab = open(profile, { fetch: recordingFetch });
    await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    const cookies = [profile.cookies.get('__Host-rt')!];
    await tab.getAccessToken({ forceRefresh: true });
    cookies.push(profile.cookies.get('__Host-rt')!);
    expect(cookies[0]).not.toBe(cookies[1]);
    for (const cookie of cookies) expect(bodies.join('\n')).not.toContain(cookie);
  });
});

describe('automatic refresh', () => {
  it('reuses the access token until shortly before it expires', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const before = profile.requestsTo('/auth/refresh').length;
    const token = await tab.getAccessToken();

    server.clock.advanceSec(869);
    expect(await tab.getAccessToken()).toBe(token);
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(before);

    // Thirty seconds before expiry the client refreshes instead of handing out a token that is about to die.
    server.clock.advanceSec(2);
    const next = await tab.getAccessToken();
    expect(next).not.toBe(token);
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(before + 1);
    expect(decodeJwt(next!).exp).toBe(Math.floor(server.clock() / 1000) + 900);
  });

  it('honours a configured refresh margin', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile, { refreshSkewSec: 300 });
    const token = await tab.getAccessToken();
    server.clock.advanceSec(599);
    expect(await tab.getAccessToken()).toBe(token);
    server.clock.advanceSec(2);
    expect(await tab.getAccessToken()).not.toBe(token);
  });

  it('makes one refresh request for many concurrent callers', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const before = profile.requestsTo('/auth/refresh').length;
    server.clock.advanceSec(880);

    const tokens = await Promise.all(Array.from({ length: 25 }, () => tab.getAccessToken()));
    expect(new Set(tokens).size).toBe(1);
    expect(typeof tokens[0]).toBe('string');
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(before + 1);
    expect(tab.getState().status).toBe('authenticated');
  });

  it('shares one refresh between concurrent fetches too', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const before = profile.requestsTo('/auth/refresh').length;
    server.clock.advanceSec(880);

    const responses = await Promise.all(Array.from({ length: 8 }, () => tab.fetch(`${API_ORIGIN}/api/me`)));
    expect(responses.map((response) => response.status)).toEqual(Array(8).fill(200));
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(before + 1);
  });

  it('refreshes on demand', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    const token = await tab.getAccessToken();
    const forced = await tab.getAccessToken({ forceRefresh: true });
    expect(forced).not.toBe(token);
    expect(await tab.getAccessToken()).toBe(forced);
  });

  it('signs out when the server says the session is over', async () => {
    const { profile, server, user } = await setup();
    const tab = await login(profile);
    await server.auth.sessions.revokeAll(user.id);
    expect(await tab.getAccessToken({ forceRefresh: true })).toBeNull();
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
    expect(await tab.getAccessToken()).toBeNull();
    // The dead cookie was removed by the server's response.
    expect(profile.cookies.size).toBe(0);
  });

  it('keeps the session when a refresh fails for a reason that says nothing about it', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);

    profile.offline = true;
    expect((await rejection(tab.getAccessToken({ forceRefresh: true }))).code).toBe('NETWORK_ERROR');
    expect(tab.getState().status).toBe('authenticated');
    profile.offline = false;

    server.failNext('/auth/refresh', 500);
    expect((await rejection(tab.getAccessToken({ forceRefresh: true }))).code).toBe('INTERNAL_ERROR');
    expect(tab.getState().status).toBe('authenticated');

    expect(typeof (await tab.getAccessToken({ forceRefresh: true }))).toBe('string');
  });

  it('returns null without a request when signed out', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    await tab.ready();
    const before = profile.sent.length;
    expect(await tab.getAccessToken()).toBeNull();
    expect(await tab.getAccessToken({ forceRefresh: true })).toBeNull();
    expect(profile.sent.length).toBe(before);
  });
});

describe('fetch', () => {
  it('attaches the access token and a proof bound to it', async () => {
    const { profile, user } = await setup();
    const tab = await login(profile);
    const response = await tab.fetch(`${API_ORIGIN}/api/me?expand=profile`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: user.id, roles: ['editor'], query: '?expand=profile' });

    const [request] = profile.requestsTo('/api/me');
    const token = await tab.getAccessToken();
    expect(request!.headers.get('authorization')).toBe(`DPoP ${token}`);
    // Requests to your API do not carry the refresh cookie.
    expect(request!.credentials).not.toBe('include');
  });

  it('refreshes once and retries once on a 401', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const refreshes = profile.requestsTo('/auth/refresh').length;
    server.failNext('/api/me', 401);

    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(200);
    expect(profile.requestsTo('/api/me')).toHaveLength(2);
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(refreshes + 1);
    const [first, second] = profile.requestsTo('/api/me');
    expect(second!.headers.get('authorization')).not.toBe(first!.headers.get('authorization'));
    expect(second!.headers.get('dpop')).not.toBe(first!.headers.get('dpop'));
  });

  it('gives up after one retry instead of looping', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const refreshes = profile.requestsTo('/auth/refresh').length;
    server.failNext('/api/me', 401, 10);

    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(401);
    expect(profile.requestsTo('/api/me')).toHaveLength(2);
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(refreshes + 1);
    expect(tab.getState().status).toBe('authenticated');
  });

  it('sends the request body again on the retry', async () => {
    const { profile, server, user } = await setup();
    const tab = await login(profile);
    server.failNext('/api/echo', 401);
    const response = await tab.fetch(`${API_ORIGIN}/api/echo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ amount: 42, note: 'retry me' }),
    });
    expect(await response.json()).toEqual({ id: user.id, received: { amount: 42, note: 'retry me' } });
    expect(profile.requestsTo('/api/echo').map((request) => request.body)).toEqual([
      '{"amount":42,"note":"retry me"}',
      '{"amount":42,"note":"retry me"}',
    ]);
  });

  it('accepts a Request object', async () => {
    const { profile, user } = await setup();
    const tab = await login(profile);
    const response = await tab.fetch(
      new Request(`${API_ORIGIN}/api/echo`, { method: 'POST', body: '{"x":1}', headers: { 'content-type': 'application/json' } }),
    );
    expect(await response.json()).toEqual({ id: user.id, received: { x: 1 } });
  });

  it('keeps the caller’s own headers', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    await tab.fetch(`${API_ORIGIN}/api/me`, { headers: { 'x-request-id': 'abc-123', accept: 'application/json' } });
    const [request] = profile.requestsTo('/api/me');
    expect(request!.headers.get('x-request-id')).toBe('abc-123');
    expect(request!.headers.get('accept')).toBe('application/json');
  });

  it('sends the request without credentials when signed out and returns the answer as it is', async () => {
    const { profile } = await setup();
    const tab = open(profile);
    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(401);
    const [request] = profile.requestsTo('/api/me');
    expect(request!.headers.get('authorization')).toBeNull();
    expect(request!.headers.get('dpop')).toBeNull();
    expect(profile.requestsTo('/api/me')).toHaveLength(1);
  });

  it('returns the 401 and signs out when the session has ended', async () => {
    const { profile, server, user } = await setup();
    const tab = await login(profile);
    await server.auth.sessions.revokeAll(user.id);
    server.failNext('/api/me', 401);
    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(401);
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
  });

  it('rejects when the token has to be refreshed and the server cannot be reached', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    server.clock.advanceSec(900);
    profile.offline = true;
    expect((await rejection(tab.fetch(`${API_ORIGIN}/api/me`))).code).toBe('NETWORK_ERROR');
    expect(tab.getState().status).toBe('authenticated');
  });
});

describe('device binding', () => {
  it('signs every request with a DPoP proof the server can verify', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    await tab.fetch(`${API_ORIGIN}/api/me?page=2#section`);
    const token = (await tab.getAccessToken())!;

    const [apiRequest] = profile.requestsTo('/api/me');
    const proof = apiRequest!.headers.get('dpop')!;
    const header = decodeProtectedHeader(proof);
    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(Object.keys(header.jwk!).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(header.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });

    const { payload } = await jwtVerify(proof, EmbeddedJWK, { typ: 'dpop+jwt', currentDate: new Date(server.clock()) });
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
    expect(payload).toEqual({
      jti: expect.stringMatching(/^[0-9a-f-]{36}$/),
      htm: 'GET',
      // No query string and no fragment.
      htu: `${API_ORIGIN}/api/me`,
      iat: Math.floor(server.clock() / 1000),
      ath: Buffer.from(digest).toString('base64url'),
    });

    // A proof for a request without a token has no token hash.
    const loginProof = decodeJwt(profile.requestsTo('/auth/login/password')[0]!.headers.get('dpop')!);
    expect(loginProof).toMatchObject({ htm: 'POST', htu: `${BASE_URL}/login/password` });
    expect(loginProof).not.toHaveProperty('ath');
  });

  it('uses a fresh proof id for every request', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    for (let index = 0; index < 5; index++) await tab.fetch(`${API_ORIGIN}/api/me`);
    const ids = profile.sent.map((request) => request.headers.get('dpop')).filter((proof) => proof !== null).map((proof) => decodeJwt(proof).jti);
    expect(ids.length).toBeGreaterThanOrEqual(7);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('creates the key as non-extractable and reuses it for every tab of the profile', async () => {
    const { profile } = await setup();
    await login(profile);
    const reloaded = open(profile);
    await reloaded.ready();
    await reloaded.fetch(`${API_ORIGIN}/api/me`);

    const pair = (await profile.keyStore.load())!;
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.usages).toEqual(['sign']);
    await expect(crypto.subtle.exportKey('jwk', pair.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', pair.privateKey)).rejects.toThrow();

    const keys = profile.sent
      .map((request) => request.headers.get('dpop'))
      .filter((proof) => proof !== null)
      .map((proof) => (decodeProtectedHeader(proof).jwk as { x: string }).x);
    expect(keys.length).toBeGreaterThan(3);
    expect(new Set(keys).size).toBe(1);
  });

  it('creates exactly one key when two tabs start at the same time', async () => {
    const { profile } = await setup();
    const one = open(profile);
    const two = open(profile);
    await Promise.all([one.ready(), two.ready()]);
    const keys = profile.sent.map((request) => (decodeProtectedHeader(request.headers.get('dpop')!).jwk as { x: string }).x);
    expect(keys).toHaveLength(2);
    expect(new Set(keys).size).toBe(1);
  });

  it('is what makes a copied refresh cookie useless on another device', async () => {
    const { profile, server } = await setup();
    await login(profile);

    const thief = new BrowserProfile(server);
    thief.cookies.set('__Host-rt', profile.cookies.get('__Host-rt')!);
    const stolen = open(thief);
    expect(await stolen.ready()).toEqual({ status: 'unauthenticated' });
    expect(server.sink.ofType('dpop.rejected').at(-1)).toMatchObject({ reason: 'DPOP_KEY_MISMATCH', data: { during: 'refresh' } });

    // The owner is unaffected.
    const owner = open(profile);
    expect((await owner.ready()).status).toBe('authenticated');
  });

  it('sends no proofs and uses Bearer when binding is switched off', async () => {
    const { profile } = await setup({ dpop: { mode: 'off' } });
    const tab = await login(profile, { dpop: false });
    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(200);
    expect(profile.sent.every((request) => request.headers.get('dpop') === null)).toBe(true);
    expect(profile.requestsTo('/api/me')[0]!.headers.get('authorization')).toMatch(/^Bearer /);
    expect(tab.getState()).toMatchObject({ session: { deviceBound: false } });
  });

  it('corrects for a device clock that is wrong and retries', async () => {
    const { profile, server } = await setup();
    // This device believes it is ten minutes later than it is. Proofs are only valid for a minute.
    const tab = open(profile, { now: () => server.clock() + 600_000 });
    const state = await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    expect(state.status).toBe('authenticated');

    const attempts = profile.requestsTo('/auth/login/password');
    expect(attempts).toHaveLength(2);
    const [rejected, accepted] = attempts.map((request) => decodeJwt(request.headers.get('dpop')!).iat as number);
    expect(rejected! - accepted!).toBe(600);

    // Once learned, the correction applies to everything that follows.
    const before = profile.sent.length;
    expect((await tab.fetch(`${API_ORIGIN}/api/me`)).status).toBe(200);
    expect(profile.sent.length).toBe(before + 1);
  });

  it('corrects the clock on a call to your API as well', async () => {
    const { profile, server } = await setup();
    let skew = 0;
    const tab = await login(profile, { now: () => server.clock() + skew });
    // The device clock jumps five minutes back after sign-in.
    skew = -300_000;
    const response = await tab.fetch(`${API_ORIGIN}/api/me`);
    expect(response.status).toBe(200);
    expect(profile.requestsTo('/api/me')).toHaveLength(2);
  });
});

describe('several tabs', () => {
  it('lets tabs refresh at the same moment without tripping reuse detection', async () => {
    const { profile, server, user } = await setup();
    const one = await login(profile);
    const two = open(profile);
    await two.ready();
    const three = open(profile);
    await three.ready();

    const tokens = await Promise.all([
      one.getAccessToken({ forceRefresh: true }),
      two.getAccessToken({ forceRefresh: true }),
      three.getAccessToken({ forceRefresh: true }),
    ]);
    expect(tokens.every((token) => typeof token === 'string')).toBe(true);
    expect([one, two, three].map((tab) => tab.getState().status)).toEqual(['authenticated', 'authenticated', 'authenticated']);
    expect(await server.auth.sessions.list(user.id)).toHaveLength(1);
    expect(server.sink.ofType('session.refresh_reuse_detected')).toHaveLength(0);
  });

  it('shows what the lock prevents: without it, two tabs present the same token and the session is revoked', async () => {
    const { profile, server, user } = await setup();
    const one = await login(profile, { locks: null });
    const two = open(profile, { locks: null });
    await two.ready();

    // Hold both refresh requests until each has picked up the same cookie.
    const held: (() => void)[] = [];
    profile.beforeSend = (request) =>
      request.path === '/auth/refresh'
        ? new Promise<void>((resolve) => {
            held.push(resolve);
            if (held.length === 2) held.forEach((release) => release());
          })
        : Promise.resolve();

    const tokens = await Promise.all([one.getAccessToken({ forceRefresh: true }), two.getAccessToken({ forceRefresh: true })]);
    profile.beforeSend = null;

    expect(tokens.filter((token) => token === null)).toHaveLength(1);
    expect(server.sink.ofType('session.refresh_reuse_detected')).toHaveLength(1);
    expect(await server.auth.sessions.list(user.id)).toEqual([]);
  });

  it('signs every tab out when one tab logs out', async () => {
    const { profile } = await setup();
    const one = await login(profile);
    const two = open(profile);
    await two.ready();
    expect(two.getState().status).toBe('authenticated');

    const before = profile.sent.length;
    await one.logout();
    await settle();
    expect(one.getState()).toEqual({ status: 'unauthenticated' });
    expect(two.getState()).toEqual({ status: 'unauthenticated' });
    expect(await two.getAccessToken()).toBeNull();
    // The other tab learned it from the broadcast, not from a request of its own.
    expect(profile.sent.slice(before).map((request) => request.path)).toEqual(['/auth/logout']);
  });

  it('signs the other tabs in when one tab signs in', async () => {
    const { profile } = await setup();
    const one = open(profile);
    const two = open(profile);
    await Promise.all([one.ready(), two.ready()]);
    expect(two.getState()).toEqual({ status: 'unauthenticated' });

    await one.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    await vi.waitFor(() => expect(two.getState().status).toBe('authenticated'));
    expect(await two.getAccessToken()).not.toBe(await one.getAccessToken());
  });

  it('stops listening once disposed', async () => {
    const { profile } = await setup();
    const one = await login(profile);
    const two = open(profile);
    await two.ready();
    two.dispose();
    await one.logout();
    await settle();
    expect(two.getState().status).toBe('authenticated');
  });
});

describe('logging out', () => {
  it('ends the session on the server and clears local state', async () => {
    const { profile, server, user } = await setup();
    const tab = await login(profile);
    await tab.logout();
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
    expect(await tab.getAccessToken()).toBeNull();
    expect(await server.auth.sessions.list(user.id)).toEqual([]);
    expect(profile.cookies.size).toBe(0);
    expect(profile.requestsTo('/auth/logout')[0]!.credentials).toBe('include');
  });

  it('ends every session when asked', async () => {
    const { profile, server, user } = await setup();
    const tab = await login(profile);
    await login(new BrowserProfile(server));
    expect(await server.auth.sessions.list(user.id)).toHaveLength(2);
    await tab.logout({ allSessions: true });
    expect(await server.auth.sessions.list(user.id)).toEqual([]);
  });

  it('signs this tab out even when the server cannot be reached, and reports the failure', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    profile.offline = true;
    expect((await rejection(tab.logout())).code).toBe('NETWORK_ERROR');
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
    expect(profile.broadcasts.at(-1)).toEqual({ type: 'signed-out' });
  });
});
