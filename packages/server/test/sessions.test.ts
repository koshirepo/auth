import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { hashRefreshToken } from '../src/sessions/session-service.js';
import { PASSWORD, createAuthEnv, createDevice, createUser, loginWithPassword } from './env.js';
import { expectAuthError } from './helpers.js';

const DAY = 86_400;
const REFRESH = '/auth/refresh';

async function setup(overrides = {}) {
  const env = createAuthEnv(overrides);
  const user = await createUser(env);
  const device = await createDevice(env.clock);
  const login = await loginWithPassword(env, device);
  return { env, user, device, login };
}

describe('refresh token rotation', () => {
  it('exchanges a refresh token for a new pair, in the same session', async () => {
    const { env, device, login } = await setup();
    env.clock.advanceSec(600);
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));

    expect(refreshed.status).toBe('authenticated');
    expect(refreshed.refreshToken).not.toBe(login.refreshToken);
    expect(refreshed.accessToken).not.toBe(login.accessToken);
    expect(refreshed.session.id).toBe(login.session.id);
    expect(refreshed.session.lastUsedAt).toBe(login.session.lastUsedAt + 600);
    expect(decodeJwt(refreshed.accessToken).sid).toBe(login.session.id);
    expect(refreshed.accessTokenExpiresAt).toBe(Math.floor(env.clock() / 1000) + 900);
  });

  it('issues opaque 256-bit tokens and stores only their hash', async () => {
    const { env, login } = await setup();
    expect(login.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(login.refreshToken.split('.')).toHaveLength(1);

    const found = await env.adapter.sessions.findByRefreshTokenHash(await hashRefreshToken(login.refreshToken));
    expect(found).not.toBeNull();
    expect(found!.token.tokenHash).not.toBe(login.refreshToken);
    expect(await env.adapter.sessions.findByRefreshTokenHash(login.refreshToken)).toBeNull();
    expect(JSON.stringify(found)).not.toContain(login.refreshToken);
  });

  it('revokes the whole session when an already used token is presented', async () => {
    const { env, device, login } = await setup();
    const second = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));

    // The first token has been rotated away. Presenting it again is reuse.
    const error = await expectAuthError(
      env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)),
      'REFRESH_TOKEN_REUSED',
    );
    expect(error.status).toBe(401);

    // The token that was legitimately issued is dead too: the session is gone.
    await expectAuthError(env.auth.sessions.refresh(second.refreshToken, await device.ctx('POST', REFRESH)), 'SESSION_REVOKED');
    const session = await env.adapter.sessions.findById(login.session.id);
    expect(session!.revokedReason).toBe('refresh_reuse');
  });

  it('revokes the session when any earlier token in a long chain is reused', async () => {
    const { env, device, login } = await setup();
    const tokens = [login.refreshToken];
    for (let index = 0; index < 4; index++) {
      const next = await env.auth.sessions.refresh(tokens[tokens.length - 1]!, await device.ctx('POST', REFRESH));
      tokens.push(next.refreshToken);
    }
    await expectAuthError(env.auth.sessions.refresh(tokens[1]!, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_REUSED');
    await expectAuthError(env.auth.sessions.refresh(tokens[4]!, await device.ctx('POST', REFRESH)), 'SESSION_REVOKED');
  });

  it('records reuse in the audit log with the token id, never the token', async () => {
    const { env, device, login } = await setup();
    await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));
    env.sink.clear();
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_REUSED');

    const [reuse] = env.sink.ofType('session.refresh_reuse_detected');
    expect(reuse).toMatchObject({ outcome: 'failure', reason: 'REFRESH_TOKEN_REUSED', sessionId: login.session.id, ip: device.ip });
    expect(reuse!.data.refreshTokenId).toMatch(/^[0-9a-f-]{36}$/);
    expect(env.sink.ofType('session.revoked')[0]!.data).toEqual({ revokeReason: 'refresh_reuse', count: 1 });
    expect(JSON.stringify(env.sink.events)).not.toContain(login.refreshToken);
  });

  it('still reports reuse when the session was already revoked', async () => {
    const { env, device, login } = await setup();
    await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));
    await env.auth.sessions.revoke(login.session.id, 'logout');
    env.sink.clear();
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_REUSED');
    expect(env.sink.ofType('session.refresh_reuse_detected')).toHaveLength(1);
    expect(env.sink.ofType('session.revoked')).toHaveLength(0);
  });

  it('lets exactly one of two simultaneous refreshes with the same token succeed', async () => {
    const { env, device, login } = await setup();
    const results = await Promise.allSettled([
      env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)),
      env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)),
      env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)),
    ]);
    const fulfilled = results.filter((result) => result.status === 'fulfilled');
    const rejected = results.filter((result) => result.status === 'rejected') as PromiseRejectedResult[];
    expect(fulfilled).toHaveLength(1);
    expect(rejected.map((result) => result.reason.code)).toEqual(['REFRESH_TOKEN_REUSED', 'REFRESH_TOKEN_REUSED']);

    // Strict reuse detection: the race itself revokes the session, including the winner's new token.
    const winner = (fulfilled[0] as PromiseFulfilledResult<{ refreshToken: string }>).value;
    await expectAuthError(env.auth.sessions.refresh(winner.refreshToken, await device.ctx('POST', REFRESH)), 'SESSION_REVOKED');
  });

  it('rejects missing, unknown and oversized tokens', async () => {
    const { env, device } = await setup();
    await expectAuthError(env.auth.sessions.refresh('', await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_MISSING');
    await expectAuthError(env.auth.sessions.refresh(undefined as unknown as string, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_MISSING');
    await expectAuthError(env.auth.sessions.refresh('not-a-real-token', await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_INVALID');
    await expectAuthError(env.auth.sessions.refresh('x'.repeat(600), await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_INVALID');
  });
});

describe('session lifetime', () => {
  it('expires a session that is idle for longer than the idle limit', async () => {
    const { env, device, login } = await setup();
    env.clock.advanceSec(7 * DAY - 1);
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));

    env.clock.advanceSec(7 * DAY + 1);
    await expectAuthError(env.auth.sessions.refresh(refreshed.refreshToken, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_EXPIRED');
  });

  it('ends a session at its absolute lifetime however often it is refreshed', async () => {
    const { env, device, login } = await setup();
    let token = login.refreshToken;
    for (let day = 5; day < 30; day += 5) {
      env.clock.advanceSec(5 * DAY);
      const refreshed = await env.auth.sessions.refresh(token, await device.ctx('POST', REFRESH));
      token = refreshed.refreshToken;
      // A refresh token never outlives its session.
      expect(refreshed.refreshTokenExpiresAt).toBeLessThanOrEqual(login.session.expiresAt);
    }
    env.clock.advanceSec(5 * DAY);
    await expectAuthError(env.auth.sessions.refresh(token, await device.ctx('POST', REFRESH)), 'SESSION_EXPIRED');
  });

  it('honours configured lifetimes', async () => {
    const { env, device, login } = await setup({ sessions: { ttlSec: 3600, idleTtlSec: 1200 } });
    expect(login.session.expiresAt - login.session.createdAt).toBe(3600);
    expect(login.refreshTokenExpiresAt - login.session.createdAt).toBe(1200);
    env.clock.advanceSec(1201);
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_EXPIRED');
  });

  it('picks up role changes at the next refresh', async () => {
    const { env, user, device, login } = await setup();
    expect(decodeJwt(login.accessToken).roles).toEqual(['editor']);
    await env.adapter.users.update(user.id, { roles: ['viewer'] });
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));
    expect(decodeJwt(refreshed.accessToken).roles).toEqual(['viewer']);
    expect(refreshed.user.roles).toEqual(['viewer']);
  });

  it('refuses to refresh for a disabled user and revokes the session', async () => {
    const { env, user, device, login } = await setup();
    await env.adapter.users.update(user.id, { status: 'disabled' });
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'ACCOUNT_DISABLED');
    expect((await env.adapter.sessions.findById(login.session.id))!.revokedReason).toBe('user_disabled');
  });
});

describe('device binding on refresh', () => {
  it('binds the session to the key that signed the login request', async () => {
    const { env, device, login } = await setup();
    expect(login.session.deviceBound).toBe(true);
    expect(decodeJwt(login.accessToken).cnf).toEqual({ jkt: device.key.jkt });
    expect((await env.adapter.sessions.findById(login.session.id))!.dpopJkt).toBe(device.key.jkt);
  });

  it('rejects a stolen refresh token presented without the device key, and does not consume it', async () => {
    const { env, device, login } = await setup();
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, device.bare()), 'DPOP_PROOF_REQUIRED');

    const thief = await createDevice(env.clock, { ip: '198.51.100.99' });
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await thief.ctx('POST', REFRESH)), 'DPOP_KEY_MISMATCH');

    const rejections = env.sink.ofType('dpop.rejected');
    expect(rejections.map((event) => event.reason)).toEqual(['DPOP_PROOF_REQUIRED', 'DPOP_KEY_MISMATCH']);
    expect(rejections[1]).toMatchObject({ sessionId: login.session.id, ip: '198.51.100.99', data: { during: 'refresh' } });

    // The real device can still refresh: the thief did not burn the token or trip reuse detection.
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH));
    expect(refreshed.session.id).toBe(login.session.id);
  });

  it('rejects a proof made for another endpoint', async () => {
    const { env, device, login } = await setup();
    const wrongPath = await device.ctx('POST', '/auth/logout');
    const mismatched = { ...wrongPath, dpop: { ...wrongPath.dpop!, url: 'https://api.example.com/auth/refresh' } };
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, mismatched), 'DPOP_PROOF_INVALID');
  });

  it('does not ask for a proof when the session is not bound', async () => {
    const { env, device, login } = await setup({ dpop: { mode: 'off' } });
    expect(login.session.deviceBound).toBe(false);
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, device.bare());
    expect(refreshed.session.deviceBound).toBe(false);
  });
});

describe('logout, revocation and listing', () => {
  it('logs out the session a refresh token belongs to', async () => {
    const { env, device, login } = await setup();
    await env.auth.sessions.logout(login.refreshToken, {}, device.bare());
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'SESSION_REVOKED');
    expect(env.sink.ofType('session.revoked')[0]!.data).toEqual({ revokeReason: 'logout', count: 1 });
  });

  it('logs out every session of the user', async () => {
    const { env, device, login } = await setup();
    const phone = await createDevice(env.clock, { ip: '203.0.113.20' });
    const second = await loginWithPassword(env, phone);
    await env.auth.sessions.logout(login.refreshToken, { all: true });

    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'SESSION_REVOKED');
    await expectAuthError(env.auth.sessions.refresh(second.refreshToken, await phone.ctx('POST', REFRESH)), 'SESSION_REVOKED');
  });

  it('never throws on logout with a bad token', async () => {
    const { env } = await setup();
    await env.auth.sessions.logout(undefined);
    await env.auth.sessions.logout('');
    await env.auth.sessions.logout('unknown-token');
    await env.auth.sessions.logout('x'.repeat(5000));
  });

  it('lists live sessions, newest first, and marks the current one', async () => {
    const { env, user, login } = await setup();
    env.clock.advanceSec(60);
    const phone = await createDevice(env.clock, { ip: '203.0.113.20', userAgent: 'phone' });
    const second = await loginWithPassword(env, phone);

    const sessions = await env.auth.sessions.list(user.id, second.session.id);
    expect(sessions.map((session) => [session.id, session.current])).toEqual([
      [second.session.id, true],
      [login.session.id, false],
    ]);
    expect(sessions[0]).toMatchObject({ ip: '203.0.113.20', userAgent: 'phone', deviceBound: true, assurance: 'aal1' });

    await env.auth.sessions.revoke(login.session.id);
    expect((await env.auth.sessions.list(user.id)).map((session) => session.id)).toEqual([second.session.id]);
  });

  it('leaves expired sessions out of the list', async () => {
    const { env, user } = await setup();
    env.clock.advanceSec(30 * DAY + 1);
    expect(await env.auth.sessions.list(user.id)).toEqual([]);
  });

  it('revokes all sessions but one', async () => {
    const { env, user, login } = await setup();
    const phone = await createDevice(env.clock);
    const second = await loginWithPassword(env, phone);
    expect(await env.auth.sessions.revokeAll(user.id, { except: second.session.id })).toBe(1);
    expect((await env.auth.sessions.list(user.id)).map((session) => session.id)).toEqual([second.session.id]);
    expect(await env.auth.sessions.get(login.session.id)).not.toBeNull();
    expect(await env.auth.sessions.get('missing')).toBeNull();
  });

  it('purges expired state and long-dead sessions', async () => {
    const { env, device, login } = await setup();
    await env.auth.sessions.logout(login.refreshToken);
    expect(await env.auth.maintenance.purgeExpired()).toEqual({ ephemeral: 0, sessions: 0 });

    env.clock.advanceSec(31 * DAY);
    const purged = await env.auth.maintenance.purgeExpired();
    expect(purged.sessions).toBe(1);
    expect(purged.ephemeral).toBeGreaterThan(0);
    // The token row went with its session, so the old token is now simply unknown.
    await expectAuthError(env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', REFRESH)), 'REFRESH_TOKEN_INVALID');
  });
});

describe('re-authentication inside a session', () => {
  it('refreshes auth_time after the password is proven again', async () => {
    const { env, login } = await setup();
    env.clock.advanceSec(3600);
    const grant = await env.auth.sessions.reauthenticate(login.session.id, { method: 'password', password: PASSWORD });

    expect(grant.session.authenticatedAt).toBe(login.session.authenticatedAt + 3600);
    expect(decodeJwt(grant.accessToken).auth_time).toBe(login.session.authenticatedAt + 3600);
    expect(grant.session.assurance).toBe('aal1');
    expect(grant).not.toHaveProperty('refreshToken');
    expect(env.sink.ofType('session.reauthenticated')[0]).toMatchObject({ outcome: 'success', data: { method: 'pwd' } });
  });

  it('rejects a wrong password and throttles repeated failures', async () => {
    const { env, login } = await setup();
    for (let attempt = 0; attempt < 5; attempt++) {
      await expectAuthError(
        env.auth.sessions.reauthenticate(login.session.id, { method: 'password', password: 'wrong password!' }),
        'INVALID_CREDENTIALS',
      );
    }
    const blocked = await expectAuthError(
      env.auth.sessions.reauthenticate(login.session.id, { method: 'password', password: PASSWORD }),
      'RATE_LIMITED',
    );
    expect(blocked.details).toEqual({ retryAfterSec: 30 });
  });

  it('refuses for a revoked session and for an unknown factor', async () => {
    const { env, login } = await setup();
    await expectAuthError(
      env.auth.sessions.reauthenticate(login.session.id, { method: 'smoke-signal' } as never),
      'REQUEST_INVALID',
    );
    await env.auth.sessions.revoke(login.session.id);
    await expectAuthError(
      env.auth.sessions.reauthenticate(login.session.id, { method: 'password', password: PASSWORD }),
      'SESSION_REVOKED',
    );
  });
});
