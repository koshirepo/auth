import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import type { PasswordHasher } from '../src/password/hasher.js';
import { argon2id } from '../src/password/argon2.js';
import { PASSWORD, createAuthEnv, createDevice, createUser, fastHasher, loginWithPassword } from './env.js';
import { expectAuthError } from './helpers.js';

const LOGIN = '/auth/login/password';

/** Wraps a hasher and counts its calls, to observe how much work a login does. */
function countingHasher(inner: PasswordHasher = fastHasher) {
  const calls = { hash: 0, verify: 0 };
  const hasher: PasswordHasher = {
    hash: (password) => {
      calls.hash++;
      return inner.hash(password);
    },
    verify: (hash, password) => {
      calls.verify++;
      return inner.verify(hash, password);
    },
    needsRehash: (hash) => inner.needsRehash(hash),
  };
  return { hasher, calls };
}

describe('password login', () => {
  it('signs a user in and returns tokens, the user and the session', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const device = await createDevice(env.clock);
    const result = await loginWithPassword(env, device);

    expect(result.user).toEqual({ id: user.id, identifier: 'ada@example.com', roles: ['editor'] });
    expect(result.session).toMatchObject({ methods: ['pwd'], assurance: 'aal1', deviceBound: true, ip: device.ip });
    expect(decodeJwt(result.accessToken)).toMatchObject({ sub: user.id, amr: ['pwd'], acr: 'aal1', roles: ['editor'] });
    expect(result.user).not.toHaveProperty('attributes');
  });

  it('normalises the identifier', async () => {
    const env = createAuthEnv();
    await createUser(env, '  Ada@Example.COM ');
    const device = await createDevice(env.clock);
    const result = await loginWithPassword(env, device, 'ADA@example.com');
    expect(result.user.identifier).toBe('ada@example.com');
  });

  it('gives the same answer for an unknown account and a wrong password', async () => {
    const env = createAuthEnv();
    await createUser(env);
    const device = await createDevice(env.clock);

    const wrongPassword = await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: 'not the password' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    const unknownAccount = await expectAuthError(
      env.auth.login.withPassword({ identifier: 'nobody@example.com', password: 'not the password' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    expect(JSON.stringify(unknownAccount)).toBe(JSON.stringify(wrongPassword));
    expect(unknownAccount.status).toBe(wrongPassword.status);
    expect(unknownAccount.constructor).toBe(wrongPassword.constructor);
  });

  it('does the same hashing work for an unknown account as for a known one', async () => {
    const { hasher, calls } = countingHasher();
    const env = createAuthEnv({ password: { hasher } });
    await createUser(env);
    const device = await createDevice(env.clock);

    calls.verify = 0;
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: 'wrong wrong wrong' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    expect(calls.verify).toBe(1);

    calls.verify = 0;
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ghost@example.com', password: 'wrong wrong wrong' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    expect(calls.verify).toBe(1);
  });

  it('does not reveal that an account is disabled unless the password is right', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    await env.auth.users.disable(user.id);
    const device = await createDevice(env.clock);

    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: 'guess guess guess' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await device.ctx('POST', LOGIN)),
      'ACCOUNT_DISABLED',
    );
  });

  it('skips hashing for a password longer than the limit', async () => {
    const { hasher, calls } = countingHasher();
    const env = createAuthEnv({ password: { hasher } });
    await createUser(env);
    const device = await createDevice(env.clock);
    calls.verify = 0;
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: 'x'.repeat(100_000) }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    expect(calls.verify).toBe(0);
  });

  it('rejects malformed input before doing any work', async () => {
    const env = createAuthEnv();
    const device = await createDevice(env.clock);
    const bad = [
      {},
      { identifier: 'ada@example.com' },
      { password: PASSWORD },
      { identifier: '', password: PASSWORD },
      { identifier: 'ada@example.com', password: '' },
      { identifier: 42, password: PASSWORD },
      { identifier: 'a'.repeat(400), password: PASSWORD },
      null,
    ];
    for (const input of bad) {
      await expectAuthError(env.auth.login.withPassword(input as never, await device.ctx('POST', LOGIN)), 'REQUEST_INVALID');
    }
  });

  it('is refused when password login is not configured', async () => {
    const env = createAuthEnv({ password: undefined });
    const device = await createDevice(env.clock);
    const error = await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await device.ctx('POST', LOGIN)),
      'REQUEST_INVALID',
    );
    expect(error.details).toEqual({ reason: 'password_login_disabled' });
  });

  it('replaces a hash made with weaker parameters when the user next signs in', async () => {
    const weak = argon2id({ memoryKiB: 64, iterations: 1, unsafeAllowWeakParameters: true });
    const strong = argon2id({ memoryKiB: 128, iterations: 2, unsafeAllowWeakParameters: true });
    const before = createAuthEnv({ password: { hasher: weak } });
    const user = await createUser(before);
    expect(await before.adapter.credentials.getPasswordHash(user.id)).toContain('m=64,t=1,p=1');

    const after = createAuthEnv({ password: { hasher: strong } }, before);
    await loginWithPassword(after, await createDevice(after.clock));
    expect(await after.adapter.credentials.getPasswordHash(user.id)).toContain('m=128,t=2,p=1');
    // The new hash still verifies the same password.
    await loginWithPassword(after, await createDevice(after.clock));
  });

  it('writes audit events that identify the attempt without recording what was typed', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const device = await createDevice(env.clock);

    // Someone pastes their password into the identifier field.
    const pasted = 'hunter2-is-my-real-password';
    await expectAuthError(
      env.auth.login.withPassword({ identifier: pasted, password: 'whatever it was' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: 'wrong password' }, await device.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    await loginWithPassword(env, device);

    const [unknown, known] = env.sink.ofType('login.failed');
    expect(unknown).toMatchObject({ outcome: 'failure', reason: 'INVALID_CREDENTIALS', ip: device.ip, data: { method: 'pwd' } });
    expect(unknown).not.toHaveProperty('userId');
    expect(known!.userId).toBe(user.id);
    expect(unknown!.data.identifierHash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(unknown!.data.identifierHash).not.toBe(known!.data.identifierHash);

    const log = JSON.stringify(env.sink.events);
    expect(log).not.toContain(pasted);
    expect(log).not.toContain('ada@example.com');
    expect(log).not.toContain('wrong password');
    expect(log).not.toContain(PASSWORD);

    expect(env.sink.ofType('login.succeeded')[0]).toMatchObject({ userId: user.id, data: { method: 'pwd', mfa: false } });
  });
});

describe('device binding at login', () => {
  it('requires a proof when binding is required', async () => {
    const env = createAuthEnv();
    await createUser(env);
    const device = await createDevice(env.clock);
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, device.bare()),
      'DPOP_PROOF_REQUIRED',
    );
    expect(env.sink.ofType('dpop.rejected')[0]).toMatchObject({ reason: 'DPOP_PROOF_REQUIRED', data: { during: 'login' } });
  });

  it('rejects a proof made for another endpoint before looking at the password', async () => {
    const { hasher, calls } = countingHasher();
    const env = createAuthEnv({ password: { hasher } });
    await createUser(env);
    const device = await createDevice(env.clock);
    const ctx = await device.ctx('POST', '/auth/refresh');
    calls.verify = 0;
    await expectAuthError(
      env.auth.login.withPassword(
        { identifier: 'ada@example.com', password: PASSWORD },
        { ...ctx, dpop: { ...ctx.dpop!, url: 'https://api.example.com/auth/login/password' } },
      ),
      'DPOP_PROOF_INVALID',
    );
    expect(calls.verify).toBe(0);
  });

  it('binds when a proof is sent and optional binding is configured, and leaves the session unbound otherwise', async () => {
    const env = createAuthEnv({ dpop: { mode: 'optional' } });
    await createUser(env);
    const device = await createDevice(env.clock);

    const bound = await loginWithPassword(env, device);
    expect(bound.session.deviceBound).toBe(true);

    const unbound = await env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, device.bare());
    expect(unbound.status === 'authenticated' && unbound.session.deviceBound).toBe(false);
  });

  it('ignores proofs when binding is off', async () => {
    const env = createAuthEnv({ dpop: { mode: 'off' } });
    await createUser(env);
    const device = await createDevice(env.clock);
    const result = await loginWithPassword(env, device);
    expect(result.session.deviceBound).toBe(false);
    expect(decodeJwt(result.accessToken)).not.toHaveProperty('cnf');
  });
});

describe('login throttling', () => {
  // Risk scoring also reacts to failed attempts. It is switched off here so these tests see the
  // throttle alone. The interaction between the two is covered in risk.test.ts.
  const throttleEnv = (overrides: Parameters<typeof createAuthEnv>[0] = {}) => createAuthEnv({ risk: { signals: [] }, ...overrides });

  async function fail(env: ReturnType<typeof createAuthEnv>, device: Awaited<ReturnType<typeof createDevice>>, identifier = 'ada@example.com') {
    return env.auth.login.withPassword({ identifier, password: 'definitely wrong' }, await device.ctx('POST', LOGIN));
  }

  it('starts delaying after five failures, and the delay doubles', async () => {
    const env = throttleEnv();
    await createUser(env);
    const device = await createDevice(env.clock);

    for (let attempt = 0; attempt < 5; attempt++) await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');

    // Even the right password is refused during the delay.
    const blocked = await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await device.ctx('POST', LOGIN)),
      'RATE_LIMITED',
    );
    expect(blocked.status).toBe(429);
    expect(blocked.details).toEqual({ retryAfterSec: 30 });
    expect(env.sink.ofType('rate_limit.exceeded')[0]).toMatchObject({ outcome: 'failure', data: { scope: 'login' } });

    env.clock.advanceSec(31);
    await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');
    expect((await expectAuthError(fail(env, device), 'RATE_LIMITED')).details).toEqual({ retryAfterSec: 60 });

    env.clock.advanceSec(61);
    await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');
    expect((await expectAuthError(fail(env, device), 'RATE_LIMITED')).details).toEqual({ retryAfterSec: 120 });
  });

  it('never delays longer than the configured maximum, so an account cannot be locked for good', async () => {
    const env = throttleEnv({ rateLimits: { login: { freeAttempts: 2, baseDelaySec: 10, maxDelaySec: 40, windowSec: 3600 } } });
    await createUser(env);
    const device = await createDevice(env.clock);
    const delays: unknown[] = [];
    for (let round = 0; round < 6; round++) {
      await fail(env, device).catch(() => undefined);
      const blocked = await fail(env, device).catch((error) => error);
      if (blocked.code === 'RATE_LIMITED') {
        delays.push(blocked.details.retryAfterSec);
        env.clock.advanceSec(blocked.details.retryAfterSec + 1);
      }
    }
    expect(Math.max(...(delays as number[]))).toBe(40);

    await loginWithPassword(env, device);
  });

  it('forgets failures after the window', async () => {
    const env = throttleEnv();
    await createUser(env);
    const device = await createDevice(env.clock);
    for (let attempt = 0; attempt < 4; attempt++) await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');
    env.clock.advanceSec(901);
    for (let attempt = 0; attempt < 4; attempt++) await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');
    await loginWithPassword(env, device);
  });

  it('resets the count when the right password is given', async () => {
    const env = throttleEnv();
    await createUser(env);
    const device = await createDevice(env.clock);
    for (let round = 0; round < 3; round++) {
      for (let attempt = 0; attempt < 4; attempt++) await expectAuthError(fail(env, device), 'INVALID_CREDENTIALS');
      await loginWithPassword(env, device);
    }
  });

  it('throttles an address that fails against many accounts', async () => {
    const env = throttleEnv();
    await createUser(env);
    const attacker = await createDevice(env.clock, { ip: '198.51.100.66' });
    for (let attempt = 0; attempt < 20; attempt++) {
      await expectAuthError(fail(env, attacker, `victim-${attempt}@example.com`), 'INVALID_CREDENTIALS');
    }
    await expectAuthError(fail(env, attacker, 'someone-new@example.com'), 'RATE_LIMITED');

    // Another address is unaffected.
    await loginWithPassword(env, await createDevice(env.clock));
  });

  it('counts by normalised identifier, so changing case does not dodge the limit', async () => {
    const env = throttleEnv();
    await createUser(env);
    const device = await createDevice(env.clock);
    for (const identifier of ['ada@example.com', 'ADA@example.com', ' Ada@Example.com', 'aDa@example.com ', 'ada@EXAMPLE.com']) {
      await expectAuthError(fail(env, device, identifier), 'INVALID_CREDENTIALS');
    }
    await expectAuthError(fail(env, device), 'RATE_LIMITED');
  });
});

describe('user accounts', () => {
  it('creates a user with a hashed password', async () => {
    const env = createAuthEnv();
    const user = await env.auth.users.create({ identifier: 'Grace@Example.com', password: PASSWORD, roles: ['admin'], attributes: { team: 'core' } });
    expect(user).toMatchObject({ identifier: 'grace@example.com', roles: ['admin'], status: 'active', attributes: { team: 'core' } });

    const hash = await env.adapter.credentials.getPasswordHash(user.id);
    expect(hash).toMatch(/^\$argon2id\$v=19\$/);
    expect(hash).not.toContain(PASSWORD);
    expect(await env.auth.users.get(user.id)).toEqual(user);
    expect(env.sink.ofType('user.created')[0]!.userId).toBe(user.id);
  });

  it('creates a user without a password, for passkey-only accounts', async () => {
    const env = createAuthEnv();
    const user = await env.auth.users.create({ identifier: 'keys@example.com' });
    expect(await env.adapter.credentials.getPasswordHash(user.id)).toBeNull();
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'keys@example.com', password: PASSWORD }, await (await createDevice(env.clock)).ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
  });

  it('refuses a duplicate identifier, whatever its case', async () => {
    const env = createAuthEnv();
    await createUser(env);
    const error = await expectAuthError(env.auth.users.create({ identifier: 'ADA@example.com', password: PASSWORD }), 'IDENTIFIER_TAKEN');
    expect(error.status).toBe(409);
  });

  it('enforces the password policy', async () => {
    const env = createAuthEnv({ password: { hasher: fastHasher, check: (password) => (password.includes('password') ? 'breached' : null) } });
    const tooShort = await expectAuthError(env.auth.users.create({ identifier: 'a@example.com', password: 'short' }), 'PASSWORD_POLICY_VIOLATION');
    expect(tooShort.details).toEqual({ reason: 'too_short' });
    const tooLong = await expectAuthError(env.auth.users.create({ identifier: 'a@example.com', password: 'x'.repeat(257) }), 'PASSWORD_POLICY_VIOLATION');
    expect(tooLong.details).toEqual({ reason: 'too_long' });
    const rejected = await expectAuthError(env.auth.users.create({ identifier: 'a@example.com', password: 'my password 123' }), 'PASSWORD_POLICY_VIOLATION');
    expect(rejected.details).toEqual({ reason: 'rejected' });
    // No account was left behind by the rejected attempts.
    expect(await env.adapter.users.findByIdentifier('a@example.com')).toBeNull();

    // Length is counted in characters, not bytes.
    await env.auth.users.create({ identifier: 'emoji@example.com', password: '🔐'.repeat(12) });
  });

  it('changes a password, keeps the current session and ends the others', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const laptop = await createDevice(env.clock);
    const phone = await createDevice(env.clock);
    const current = await loginWithPassword(env, laptop);
    const other = await loginWithPassword(env, phone);

    await expectAuthError(env.auth.users.changePassword(user.id, 'not my password', 'a brand new password'), 'INVALID_CREDENTIALS');
    await expectAuthError(env.auth.users.changePassword(user.id, PASSWORD, 'short'), 'PASSWORD_POLICY_VIOLATION');
    await env.auth.users.changePassword(user.id, PASSWORD, 'a brand new password', { keepSessionId: current.session.id });

    await env.auth.sessions.refresh(current.refreshToken, await laptop.ctx('POST', '/auth/refresh'));
    await expectAuthError(env.auth.sessions.refresh(other.refreshToken, await phone.ctx('POST', '/auth/refresh')), 'SESSION_REVOKED');
    await expectAuthError(
      env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await laptop.ctx('POST', LOGIN)),
      'INVALID_CREDENTIALS',
    );
    await loginWithPassword(env, laptop, 'ada@example.com', 'a brand new password');

    const changes = env.sink.ofType('password.changed');
    expect(changes.map((event) => [event.outcome, event.data.by])).toEqual([
      ['failure', 'user'],
      ['success', 'user'],
    ]);
  });

  it('sets a password administratively and ends every session', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const device = await createDevice(env.clock);
    const session = await loginWithPassword(env, device);

    await env.auth.users.setPassword(user.id, 'reset by an administrator');
    await expectAuthError(env.auth.sessions.refresh(session.refreshToken, await device.ctx('POST', '/auth/refresh')), 'SESSION_REVOKED');
    await loginWithPassword(env, device, 'ada@example.com', 'reset by an administrator');
    await expectAuthError(env.auth.users.setPassword('missing-user', 'reset by an administrator'), 'USER_NOT_FOUND');
  });

  it('disables a user: sessions end and sign-in is refused', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const device = await createDevice(env.clock);
    const session = await loginWithPassword(env, device);

    await env.auth.users.disable(user.id);
    await expectAuthError(env.auth.sessions.refresh(session.refreshToken, await device.ctx('POST', '/auth/refresh')), 'SESSION_REVOKED');
    expect(env.sink.ofType('user.disabled')[0]!.userId).toBe(user.id);
    await expectAuthError(env.auth.users.disable('missing-user'), 'USER_NOT_FOUND');
  });
});
