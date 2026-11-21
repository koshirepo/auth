import { AUDIT_EVENT_TYPES, defineRbac, type AuditEvent } from '@koshirepo/auth-core';
import { describe, expect, it, vi } from 'vitest';
import { memoryAdapter } from '../src/adapters/memory.js';
import { AuditEmitter } from '../src/audit/emitter.js';
import { consoleSink, memorySink, storeSink, type AuditSink } from '../src/audit/sinks.js';
import { createFakeClock } from '../src/testing/clock.js';
import { createClock } from '../src/util/clock.js';
import { fromBase32, toBase64Url } from '../src/util/encoding.js';
import { DataProtector } from '../src/util/protector.js';
import { SoftwareAuthenticator } from './authenticator.js';
import { APP_ORIGIN, PASSWORD, createAuthEnv, createDevice, createUser, loginWithPassword, totpCode, type Device } from './env.js';
import { encodeSegment, expectAuthError } from './helpers.js';

function emitter(sinks: AuditSink[], options: { failClosed?: boolean; onError?: (error: unknown, event: AuditEvent) => void } = {}) {
  const clock = createFakeClock();
  return new AuditEmitter({
    sinks,
    failClosed: options.failClosed ?? false,
    onError: options.onError ?? (() => undefined),
    clock: createClock(clock),
  });
}

describe('AuditEmitter', () => {
  it('builds a complete event from typed input and the request context', async () => {
    const sink = memorySink();
    await emitter([sink]).emit(
      'login.failed',
      { outcome: 'failure', reason: 'INVALID_CREDENTIALS', userId: 'u1', data: { method: 'pwd', identifierHash: 'h' } },
      { ip: '203.0.113.5', userAgent: 'agent/1.0' },
    );
    const [event] = sink.events;
    expect(event).toEqual({
      id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      type: 'login.failed',
      at: '2026-01-01T00:00:00.000Z',
      outcome: 'failure',
      userId: 'u1',
      ip: '203.0.113.5',
      userAgent: 'agent/1.0',
      reason: 'INVALID_CREDENTIALS',
      data: { method: 'pwd', identifierHash: 'h' },
    });
  });

  it('leaves out fields that were not given', async () => {
    const sink = memorySink();
    await emitter([sink]).emit('key.created', { outcome: 'success', data: { kid: 'k1', algorithm: 'EdDSA' } });
    expect(Object.keys(sink.events[0]!).sort()).toEqual(['at', 'data', 'id', 'outcome', 'type']);
  });

  it('truncates the user agent, which is attacker-controlled text', async () => {
    const sink = memorySink();
    await emitter([sink]).emit('user.created', { outcome: 'success', data: {} }, { userAgent: 'A'.repeat(5000) });
    expect(sink.events[0]!.userAgent).toHaveLength(256);
  });

  it('gives every event its own id', async () => {
    const sink = memorySink();
    const audit = emitter([sink]);
    for (let index = 0; index < 20; index++) await audit.emit('user.created', { outcome: 'success', data: {} });
    expect(new Set(sink.events.map((event) => event.id)).size).toBe(20);
  });

  it('writes to every sink and waits for asynchronous ones', async () => {
    const one = memorySink();
    const order: string[] = [];
    const slow: AuditSink = {
      async write() {
        await new Promise((resolve) => setTimeout(resolve, 5));
        order.push('slow sink done');
      },
    };
    await emitter([one, slow]).emit('user.created', { outcome: 'success', data: {} });
    order.push('emit returned');
    expect(one.events).toHaveLength(1);
    expect(order).toEqual(['slow sink done', 'emit returned']);
  });

  it('by default reports a failing sink and carries on, still writing to the others', async () => {
    const healthy = memorySink();
    const reported: [unknown, AuditEvent][] = [];
    const broken: AuditSink = {
      write() {
        throw new Error('disk full');
      },
    };
    const rejecting: AuditSink = { write: () => Promise.reject(new Error('network down')) };
    await emitter([broken, healthy, rejecting], { onError: (error, event) => reported.push([error, event]) }).emit('user.created', {
      outcome: 'success',
      data: {},
    });
    expect(healthy.events).toHaveLength(1);
    expect(reported.map(([error]) => (error as Error).message)).toEqual(['disk full', 'network down']);
    expect(reported[0]![1].type).toBe('user.created');
  });

  it('survives an error hook that throws', async () => {
    const broken: AuditSink = { write: () => Promise.reject(new Error('down')) };
    await emitter([broken], {
      onError: () => {
        throw new Error('the hook is broken too');
      },
    }).emit('user.created', { outcome: 'success', data: {} });
  });

  it('fails the operation when a sink fails and failClosed is set', async () => {
    const broken: AuditSink = { write: () => Promise.reject(new Error('down')) };
    const error = await expectAuthError(
      emitter([broken], { failClosed: true }).emit('user.created', { outcome: 'success', data: {} }),
      'INTERNAL_ERROR',
    );
    expect((error.cause as Error).message).toBe('down');
  });
});

describe('audit sinks', () => {
  it('consoleSink writes one JSON object per line', () => {
    const lines: string[] = [];
    const event = { id: 'e1', type: 'user.created', at: '2026-01-01T00:00:00.000Z', outcome: 'success', data: {} } as AuditEvent;
    consoleSink({ write: (line) => lines.push(line) }).write(event);
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain('\n');
    expect(JSON.parse(lines[0]!)).toEqual(event);
  });

  it('consoleSink writes to standard output by default', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    consoleSink().write({ id: 'e1', type: 'user.created', at: 'now', outcome: 'success', data: {} } as AuditEvent);
    expect(log).toHaveBeenCalledOnce();
    log.mockRestore();
  });

  it('storeSink appends to an audit store', async () => {
    const adapter = memoryAdapter();
    const event = { id: 'e1', type: 'user.created', at: '2026-01-01T00:00:00.000Z', outcome: 'success', data: {} } as AuditEvent;
    await storeSink(adapter.audit).write(event);
    expect(await adapter.audit.list()).toEqual([event]);
  });

  it('memorySink filters by type and clears', () => {
    const sink = memorySink();
    sink.write({ id: '1', type: 'user.created', at: '', outcome: 'success', data: {} } as AuditEvent);
    sink.write({ id: '2', type: 'user.disabled', at: '', outcome: 'success', data: {} } as AuditEvent);
    expect(sink.ofType('user.disabled').map((event) => event.id)).toEqual(['2']);
    sink.clear();
    expect(sink.events).toEqual([]);
  });
});

describe('audit configuration', () => {
  it('writes to the adapter’s audit store when no sink is configured', async () => {
    const env = createAuthEnv({ audit: undefined });
    const user = await createUser(env);
    await loginWithPassword(env, await createDevice(env.clock));
    const stored = await env.adapter.audit.list({ userId: user.id });
    expect(stored.map((event) => event.type)).toContain('login.succeeded');
    expect(stored.map((event) => event.type)).toContain('user.created');
  });

  it('does not block sign-in when a sink is down, unless failClosed is set', async () => {
    const down: AuditSink = { write: () => Promise.reject(new Error('audit database unreachable')) };
    const reported: unknown[] = [];

    const open = createAuthEnv({ audit: { sinks: [down], onError: (error) => reported.push(error) } });
    await createUser(open);
    const result = await loginWithPassword(open, await createDevice(open.clock));
    expect(result.status).toBe('authenticated');
    expect(reported.length).toBeGreaterThan(0);

    const closed = createAuthEnv({ audit: { sinks: [down], failClosed: true } });
    await expectAuthError(closed.auth.users.create({ identifier: 'ada@example.com', password: PASSWORD }), 'INTERNAL_ERROR');
  });

  it('logs sink failures to stderr by default, naming the event but not its contents', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const env = createAuthEnv({ audit: { sinks: [{ write: () => Promise.reject(new Error('down')) }] } });
    await createUser(env);
    expect(error).toHaveBeenCalled();
    expect(String(error.mock.calls[0]![0])).toMatch(/audit sink failed for event user\.created/);
    error.mockRestore();
  });
});

// ---------------------------------------------------------------------------------------------
// The whole library, end to end
// ---------------------------------------------------------------------------------------------

/** Wraps a device so that every DPoP proof it produces is recorded. */
function recording(device: Device, proofs: Set<string>): Device {
  return {
    ...device,
    async ctx(method, path, accessToken) {
      const ctx = await device.ctx(method, path, accessToken);
      if (ctx.dpop) proofs.add(ctx.dpop.proof);
      return ctx;
    },
  };
}

async function ignore(promise: Promise<unknown>): Promise<void> {
  await promise.then(
    () => undefined,
    () => undefined,
  );
}

/** Every string that appears anywhere in a value, keys included. */
function strings(value: unknown, into: string[] = []): string[] {
  if (typeof value === 'string') into.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, into);
  else if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      into.push(key);
      strings(item, into);
    }
  }
  return into;
}

/**
 * Drives every feature once and collects every secret that was issued or submitted on the way.
 */
async function exerciseEverything() {
  const clock = createFakeClock();
  const adapter = memoryAdapter({ clock });
  const sink = memorySink();
  const rbac = defineRbac({ permissions: ['doc:read', 'doc:write'], roles: { reader: { grants: ['doc:read'] } } });
  const env = createAuthEnv(
    {
      access: { rbac },
      audit: { sinks: [sink, storeSink(adapter.audit)] },
    },
    { clock, adapter },
  );
  const { auth } = env;

  /** Long secrets: none may appear anywhere in the log, even as part of a longer string. */
  const secrets = new Set<string>([env.dataKey]);
  /** Short one-time codes: none may appear as a value in the log. */
  const codes = new Set<string>();
  const note = (...values: string[]) => values.forEach((value) => secrets.add(value));
  const noteGrant = (grant: { accessToken: string; refreshToken?: string }) => {
    note(grant.accessToken);
    if (grant.refreshToken) note(grant.refreshToken);
  };

  const proofs = new Set<string>();
  const laptop = recording(await createDevice(clock), proofs);
  const stranger = recording(await createDevice(clock, { ip: '198.51.100.66' }), proofs);
  const LOGIN = '/auth/login/password';
  const NEW_PASSWORD = 'an entirely different passphrase';
  note(PASSWORD, NEW_PASSWORD);

  // Accounts
  const user = await auth.users.create({ identifier: 'ada@example.com', password: PASSWORD, roles: ['reader'] });

  // Failed logins, including a password typed into the identifier field
  const pasted = 'Tr0ub4dor&3-typed-into-the-wrong-box';
  note(pasted, 'not-the-right-password');
  await ignore(auth.login.withPassword({ identifier: pasted, password: 'not-the-right-password' }, await laptop.ctx('POST', LOGIN)));
  for (let index = 0; index < 6; index++) {
    note(`guess-number-${index}-password`);
    await ignore(
      auth.login.withPassword({ identifier: 'victim@example.com', password: `guess-number-${index}-password` }, await stranger.ctx('POST', LOGIN)),
    );
  }

  // Login, refresh, reuse
  const first = await loginWithPassword(env, laptop);
  noteGrant(first);
  await ignore(auth.tokens.verify(`${encodeSegment({ alg: 'none', typ: 'at+jwt' })}.${encodeSegment({ sub: user.id })}.`));
  await ignore(auth.sessions.refresh(first.refreshToken, laptop.bare()));
  const second = await auth.sessions.refresh(first.refreshToken, await laptop.ctx('POST', '/auth/refresh'));
  noteGrant(second);
  await ignore(auth.sessions.refresh(first.refreshToken, await laptop.ctx('POST', '/auth/refresh')));

  // TOTP enrolment
  const third = await loginWithPassword(env, laptop);
  noteGrant(third);
  const enrollment = await auth.mfa.beginTotpEnrollment(user.id);
  note(enrollment.secret, toBase64Url(fromBase32(enrollment.secret)), enrollment.enrollmentId, enrollment.otpauthUri);
  const confirmCode = await totpCode(clock, enrollment.secret);
  codes.add(confirmCode);
  const { recoveryCodes } = await auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: enrollment.enrollmentId, code: confirmCode });
  note(...recoveryCodes, ...recoveryCodes.map((code) => code.replace(/-/g, '')));

  // Login with TOTP: one wrong code, then the right one
  clock.advanceSec(30);
  const pending = await auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await laptop.ctx('POST', LOGIN));
  if (pending.status !== 'mfa_required') throw new Error('expected mfa_required');
  note(pending.ticket);
  codes.add('000000');
  await ignore(auth.mfa.verify({ ticket: pending.ticket, method: 'totp', code: '000000' }, await laptop.ctx('POST', '/auth/mfa/verify')));
  const loginCode = await totpCode(clock, enrollment.secret);
  codes.add(loginCode);
  const fourth = await auth.mfa.verify({ ticket: pending.ticket, method: 'totp', code: loginCode }, await laptop.ctx('POST', '/auth/mfa/verify'));
  noteGrant(fourth);

  // Login with a recovery code
  const pendingRecovery = await auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await laptop.ctx('POST', LOGIN));
  if (pendingRecovery.status !== 'mfa_required') throw new Error('expected mfa_required');
  note(pendingRecovery.ticket);
  const fifth = await auth.mfa.verify(
    { ticket: pendingRecovery.ticket, method: 'recovery_code', code: recoveryCodes[0]! },
    await laptop.ctx('POST', '/auth/mfa/verify'),
  );
  noteGrant(fifth);
  note(...(await auth.mfa.regenerateRecoveryCodes(user.id)));

  // Step-up
  noteGrant(await auth.sessions.reauthenticate(fifth.session.id, { method: 'password', password: PASSWORD }));

  // Passkeys
  const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
  const registration = await auth.passkeys.registrationOptions(user.id);
  note(registration.challengeId, registration.options.challenge);
  const passkey = await auth.passkeys.register(user.id, {
    challengeId: registration.challengeId,
    response: authenticator.create(registration.options),
  });
  const passkeyLogin = await auth.login.passkeyOptions();
  note(passkeyLogin.challengeId, passkeyLogin.options.challenge);
  const sixth = await auth.login.withPasskey(
    { challengeId: passkeyLogin.challengeId, response: authenticator.get(passkeyLogin.options) },
    await laptop.ctx('POST', '/auth/login/passkey'),
  );
  if (sixth.status !== 'authenticated') throw new Error('expected a completed passkey login');
  noteGrant(sixth);
  await auth.passkeys.remove(user.id, passkey.id);

  // Authorization
  const verified = await auth.tokens.verify(sixth.accessToken, await laptop.ctx('GET', '/docs/1', sixth.accessToken));
  await ignore(auth.authorize(verified, 'doc:write', undefined, { request: laptop.bare() }));

  // Account changes
  await auth.users.changePassword(user.id, PASSWORD, NEW_PASSWORD);
  await auth.mfa.removeTotp(user.id);

  // Key rotation through to retirement
  await auth.keys.rotate();
  clock.advanceSec(700);
  await auth.keys.jwks();
  clock.advanceSec(1600);
  await auth.keys.jwks();

  await auth.users.disable(user.id);

  // The private signing keys themselves.
  const protector = new DataProtector([{ id: 'k1', key: env.dataKey }]);
  for (const key of await adapter.keys.list()) {
    const privateJwk = JSON.parse(await protector.decrypt(key.encryptedPrivateJwk)) as { d: string };
    note(privateJwk.d, key.encryptedPrivateJwk);
  }
  note(...proofs);

  return { events: sink.events, stored: await adapter.audit.list(), secrets, codes, user };
}

describe('the audit log across every flow', () => {
  it('emits every event type, and no event contains a secret or a token', async () => {
    const { events, stored, secrets, codes, user } = await exerciseEverything();

    // Every documented event type occurred, so the checks below cover all of them.
    const emitted = new Set(events.map((event) => event.type));
    expect([...AUDIT_EVENT_TYPES].filter((type) => !emitted.has(type))).toEqual([]);
    expect(events.length).toBeGreaterThanOrEqual(40);

    // The scenario really did collect the sensitive material.
    expect(secrets.size).toBeGreaterThanOrEqual(60);
    expect(codes.size).toBe(3);

    // Layer three of the defence: nothing sensitive is in the log, in either sink.
    for (const log of [JSON.stringify(events), JSON.stringify(stored)]) {
      for (const secret of secrets) {
        expect(secret.length).toBeGreaterThanOrEqual(16);
        if (log.includes(secret)) throw new Error(`The audit log contains a secret: ${secret.slice(0, 6)}…`);
      }
    }
    const everyString = new Set([...strings(events), ...strings(stored)]);
    for (const code of codes) expect(everyString.has(code)).toBe(false);

    // The login identifier is recorded as a keyed hash only.
    expect(JSON.stringify(events)).not.toContain('ada@example.com');
    expect(JSON.stringify(events)).not.toContain('victim@example.com');

    // The database sink received exactly the same events.
    expect(stored).toHaveLength(events.length);
    expect(new Set(stored.map((event) => event.id))).toEqual(new Set(events.map((event) => event.id)));
    expect(events.some((event) => event.userId === user.id)).toBe(true);
  }, 30_000);

  it('gives every event the same shape: only the documented top-level fields', async () => {
    const { events } = await exerciseEverything();
    const allowed = new Set(['id', 'type', 'at', 'outcome', 'userId', 'sessionId', 'ip', 'userAgent', 'reason', 'data']);
    for (const event of events) {
      for (const key of Object.keys(event)) expect(allowed.has(key)).toBe(true);
      expect(event.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(Number.isNaN(Date.parse(event.at))).toBe(false);
      expect(['success', 'failure']).toContain(event.outcome);
      expect(typeof event.data).toBe('object');
      if (event.reason !== undefined) expect(event.reason).toMatch(/^[A-Za-z_]+$/);
    }
  }, 30_000);
});
