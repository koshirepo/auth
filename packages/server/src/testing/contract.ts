import type { AuditEvent } from '@acme/auth-core';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AuthAdapter, NewRefreshToken, PasskeyCredential, Session, StoredSigningKey, User } from '../adapters/types.js';
import type { FakeClock } from './clock.js';

export interface AdapterHarness {
  adapter: AuthAdapter;
  /** The clock the adapter was created with. The suite moves it to test expiry. */
  clock: FakeClock;
  dispose?: () => Promise<void> | void;
}

/**
 * Runs the adapter contract against an adapter. Call it from a Vitest test file:
 *
 * ```ts
 * runAdapterContractTests('my adapter', async () => {
 *   const clock = createFakeClock();
 *   return { clock, adapter: myAdapter({ clock }) };
 * });
 * ```
 *
 * `create` is called before every test and must return an empty adapter.
 *
 * The suite checks ordinary behaviour and, more importantly, the atomic operations: every
 * one-time value must be consumable exactly once even when several calls race.
 */
export function runAdapterContractTests(name: string, create: () => Promise<AdapterHarness> | AdapterHarness): void {
  describe(`adapter contract: ${name}`, () => {
    let harness: AdapterHarness;
    let adapter: AuthAdapter;
    let clock: FakeClock;
    let counter = 0;

    beforeEach(async () => {
      harness = await create();
      adapter = harness.adapter;
      clock = harness.clock;
    });

    afterEach(async () => {
      await harness.dispose?.();
    });

    const now = () => new Date(clock());
    const unique = (prefix: string) => `${prefix}-${++counter}`;

    const makeUser = (overrides: Partial<User> = {}): User => {
      const id = unique('user');
      return {
        id,
        identifier: `${id}@example.com`,
        roles: ['viewer'],
        status: 'active',
        attributes: { plan: 'free' },
        createdAt: now(),
        ...overrides,
      };
    };

    const makeSession = (overrides: Partial<Session> = {}): Session => ({
      id: unique('session'),
      userId: 'user-x',
      createdAt: now(),
      lastUsedAt: now(),
      expiresAt: new Date(clock() + 30 * 86_400_000),
      authenticatedAt: now(),
      methods: ['pwd'],
      assurance: 'aal1',
      dpopJkt: 'thumbprint-1',
      ip: '203.0.113.5',
      userAgent: 'contract-test',
      revokedAt: null,
      revokedReason: null,
      ...overrides,
    });

    const makeToken = (overrides: Partial<NewRefreshToken> = {}): NewRefreshToken => {
      const id = unique('token');
      return { id, tokenHash: `hash-of-${id}`, createdAt: now(), expiresAt: new Date(clock() + 7 * 86_400_000), ...overrides };
    };

    const makePasskey = (overrides: Partial<PasskeyCredential> = {}): PasskeyCredential => {
      const id = unique('passkey');
      return {
        id,
        userId: 'user-x',
        credentialId: `credential-${id}`,
        publicKey: 'cHVibGljLWtleQ',
        counter: 0,
        transports: ['internal', 'hybrid'],
        deviceType: 'multiDevice',
        backedUp: true,
        name: 'Laptop',
        createdAt: now(),
        lastUsedAt: null,
        ...overrides,
      };
    };

    const makeKey = (overrides: Partial<StoredSigningKey> = {}): StoredSigningKey => ({
      kid: unique('kid'),
      algorithm: 'EdDSA',
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'abc' },
      encryptedPrivateJwk: 'ciphertext',
      status: 'pending',
      createdAt: now(),
      activatedAt: null,
      retiringAt: null,
      retiredAt: null,
      ...overrides,
    });

    const countTrue = (results: boolean[]) => results.filter(Boolean).length;

    // -----------------------------------------------------------------------------------------
    describe('users', () => {
      it('creates and finds a user by id and by identifier', async () => {
        const user = makeUser({ roles: ['editor', 'viewer'] });
        expect(await adapter.users.create(user)).toEqual(user);
        expect(await adapter.users.findById(user.id)).toEqual(user);
        expect(await adapter.users.findByIdentifier(user.identifier)).toEqual(user);
      });

      it('returns null for unknown users', async () => {
        expect(await adapter.users.findById('nobody')).toBeNull();
        expect(await adapter.users.findByIdentifier('nobody@example.com')).toBeNull();
      });

      it('refuses a second user with the same identifier', async () => {
        const first = makeUser();
        await adapter.users.create(first);
        expect(await adapter.users.create(makeUser({ identifier: first.identifier }))).toBeNull();
        expect((await adapter.users.findByIdentifier(first.identifier))?.id).toBe(first.id);
      });

      it('creates exactly one user when the same identifier is registered concurrently', async () => {
        const results = await Promise.all(
          Array.from({ length: 5 }, () => adapter.users.create(makeUser({ identifier: 'race@example.com' }))),
        );
        expect(results.filter((user) => user !== null)).toHaveLength(1);
      });

      it('updates only the fields given', async () => {
        const user = makeUser();
        await adapter.users.create(user);
        expect(await adapter.users.update(user.id, { roles: ['admin'] })).toEqual({ ...user, roles: ['admin'] });
        expect(await adapter.users.update(user.id, { status: 'disabled' })).toEqual({ ...user, roles: ['admin'], status: 'disabled' });
        const updated = await adapter.users.update(user.id, { attributes: { plan: 'pro', seats: 3 } });
        expect(updated).toEqual({ ...user, roles: ['admin'], status: 'disabled', attributes: { plan: 'pro', seats: 3 } });
        expect(await adapter.users.findById(user.id)).toEqual(updated);
      });

      it('returns null when updating an unknown user', async () => {
        expect(await adapter.users.update('nobody', { roles: [] })).toBeNull();
      });

      it('hands out copies, so changing a result does not change the store', async () => {
        const user = makeUser();
        await adapter.users.create(user);
        const found = await adapter.users.findById(user.id);
        found!.roles.push('admin');
        expect((await adapter.users.findById(user.id))!.roles).toEqual(['viewer']);
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('credentials: passwords', () => {
      it('stores, returns and replaces a password hash', async () => {
        expect(await adapter.credentials.getPasswordHash('u1')).toBeNull();
        await adapter.credentials.setPasswordHash('u1', '$argon2id$one', now());
        expect(await adapter.credentials.getPasswordHash('u1')).toBe('$argon2id$one');
        await adapter.credentials.setPasswordHash('u1', '$argon2id$two', now());
        expect(await adapter.credentials.getPasswordHash('u1')).toBe('$argon2id$two');
        expect(await adapter.credentials.getPasswordHash('u2')).toBeNull();
      });
    });

    describe('credentials: TOTP', () => {
      const totp = (userId: string, lastUsedStep = 100) => ({
        userId,
        encryptedSecret: 'jwe-ciphertext',
        algorithm: 'SHA-1' as const,
        digits: 6,
        period: 30,
        lastUsedStep,
        createdAt: now(),
      });

      it('saves, returns, replaces and deletes a credential', async () => {
        expect(await adapter.credentials.getTotp('u1')).toBeNull();
        const first = totp('u1');
        await adapter.credentials.saveTotp(first);
        expect(await adapter.credentials.getTotp('u1')).toEqual(first);

        const second = { ...totp('u1', 500), encryptedSecret: 'other-ciphertext' };
        await adapter.credentials.saveTotp(second);
        expect(await adapter.credentials.getTotp('u1')).toEqual(second);

        expect(await adapter.credentials.deleteTotp('u1')).toBe(true);
        expect(await adapter.credentials.deleteTotp('u1')).toBe(false);
        expect(await adapter.credentials.getTotp('u1')).toBeNull();
      });

      it('advances the accepted step only forwards', async () => {
        await adapter.credentials.saveTotp(totp('u1', 100));
        expect(await adapter.credentials.advanceTotpStep('u1', 101)).toBe(true);
        expect(await adapter.credentials.advanceTotpStep('u1', 101)).toBe(false);
        expect(await adapter.credentials.advanceTotpStep('u1', 100)).toBe(false);
        expect(await adapter.credentials.advanceTotpStep('u1', 50)).toBe(false);
        expect(await adapter.credentials.advanceTotpStep('u1', 103)).toBe(true);
        expect((await adapter.credentials.getTotp('u1'))!.lastUsedStep).toBe(103);
      });

      it('returns false when the user has no TOTP credential', async () => {
        expect(await adapter.credentials.advanceTotpStep('nobody', 10)).toBe(false);
      });

      it('accepts a step exactly once when several calls race', async () => {
        await adapter.credentials.saveTotp(totp('u1', 100));
        const results = await Promise.all(Array.from({ length: 8 }, () => adapter.credentials.advanceTotpStep('u1', 101)));
        expect(countTrue(results)).toBe(1);
      });

      it('handles time steps beyond 32 bits', async () => {
        await adapter.credentials.saveTotp(totp('u1', 5_000_000_000));
        expect(await adapter.credentials.advanceTotpStep('u1', 5_000_000_001)).toBe(true);
        expect((await adapter.credentials.getTotp('u1'))!.lastUsedStep).toBe(5_000_000_001);
      });
    });

    describe('credentials: recovery codes', () => {
      it('replaces, counts and consumes codes', async () => {
        expect(await adapter.credentials.countRecoveryCodes('u1')).toBe(0);
        await adapter.credentials.replaceRecoveryCodes('u1', ['a', 'b', 'c'], now());
        expect(await adapter.credentials.countRecoveryCodes('u1')).toBe(3);

        expect(await adapter.credentials.consumeRecoveryCode('u1', 'b', now())).toBe(true);
        expect(await adapter.credentials.countRecoveryCodes('u1')).toBe(2);
        expect(await adapter.credentials.consumeRecoveryCode('u1', 'b', now())).toBe(false);
        expect(await adapter.credentials.consumeRecoveryCode('u1', 'zzz', now())).toBe(false);
      });

      it('invalidates old codes when new ones are generated', async () => {
        await adapter.credentials.replaceRecoveryCodes('u1', ['a', 'b'], now());
        await adapter.credentials.replaceRecoveryCodes('u1', ['c', 'd'], now());
        expect(await adapter.credentials.consumeRecoveryCode('u1', 'a', now())).toBe(false);
        expect(await adapter.credentials.consumeRecoveryCode('u1', 'c', now())).toBe(true);
        expect(await adapter.credentials.countRecoveryCodes('u1')).toBe(1);
      });

      it('removes all codes when replaced with an empty list', async () => {
        await adapter.credentials.replaceRecoveryCodes('u1', ['a', 'b'], now());
        await adapter.credentials.replaceRecoveryCodes('u1', [], now());
        expect(await adapter.credentials.countRecoveryCodes('u1')).toBe(0);
      });

      it('keeps the codes of different users apart', async () => {
        await adapter.credentials.replaceRecoveryCodes('u1', ['same'], now());
        await adapter.credentials.replaceRecoveryCodes('u2', ['same'], now());
        expect(await adapter.credentials.consumeRecoveryCode('u1', 'same', now())).toBe(true);
        expect(await adapter.credentials.countRecoveryCodes('u2')).toBe(1);
      });

      it('lets a code be used exactly once when several calls race', async () => {
        await adapter.credentials.replaceRecoveryCodes('u1', ['once'], now());
        const results = await Promise.all(
          Array.from({ length: 8 }, () => adapter.credentials.consumeRecoveryCode('u1', 'once', now())),
        );
        expect(countTrue(results)).toBe(1);
      });
    });

    describe('credentials: passkeys', () => {
      it('saves, lists and finds passkeys', async () => {
        const first = makePasskey({ userId: 'u1' });
        clock.advance(1000);
        const second = makePasskey({ userId: 'u1', name: null, createdAt: now() });
        expect(await adapter.credentials.savePasskey(first)).toBe(true);
        expect(await adapter.credentials.savePasskey(second)).toBe(true);
        expect(await adapter.credentials.listPasskeys('u1')).toEqual([first, second]);
        expect(await adapter.credentials.listPasskeys('u2')).toEqual([]);
        expect(await adapter.credentials.findPasskeyByCredentialId(second.credentialId)).toEqual(second);
        expect(await adapter.credentials.findPasskeyByCredentialId('unknown')).toBeNull();
      });

      it('refuses a credential id that is already registered, even for another user', async () => {
        const first = makePasskey({ userId: 'u1' });
        await adapter.credentials.savePasskey(first);
        const clash = makePasskey({ userId: 'u2', credentialId: first.credentialId });
        expect(await adapter.credentials.savePasskey(clash)).toBe(false);
        expect((await adapter.credentials.findPasskeyByCredentialId(first.credentialId))!.userId).toBe('u1');
      });

      it('records the counter and last use', async () => {
        const passkey = makePasskey({ userId: 'u1' });
        await adapter.credentials.savePasskey(passkey);
        clock.advance(5000);
        await adapter.credentials.updatePasskeyUsage(passkey.id, 4_000_000_000, now());
        const updated = await adapter.credentials.findPasskeyByCredentialId(passkey.credentialId);
        expect(updated!.counter).toBe(4_000_000_000);
        expect(updated!.lastUsedAt).toEqual(now());
      });

      it('deletes a passkey only for its owner', async () => {
        const passkey = makePasskey({ userId: 'u1' });
        await adapter.credentials.savePasskey(passkey);
        expect(await adapter.credentials.deletePasskey('u2', passkey.id)).toBe(false);
        expect(await adapter.credentials.deletePasskey('u1', passkey.id)).toBe(true);
        expect(await adapter.credentials.deletePasskey('u1', passkey.id)).toBe(false);
        expect(await adapter.credentials.listPasskeys('u1')).toEqual([]);
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('sessions', () => {
      it('creates a session with its first refresh token', async () => {
        const session = makeSession({ methods: ['pwd', 'otp'], assurance: 'aal2' });
        const token = makeToken();
        await adapter.sessions.create(session, token);

        expect(await adapter.sessions.findById(session.id)).toEqual(session);
        expect(await adapter.sessions.findByRefreshTokenHash(token.tokenHash)).toEqual({
          session,
          token: { ...token, sessionId: session.id, usedAt: null },
        });
      });

      it('keeps nullable session fields null', async () => {
        const session = makeSession({ dpopJkt: null, ip: null, userAgent: null });
        await adapter.sessions.create(session, makeToken());
        expect(await adapter.sessions.findById(session.id)).toEqual(session);
      });

      it('returns null for unknown sessions and token hashes', async () => {
        expect(await adapter.sessions.findById('nope')).toBeNull();
        expect(await adapter.sessions.findByRefreshTokenHash('nope')).toBeNull();
      });

      it('rotates a token: the old one is marked used and the new one belongs to the same session', async () => {
        const session = makeSession();
        const first = makeToken();
        await adapter.sessions.create(session, first);

        clock.advance(60_000);
        const second = makeToken({ createdAt: now() });
        expect(await adapter.sessions.rotate(first.id, second, now())).toBe(true);

        const old = await adapter.sessions.findByRefreshTokenHash(first.tokenHash);
        expect(old!.token.usedAt).toEqual(now());
        const fresh = await adapter.sessions.findByRefreshTokenHash(second.tokenHash);
        expect(fresh!.token).toEqual({ ...second, sessionId: session.id, usedAt: null });
        expect(fresh!.session.lastUsedAt).toEqual(now());
      });

      it('refuses to rotate a token twice and inserts nothing the second time', async () => {
        const session = makeSession();
        const first = makeToken();
        await adapter.sessions.create(session, first);
        const second = makeToken();
        const third = makeToken();
        expect(await adapter.sessions.rotate(first.id, second, now())).toBe(true);
        expect(await adapter.sessions.rotate(first.id, third, now())).toBe(false);
        expect(await adapter.sessions.findByRefreshTokenHash(third.tokenHash)).toBeNull();
      });

      it('refuses to rotate an unknown token', async () => {
        const stray = makeToken();
        expect(await adapter.sessions.rotate('no-such-token', stray, now())).toBe(false);
        expect(await adapter.sessions.findByRefreshTokenHash(stray.tokenHash)).toBeNull();
      });

      it('lets exactly one of several concurrent rotations win', async () => {
        const session = makeSession();
        const first = makeToken();
        await adapter.sessions.create(session, first);

        const candidates = Array.from({ length: 8 }, () => makeToken());
        const results = await Promise.all(candidates.map((next) => adapter.sessions.rotate(first.id, next, now())));
        expect(countTrue(results)).toBe(1);

        const inserted = await Promise.all(candidates.map((next) => adapter.sessions.findByRefreshTokenHash(next.tokenHash)));
        expect(inserted.filter((found) => found !== null)).toHaveLength(1);
        expect(inserted[results.indexOf(true)]).not.toBeNull();
      });

      it('updates authentication facts', async () => {
        const session = makeSession();
        await adapter.sessions.create(session, makeToken());
        clock.advance(120_000);
        const updated = await adapter.sessions.update(session.id, {
          authenticatedAt: now(),
          methods: ['pwd', 'otp'],
          assurance: 'aal2',
        });
        expect(updated).toEqual({ ...session, authenticatedAt: now(), methods: ['pwd', 'otp'], assurance: 'aal2' });
        expect(await adapter.sessions.update(session.id, {})).toEqual(updated);
        expect(await adapter.sessions.update('nope', { assurance: 'aal2' })).toBeNull();
      });

      it('lists a user’s live sessions, newest first', async () => {
        const oldest = makeSession({ userId: 'u1' });
        await adapter.sessions.create(oldest, makeToken());
        clock.advance(1000);
        const middle = makeSession({ userId: 'u1', createdAt: now() });
        await adapter.sessions.create(middle, makeToken());
        clock.advance(1000);
        const newest = makeSession({ userId: 'u1', createdAt: now() });
        await adapter.sessions.create(newest, makeToken());
        await adapter.sessions.create(makeSession({ userId: 'u2' }), makeToken());

        await adapter.sessions.revoke(middle.id, 'logout', now());
        expect((await adapter.sessions.listByUser('u1')).map((session) => session.id)).toEqual([newest.id, oldest.id]);
      });

      it('revokes a session once', async () => {
        const session = makeSession();
        const token = makeToken();
        await adapter.sessions.create(session, token);
        clock.advance(1000);
        expect(await adapter.sessions.revoke(session.id, 'refresh_reuse', now())).toBe(true);
        expect(await adapter.sessions.revoke(session.id, 'logout', now())).toBe(false);
        expect(await adapter.sessions.revoke('nope', 'logout', now())).toBe(false);

        const found = await adapter.sessions.findByRefreshTokenHash(token.tokenHash);
        expect(found!.session.revokedAt).toEqual(now());
        expect(found!.session.revokedReason).toBe('refresh_reuse');
      });

      it('revokes all of a user’s sessions, optionally keeping one', async () => {
        const keep = makeSession({ userId: 'u1' });
        const one = makeSession({ userId: 'u1' });
        const two = makeSession({ userId: 'u1' });
        const other = makeSession({ userId: 'u2' });
        for (const session of [keep, one, two, other]) await adapter.sessions.create(session, makeToken());

        expect(await adapter.sessions.revokeAllForUser('u1', 'password_changed', now(), keep.id)).toBe(2);
        expect((await adapter.sessions.listByUser('u1')).map((session) => session.id)).toEqual([keep.id]);
        expect(await adapter.sessions.listByUser('u2')).toHaveLength(1);

        expect(await adapter.sessions.revokeAllForUser('u1', 'logout_all', now())).toBe(1);
        expect(await adapter.sessions.revokeAllForUser('u1', 'logout_all', now())).toBe(0);
      });

      it('deletes expired and long-revoked sessions together with their tokens', async () => {
        const expired = makeSession({ expiresAt: new Date(clock() + 1000) });
        const expiredToken = makeToken();
        const revoked = makeSession();
        const revokedToken = makeToken();
        const live = makeSession();
        const liveToken = makeToken();
        await adapter.sessions.create(expired, expiredToken);
        await adapter.sessions.create(revoked, revokedToken);
        await adapter.sessions.create(live, liveToken);
        await adapter.sessions.revoke(revoked.id, 'logout', now());

        clock.advance(60_000);
        expect(await adapter.sessions.deleteExpired(now())).toBe(2);
        expect(await adapter.sessions.findById(expired.id)).toBeNull();
        expect(await adapter.sessions.findByRefreshTokenHash(expiredToken.tokenHash)).toBeNull();
        expect(await adapter.sessions.findByRefreshTokenHash(revokedToken.tokenHash)).toBeNull();
        expect(await adapter.sessions.findByRefreshTokenHash(liveToken.tokenHash)).not.toBeNull();
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('audit', () => {
      const event = (overrides: Partial<AuditEvent> = {}): AuditEvent =>
        ({
          id: unique('event'),
          type: 'login.succeeded',
          at: now().toISOString(),
          outcome: 'success',
          userId: 'u1',
          sessionId: 's1',
          ip: '203.0.113.5',
          data: { method: 'pwd', riskScore: 0, mfa: false },
          ...overrides,
        }) as AuditEvent;

      it('appends events and lists them newest first', async () => {
        const first = event();
        clock.advance(1000);
        const second = event({ type: 'login.failed', outcome: 'failure', data: { method: 'pwd', identifierHash: 'h' } } as Partial<AuditEvent>);
        clock.advance(1000);
        const third = event({ userId: 'u2' });
        for (const item of [first, second, third]) await adapter.audit.append(item);

        expect(await adapter.audit.list()).toEqual([third, second, first]);
      });

      it('filters by user, type and time, and limits the result', async () => {
        const first = event();
        clock.advance(1000);
        const second = event({ type: 'login.failed', outcome: 'failure', data: { method: 'pwd' } } as Partial<AuditEvent>);
        clock.advance(1000);
        const third = event({ userId: 'u2' });
        for (const item of [first, second, third]) await adapter.audit.append(item);

        expect(await adapter.audit.list({ userId: 'u1' })).toEqual([second, first]);
        expect(await adapter.audit.list({ type: 'login.failed' })).toEqual([second]);
        expect(await adapter.audit.list({ since: second.at })).toEqual([third, second]);
        expect(await adapter.audit.list({ limit: 1 })).toEqual([third]);
        expect(await adapter.audit.list({ userId: 'u1', type: 'login.succeeded', limit: 5 })).toEqual([first]);
      });

      it('keeps events without a user or session', async () => {
        const anonymous = event({ type: 'key.created', data: { kid: 'k', algorithm: 'EdDSA' } } as Partial<AuditEvent>);
        delete (anonymous as { userId?: string }).userId;
        delete (anonymous as { sessionId?: string }).sessionId;
        await adapter.audit.append(anonymous);
        expect(await adapter.audit.list()).toEqual([anonymous]);
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('signing keys', () => {
      it('inserts a first key and lists it', async () => {
        const key = makeKey();
        expect(await adapter.keys.insertPending(key, null)).toBe(true);
        expect(await adapter.keys.list()).toEqual([key]);
      });

      it('allows only one pending key', async () => {
        expect(await adapter.keys.insertPending(makeKey(), null)).toBe(true);
        expect(await adapter.keys.insertPending(makeKey(), null)).toBe(false);
        expect(await adapter.keys.list()).toHaveLength(1);
      });

      it('inserts only when the active key is the one the caller expects', async () => {
        const first = makeKey();
        await adapter.keys.insertPending(first, null);
        await adapter.keys.activate(first.kid, now());

        // A caller that still believes there is no active key, or a different one, is refused.
        expect(await adapter.keys.insertPending(makeKey(), null)).toBe(false);
        expect(await adapter.keys.insertPending(makeKey(), 'some-other-kid')).toBe(false);
        expect(await adapter.keys.insertPending(makeKey(), first.kid)).toBe(true);
      });

      it('lets exactly one of several concurrent inserts win', async () => {
        const results = await Promise.all(Array.from({ length: 6 }, () => adapter.keys.insertPending(makeKey(), null)));
        expect(countTrue(results)).toBe(1);
        expect((await adapter.keys.list()).filter((key) => key.status === 'pending')).toHaveLength(1);
      });

      it('activates a pending key and moves the previous active key to retiring', async () => {
        const first = makeKey();
        await adapter.keys.insertPending(first, null);
        expect(await adapter.keys.activate(first.kid, now())).toBe(true);
        const activatedAt = now();

        clock.advance(60_000);
        const second = makeKey({ createdAt: now() });
        await adapter.keys.insertPending(second, first.kid);
        clock.advance(60_000);
        expect(await adapter.keys.activate(second.kid, now())).toBe(true);

        const byKid = Object.fromEntries((await adapter.keys.list()).map((key) => [key.kid, key]));
        expect(byKid[first.kid]).toMatchObject({ status: 'retiring', activatedAt, retiringAt: now() });
        expect(byKid[second.kid]).toMatchObject({ status: 'active', activatedAt: now(), retiringAt: null });
      });

      it('refuses to activate a key that is not pending, and changes nothing', async () => {
        const first = makeKey();
        await adapter.keys.insertPending(first, null);
        await adapter.keys.activate(first.kid, now());

        expect(await adapter.keys.activate(first.kid, now())).toBe(false);
        expect(await adapter.keys.activate('unknown', now())).toBe(false);
        expect((await adapter.keys.list())[0]!.status).toBe('active');
      });

      it('lets exactly one of several concurrent activations win and never leaves two active keys', async () => {
        const first = makeKey();
        await adapter.keys.insertPending(first, null);
        await adapter.keys.activate(first.kid, now());
        const second = makeKey();
        await adapter.keys.insertPending(second, first.kid);

        const results = await Promise.all(Array.from({ length: 6 }, () => adapter.keys.activate(second.kid, now())));
        expect(countTrue(results)).toBe(1);
        const statuses = (await adapter.keys.list()).map((key) => key.status).sort();
        expect(statuses).toEqual(['active', 'retiring']);
      });

      it('retires only a retiring key', async () => {
        const first = makeKey();
        await adapter.keys.insertPending(first, null);
        expect(await adapter.keys.retire(first.kid, now())).toBe(false);
        await adapter.keys.activate(first.kid, now());
        expect(await adapter.keys.retire(first.kid, now())).toBe(false);

        const second = makeKey();
        await adapter.keys.insertPending(second, first.kid);
        await adapter.keys.activate(second.kid, now());
        clock.advance(1000);
        expect(await adapter.keys.retire(first.kid, now())).toBe(true);
        expect(await adapter.keys.retire(first.kid, now())).toBe(false);

        const retired = (await adapter.keys.list()).find((key) => key.kid === first.kid);
        expect(retired).toMatchObject({ status: 'retired', retiredAt: now() });
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('devices', () => {
      it('records a new device and updates it on later sightings', async () => {
        const first = now();
        await adapter.devices.upsert({ userId: 'u1', deviceKey: 'd1', ip: '203.0.113.5', country: 'DE', latitude: 52.5, longitude: 13.4, now: first });
        expect(await adapter.devices.listByUser('u1')).toEqual([
          { userId: 'u1', deviceKey: 'd1', firstSeenAt: first, lastSeenAt: first, lastIp: '203.0.113.5', lastCountry: 'DE', lastLatitude: 52.5, lastLongitude: 13.4 },
        ]);

        clock.advance(3_600_000);
        await adapter.devices.upsert({ userId: 'u1', deviceKey: 'd1', ip: '198.51.100.7', country: null, latitude: null, longitude: null, now: now() });
        expect(await adapter.devices.listByUser('u1')).toEqual([
          { userId: 'u1', deviceKey: 'd1', firstSeenAt: first, lastSeenAt: now(), lastIp: '198.51.100.7', lastCountry: null, lastLatitude: null, lastLongitude: null },
        ]);
      });

      it('keeps devices per user', async () => {
        await adapter.devices.upsert({ userId: 'u1', deviceKey: 'd1', ip: null, country: null, latitude: null, longitude: null, now: now() });
        await adapter.devices.upsert({ userId: 'u1', deviceKey: 'd2', ip: null, country: null, latitude: null, longitude: null, now: now() });
        await adapter.devices.upsert({ userId: 'u2', deviceKey: 'd1', ip: null, country: null, latitude: null, longitude: null, now: now() });
        expect((await adapter.devices.listByUser('u1')).map((device) => device.deviceKey).sort()).toEqual(['d1', 'd2']);
        expect(await adapter.devices.listByUser('u2')).toHaveLength(1);
        expect(await adapter.devices.listByUser('u3')).toEqual([]);
      });
    });

    // -----------------------------------------------------------------------------------------
    describe('ephemeral state', () => {
      it('stores and returns JSON values', async () => {
        const value = { userId: 'u1', attempts: 2, methods: ['pwd'], nested: { ok: true, none: null } };
        await adapter.ephemeral.set('k', value, 60);
        expect(await adapter.ephemeral.get('k')).toEqual(value);
        await adapter.ephemeral.set('k', 'replaced', 60);
        expect(await adapter.ephemeral.get('k')).toBe('replaced');
        expect(await adapter.ephemeral.get('missing')).toBeNull();
      });

      it('treats an expired entry as missing', async () => {
        await adapter.ephemeral.set('k', 'v', 60);
        clock.advanceSec(59);
        expect(await adapter.ephemeral.get('k')).toBe('v');
        clock.advanceSec(1);
        expect(await adapter.ephemeral.get('k')).toBeNull();
        expect(await adapter.ephemeral.take('k')).toBeNull();
      });

      it('take returns the value once', async () => {
        await adapter.ephemeral.set('k', { challenge: 'abc' }, 60);
        expect(await adapter.ephemeral.take('k')).toEqual({ challenge: 'abc' });
        expect(await adapter.ephemeral.take('k')).toBeNull();
        expect(await adapter.ephemeral.get('k')).toBeNull();
      });

      it('take gives the value to exactly one of several concurrent callers', async () => {
        await adapter.ephemeral.set('k', 'ticket', 60);
        const results = await Promise.all(Array.from({ length: 8 }, () => adapter.ephemeral.take('k')));
        expect(results.filter((value) => value !== null)).toEqual(['ticket']);
      });

      it('setIfAbsent succeeds once until the entry expires', async () => {
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(true);
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(false);
        clock.advanceSec(29);
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(false);
        clock.advanceSec(1);
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(true);
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(false);
      });

      it('setIfAbsent does not extend the lifetime of a live entry', async () => {
        await adapter.ephemeral.setIfAbsent('seen', 30);
        clock.advanceSec(20);
        await adapter.ephemeral.setIfAbsent('seen', 30);
        clock.advanceSec(10);
        expect(await adapter.ephemeral.setIfAbsent('seen', 30)).toBe(true);
      });

      it('setIfAbsent lets exactly one of several concurrent callers win', async () => {
        const results = await Promise.all(Array.from({ length: 8 }, () => adapter.ephemeral.setIfAbsent('race', 30)));
        expect(countTrue(results)).toBe(1);
      });

      it('increment counts up and can be read back', async () => {
        expect(await adapter.ephemeral.increment('count', 60)).toBe(1);
        expect(await adapter.ephemeral.increment('count', 60)).toBe(2);
        expect(await adapter.ephemeral.increment('count', 60)).toBe(3);
        expect(await adapter.ephemeral.get('count')).toBe(3);
      });

      it('increment keeps the expiry set by the first call', async () => {
        await adapter.ephemeral.increment('count', 60);
        clock.advanceSec(50);
        expect(await adapter.ephemeral.increment('count', 60)).toBe(2);
        clock.advanceSec(10);
        expect(await adapter.ephemeral.get('count')).toBeNull();
        expect(await adapter.ephemeral.increment('count', 60)).toBe(1);
      });

      it('increment does not lose updates when several calls race', async () => {
        const results = await Promise.all(Array.from({ length: 10 }, () => adapter.ephemeral.increment('race', 60)));
        expect([...results].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      });

      it('purgeExpired removes only expired entries', async () => {
        await adapter.ephemeral.set('short', 1, 10);
        await adapter.ephemeral.set('long', 2, 100);
        await adapter.ephemeral.setIfAbsent('marker', 10);
        clock.advanceSec(11);
        expect(await adapter.ephemeral.purgeExpired()).toBe(2);
        expect(await adapter.ephemeral.purgeExpired()).toBe(0);
        expect(await adapter.ephemeral.get('long')).toBe(2);
      });

      it('accepts keys with unusual characters', async () => {
        const key = "login:id:a+b/c=d'e\"f:%_\\";
        await adapter.ephemeral.set(key, 'v', 60);
        expect(await adapter.ephemeral.get(key)).toBe('v');
        expect(await adapter.ephemeral.take(key)).toBe('v');
      });
    });
  });
}
