import { describe, expect, it } from 'vitest';
import { KeyManager } from '../src/keys/key-manager.js';
import { DataProtector } from '../src/util/protector.js';
import { createTokenEnv, expectAuthError, randomDataKey, sampleSession, sampleUser } from './helpers.js';

const DAY = 86_400;

describe('KeyManager', () => {
  it('creates and activates a key on first use', async () => {
    const env = createTokenEnv();
    const { kid, algorithm } = await env.keys.signingKey();
    expect(algorithm).toBe('EdDSA');

    const stored = await env.adapter.keys.list();
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ kid, status: 'active', algorithm: 'EdDSA' });
    expect(env.sink.events.map((event) => event.type)).toEqual(['key.created', 'key.activated']);
  });

  it('uses the RFC 7638 thumbprint as the key id', async () => {
    const env = createTokenEnv();
    const { kid } = await env.keys.signingKey();
    const [jwk] = (await env.keys.jwks()).keys;
    const canonical = JSON.stringify({ crv: jwk!.crv, kty: jwk!.kty, x: jwk!.x });
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
    expect(kid).toBe(Buffer.from(digest).toString('base64url'));
  });

  it('publishes public keys only', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    const { keys } = await env.keys.jwks();
    expect(keys).toHaveLength(1);
    expect(Object.keys(keys[0]!).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
    expect(keys[0]).toMatchObject({ kty: 'OKP', crv: 'Ed25519', use: 'sig', alg: 'EdDSA' });
    expect(JSON.stringify(keys)).not.toContain('"d"');
  });

  it('stores the private key encrypted', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    const [stored] = await env.adapter.keys.list();
    expect(stored!.encryptedPrivateJwk.split('.')).toHaveLength(5);
    expect(stored!.publicJwk).not.toHaveProperty('d');

    const privateJwk = JSON.parse(await env.protector.decrypt(stored!.encryptedPrivateJwk)) as { d: string };
    expect(privateJwk.d.length).toBeGreaterThan(20);
    expect(JSON.stringify(stored)).not.toContain(privateJwk.d);
  });

  it('cannot use a stored key without the data key it was encrypted with', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    const other = new KeyManager({
      store: env.adapter.keys,
      protector: new DataProtector([{ id: 'k1', key: randomDataKey() }]),
      clock: env.time,
      audit: env.audit,
      algorithm: 'EdDSA',
      rotateEveryDays: 90,
      publishLeadSec: 600,
      retireAfterSec: 1505,
      cacheTtlSec: 30,
    });
    await expectAuthError(other.signingKey(), 'INTERNAL_ERROR');
  });

  it('still reads keys after a new data key is put first', async () => {
    const env = createTokenEnv();
    const { kid } = await env.keys.signingKey();
    const rotatedProtector = new DataProtector([
      { id: 'k2', key: randomDataKey() },
      { id: 'k1', key: env.dataKey },
    ]);
    const later = new KeyManager({
      store: env.adapter.keys,
      protector: rotatedProtector,
      clock: env.time,
      audit: env.audit,
      algorithm: 'EdDSA',
      rotateEveryDays: 90,
      publishLeadSec: 600,
      retireAfterSec: 1505,
      cacheTtlSec: 30,
    });
    expect((await later.signingKey()).kid).toBe(kid);
  });

  it('rotates through pending, active, retiring and retired', async () => {
    const env = createTokenEnv({ dpop: { mode: 'off' } });
    const first = (await env.keys.signingKey()).kid;
    const oldToken = (await env.tokens.issue(sampleUser(), sampleSession(env.clock))).accessToken;

    // Publish the next key. It must not sign yet.
    const { kid: second } = await env.keys.rotate();
    expect(second).not.toBe(first);
    expect((await env.keys.jwks()).keys.map((key) => key.kid)).toEqual([first, second]);
    expect((await env.keys.signingKey()).kid).toBe(first);

    env.clock.advanceSec(565);
    expect((await env.keys.signingKey()).kid).toBe(first);

    // After the publication lead time (600 s) the new key signs and the old one only verifies.
    // The step is 36 s so that the 30 s in-memory key cache has also expired.
    env.clock.advanceSec(36);
    expect((await env.keys.signingKey()).kid).toBe(second);
    const statuses = Object.fromEntries((await env.adapter.keys.list()).map((key) => [key.kid, key.status]));
    expect(statuses).toEqual({ [first]: 'retiring', [second]: 'active' });
    expect((await env.keys.jwks()).keys.map((key) => key.kid)).toEqual([first, second]);

    // A token signed by the old key before the switch is still accepted.
    const verified = await env.tokens.verify(oldToken, {}, {});
    expect(verified.subject.id).toBe('user-1');

    // Once every token it signed has expired, the old key leaves the JWKS and stops verifying.
    env.clock.advanceSec(1505);
    expect((await env.keys.jwks()).keys.map((key) => key.kid)).toEqual([second]);
    expect(await env.keys.verificationKey(first)).toBeNull();
    await expectAuthError(env.tokens.verify(oldToken), 'TOKEN_KEY_UNKNOWN');

    expect(env.sink.ofType('key.created')).toHaveLength(2);
    expect(env.sink.ofType('key.activated').map((event) => event.data.kid)).toEqual([first, second]);
    expect(env.sink.ofType('key.retired').map((event) => event.data.kid)).toEqual([first]);
  }, 30_000);

  it('returns the key already pending when rotate is called twice', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    const one = await env.keys.rotate();
    const two = await env.keys.rotate();
    expect(two.kid).toBe(one.kid);
    expect((await env.adapter.keys.list()).filter((key) => key.status === 'pending')).toHaveLength(1);
  });

  it('rotates on its own when the active key is too old', async () => {
    const env = createTokenEnv();
    const first = (await env.keys.signingKey()).kid;

    env.clock.advanceSec(90 * DAY - 60);
    expect((await env.keys.signingKey()).kid).toBe(first);
    expect(await env.adapter.keys.list()).toHaveLength(1);

    env.clock.advanceSec(61);
    expect((await env.keys.signingKey()).kid).toBe(first);
    expect((await env.adapter.keys.list()).map((key) => key.status).sort()).toEqual(['active', 'pending']);

    env.clock.advanceSec(601);
    expect((await env.keys.signingKey()).kid).not.toBe(first);
  });

  it('does not rotate on its own when rotateEveryDays is 0', async () => {
    const env = createTokenEnv({ keys: { rotateEveryDays: 0 } });
    const first = (await env.keys.signingKey()).kid;
    env.clock.advanceSec(1000 * DAY);
    expect((await env.keys.signingKey()).kid).toBe(first);
    expect(await env.adapter.keys.list()).toHaveLength(1);
  });

  it('replaces the key when the configured algorithm changes', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    const es256 = createTokenEnv(
      { tokens: { algorithm: 'ES256', allowedAlgorithms: ['ES256', 'EdDSA'] } },
      { clock: env.clock, adapter: env.adapter, dataKey: env.dataKey },
    );
    expect((await es256.keys.signingKey()).algorithm).toBe('EdDSA');
    env.clock.advanceSec(601);
    const next = await es256.keys.signingKey();
    expect(next.algorithm).toBe('ES256');
    const published = (await es256.keys.jwks()).keys.find((key) => key.kid === next.kid);
    expect(published).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
    expect(published).not.toHaveProperty('d');
  });

  it('leaves exactly one pending key when two instances rotate at once', async () => {
    const one = createTokenEnv();
    await one.keys.signingKey();
    const two = createTokenEnv({}, { clock: one.clock, adapter: one.adapter, dataKey: one.dataKey });

    const [a, b] = await Promise.all([one.keys.rotate(), two.keys.rotate()]);
    expect(a.kid).toBe(b.kid);
    const stored = await one.adapter.keys.list();
    expect(stored.filter((key) => key.status === 'pending')).toHaveLength(1);
    expect(stored.filter((key) => key.status === 'active')).toHaveLength(1);
  });

  it('settles on one active key when two instances start on an empty store', async () => {
    const one = createTokenEnv();
    const two = createTokenEnv({}, { clock: one.clock, adapter: one.adapter, dataKey: one.dataKey });

    const [a, b] = await Promise.all([one.keys.signingKey(), two.keys.signingKey()]);
    expect(a.kid).toBe(b.kid);
    const stored = await one.adapter.keys.list();
    expect(stored).toHaveLength(1);
    expect(stored[0]!.status).toBe('active');
  });

  it('picks up a rotation done by another instance', async () => {
    const one = createTokenEnv({ dpop: { mode: 'off' } });
    const first = (await one.keys.signingKey()).kid;
    const two = createTokenEnv({ dpop: { mode: 'off' } }, { clock: one.clock, adapter: one.adapter, dataKey: one.dataKey });
    expect((await two.keys.signingKey()).kid).toBe(first);

    await one.keys.rotate();
    one.clock.advanceSec(601);
    const second = (await one.keys.signingKey()).kid;
    const token = (await one.tokens.issue(sampleUser(), sampleSession(one.clock))).accessToken;

    // Instance two has not signed since the rotation, but can already verify the new key's tokens.
    expect((await two.tokens.verify(token)).claims.sub).toBe('user-1');
    expect((await two.keys.signingKey()).kid).toBe(second);
  });

  it('does not reload the key list for every unknown key id', async () => {
    const env = createTokenEnv();
    await env.keys.signingKey();
    let lists = 0;
    const original = env.adapter.keys.list.bind(env.adapter.keys);
    env.adapter.keys.list = async () => {
      lists++;
      return original();
    };
    for (let index = 0; index < 20; index++) {
      expect(await env.keys.verificationKey(`unknown-${index}`)).toBeNull();
    }
    expect(lists).toBe(1);
  });
});
