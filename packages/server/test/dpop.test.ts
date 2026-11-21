import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { memoryReplayStore, normalizeHtu, validateDpopProof, type DpopValidatorOptions } from '../src/dpop/proof.js';
import { createFakeClock } from '../src/testing/clock.js';
import { createDpopKey, createDpopProof, encodeSegment, expectAuthError } from './helpers.js';

const URL_ = 'https://api.example.com/auth/refresh';

function setup(overrides: Partial<DpopValidatorOptions> = {}) {
  const clock = createFakeClock();
  const options: DpopValidatorOptions = {
    algorithms: ['ES256'],
    iatToleranceSec: 60,
    replayStore: memoryReplayStore({ now: clock }),
    now: clock,
    ...overrides,
  };
  return { clock, options };
}

describe('validateDpopProof', () => {
  it('accepts a valid proof and returns the thumbprint of the signing key', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), jti: 'proof-id-1' });
    expect(await validateDpopProof({ proof, method: 'POST', url: URL_ }, options)).toEqual({ jkt: key.jkt, jti: 'proof-id-1' });
  });

  it('requires a proof', async () => {
    const { options } = setup();
    await expectAuthError(validateDpopProof({ proof: undefined, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_REQUIRED');
    await expectAuthError(validateDpopProof({ proof: '', method: 'POST', url: URL_ }, options), 'DPOP_PROOF_REQUIRED');
  });

  it('rejects a proof made for another HTTP method', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'GET', url: URL_, nowMs: clock() });
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects a proof made for another URL', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    for (const url of [
      'https://api.example.com/auth/logout',
      'https://evil.example/auth/refresh',
      'http://api.example.com/auth/refresh',
      'https://api.example.com:8443/auth/refresh',
      'not a url',
    ]) {
      const proof = await createDpopProof(key, { method: 'POST', url, nowMs: clock() });
      await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    }
  });

  it('ignores the query string and fragment, and normalises case and default ports', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const variants = [
      { proofUrl: URL_, requestUrl: `${URL_}?page=2#top` },
      { proofUrl: `${URL_}?x=1`, requestUrl: URL_ },
      { proofUrl: 'HTTPS://API.EXAMPLE.COM:443/auth/refresh', requestUrl: URL_ },
    ];
    for (const { proofUrl, requestUrl } of variants) {
      const proof = await createDpopProof(key, { method: 'POST', url: proofUrl, nowMs: clock() });
      await validateDpopProof({ proof, method: 'POST', url: requestUrl }, options);
    }
    expect(normalizeHtu('https://API.example.com:443/a/b?c=d#e')).toBe('https://api.example.com/a/b');
    expect(normalizeHtu('ftp://example.com/x')).toBeNull();
  });

  it('rejects a proof that is too old or dated in the future', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const now = Math.floor(clock() / 1000);

    for (const iat of [now - 61, now + 61, now - 3600]) {
      const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), iat });
      await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    }
    for (const iat of [now - 60, now + 60, now]) {
      const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), iat });
      await validateDpopProof({ proof, method: 'POST', url: URL_ }, options);
    }
  });

  it('tells a client with a wrong clock what time it is, so it can correct its proofs', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const now = Math.floor(clock() / 1000);
    const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), iat: now + 600 });
    const error = await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    expect(error.details).toEqual({ reason: 'iat_out_of_window', serverTime: now });

    // Other failures do not carry the hint.
    const wrongMethod = await createDpopProof(key, { method: 'GET', url: URL_, nowMs: clock() });
    const other = await expectAuthError(validateDpopProof({ proof: wrongMethod, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    expect(other.details).toBeUndefined();
  });

  it('rejects a proof that becomes stale while waiting', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock() });
    clock.advanceSec(61);
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects a replayed proof', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock() });
    await validateDpopProof({ proof, method: 'POST', url: URL_ }, options);
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_REPLAYED');

    clock.advanceSec(30);
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_REPLAYED');
  });

  it('rejects a second proof that reuses the id of an earlier one', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const first = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), jti: 'same-proof-id' });
    const second = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock() + 1000, jti: 'same-proof-id' });
    expect(second).not.toBe(first);
    await validateDpopProof({ proof: first, method: 'POST', url: URL_ }, options);
    await expectAuthError(validateDpopProof({ proof: second, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_REPLAYED');
  });

  it('lets two different keys use the same proof id', async () => {
    const { clock, options } = setup();
    const one = await createDpopKey();
    const two = await createDpopKey();
    for (const key of [one, two]) {
      const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), jti: 'shared-proof-id' });
      await validateDpopProof({ proof, method: 'POST', url: URL_ }, options);
    }
  });

  it('rejects a proof signed by a different key than the one expected', async () => {
    const { clock, options } = setup();
    const bound = await createDpopKey();
    const thief = await createDpopKey();
    const proof = await createDpopProof(thief, { method: 'POST', url: URL_, nowMs: clock() });
    await expectAuthError(
      validateDpopProof({ proof, method: 'POST', url: URL_, expectedJkt: bound.jkt }, options),
      'DPOP_KEY_MISMATCH',
    );
  });

  it('does not burn a proof id when the key does not match', async () => {
    const { clock, options } = setup();
    const bound = await createDpopKey();
    const thief = await createDpopKey();
    const stolenId = await createDpopProof(thief, { method: 'POST', url: URL_, nowMs: clock(), jti: 'contested-id' });
    await expectAuthError(
      validateDpopProof({ proof: stolenId, method: 'POST', url: URL_, expectedJkt: bound.jkt }, options),
      'DPOP_KEY_MISMATCH',
    );
    const real = await createDpopProof(bound, { method: 'POST', url: URL_, nowMs: clock(), jti: 'contested-id' });
    await validateDpopProof({ proof: real, method: 'POST', url: URL_, expectedJkt: bound.jkt }, options);
  });

  it('requires the access token hash when a token is presented', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const accessToken = 'header.payload.signature';

    const good = await createDpopProof(key, { method: 'GET', url: URL_, nowMs: clock(), accessToken });
    await validateDpopProof({ proof: good, method: 'GET', url: URL_, accessToken }, options);

    const missing = await createDpopProof(key, { method: 'GET', url: URL_, nowMs: clock() });
    await expectAuthError(validateDpopProof({ proof: missing, method: 'GET', url: URL_, accessToken }, options), 'DPOP_PROOF_INVALID');

    const wrong = await createDpopProof(key, { method: 'GET', url: URL_, nowMs: clock(), accessToken: 'another.token.value' });
    await expectAuthError(validateDpopProof({ proof: wrong, method: 'GET', url: URL_, accessToken }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects the wrong typ', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    for (const typ of ['JWT', 'at+jwt', 'DPOP+JWT']) {
      const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), typ });
      await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    }
  });

  it('rejects an algorithm that is not on the allowlist', async () => {
    const { clock, options } = setup();
    const edKey = await createDpopKey('EdDSA');
    const proof = await createDpopProof(edKey, { method: 'POST', url: URL_, nowMs: clock() });
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');

    const permissive = setup({ algorithms: ['ES256', 'EdDSA'] });
    const allowed = await createDpopProof(edKey, { method: 'POST', url: URL_, nowMs: permissive.clock() });
    expect((await validateDpopProof({ proof: allowed, method: 'POST', url: URL_ }, permissive.options)).jkt).toBe(edKey.jkt);
  });

  it('rejects symmetric and unsigned proofs even if someone allowlists them', async () => {
    const { clock, options } = setup({ algorithms: ['ES256', 'HS256', 'none'] });
    const now = Math.floor(clock() / 1000);
    const claims = { htm: 'POST', htu: URL_, jti: 'proof-id-hs', iat: now };
    const secret = new TextEncoder().encode('0123456789abcdef0123456789abcdef');

    const hmac = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'HS256', typ: 'dpop+jwt', jwk: { kty: 'oct', k: Buffer.from(secret).toString('base64url') } as never })
      .sign(secret);
    await expectAuthError(validateDpopProof({ proof: hmac, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');

    const key = await createDpopKey();
    const unsigned = `${encodeSegment({ alg: 'none', typ: 'dpop+jwt', jwk: key.publicJwk })}.${encodeSegment(claims)}.`;
    await expectAuthError(validateDpopProof({ proof: unsigned, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects a proof that embeds a private key', async () => {
    const { clock, options } = setup();
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    const key = await createDpopKey();
    const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), jwk: privateJwk as Record<string, unknown> });
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects a proof whose embedded key did not sign it', async () => {
    const { clock, options } = setup();
    const signer = await createDpopKey();
    const claimed = await createDpopKey();
    const proof = await createDpopProof(signer, { method: 'POST', url: URL_, nowMs: clock(), jwk: claimed.publicJwk as Record<string, unknown> });
    await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects proofs with missing claims', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    for (const missing of ['jti', 'htm', 'htu', 'iat']) {
      const proof = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), claims: { [missing]: undefined } });
      await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    }
    const shortId = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock(), jti: 'x' });
    await expectAuthError(validateDpopProof({ proof: shortId, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });

  it('rejects junk', async () => {
    const { options } = setup();
    for (const proof of ['abc', 'a.b.c', 'a.b', `${'x'.repeat(9000)}.y.z`, '{}']) {
      await expectAuthError(validateDpopProof({ proof, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
    }
  });

  it('treats the request method case-insensitively but the proof claim exactly', async () => {
    const { clock, options } = setup();
    const key = await createDpopKey();
    const upper = await createDpopProof(key, { method: 'POST', url: URL_, nowMs: clock() });
    await validateDpopProof({ proof: upper, method: 'post', url: URL_ }, options);
    const lower = await createDpopProof(key, { method: 'post', url: URL_, nowMs: clock() });
    await expectAuthError(validateDpopProof({ proof: lower, method: 'POST', url: URL_ }, options), 'DPOP_PROOF_INVALID');
  });
});

describe('memoryReplayStore', () => {
  it('forgets an entry after its lifetime', async () => {
    const clock = createFakeClock();
    const store = memoryReplayStore({ now: clock });
    expect(await store.setIfAbsent('a', 10)).toBe(true);
    expect(await store.setIfAbsent('a', 10)).toBe(false);
    clock.advanceSec(11);
    expect(await store.setIfAbsent('a', 10)).toBe(true);
  });
});
