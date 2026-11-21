import { SignJWT, decodeJwt, decodeProtectedHeader, exportSPKI, generateKeyPair, importJWK, type CryptoKey, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  AUDIENCE,
  ISSUER,
  createDpopKey,
  createDpopProof,
  createTokenEnv,
  encodeSegment,
  expectAuthError,
  sampleSession,
  sampleUser,
} from './helpers.js';

const API_URL = 'https://api.example.com/invoices/1';

/** An environment where tokens are not bound to a device key, to test the JWT checks on their own. */
function unboundEnv(overrides = {}) {
  return createTokenEnv({ dpop: { mode: 'off' }, ...overrides });
}

async function issueUnbound(env: ReturnType<typeof createTokenEnv>) {
  return (await env.tokens.issue(sampleUser(), sampleSession(env.clock))).accessToken;
}

/** Signs arbitrary claims with the server's real active key, to build tokens the server would never issue. */
async function signWithActiveKey(
  env: ReturnType<typeof createTokenEnv>,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
) {
  const { kid, algorithm, privateKey } = await env.keys.signingKey();
  const now = Math.floor(env.clock() / 1000);
  return new SignJWT({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'user-1',
    iat: now,
    exp: now + 900,
    jti: 'jti-1',
    sid: 'session-1',
    roles: [],
    amr: ['pwd'],
    acr: 'aal1',
    auth_time: now,
    ...claims,
  })
    .setProtectedHeader({ alg: algorithm, kid, typ: 'at+jwt', ...header })
    .sign(privateKey);
}

describe('access token issuance', () => {
  it('issues a 15-minute token with the documented header and claims', async () => {
    const env = unboundEnv();
    const session = sampleSession(env.clock, { methods: ['pwd', 'otp'], assurance: 'aal2' });
    const { accessToken, accessTokenExpiresAt } = await env.tokens.issue(sampleUser(), session);
    const now = Math.floor(env.clock() / 1000);

    const header = decodeProtectedHeader(accessToken);
    expect(header).toEqual({ alg: 'EdDSA', kid: (await env.keys.signingKey()).kid, typ: 'at+jwt' });

    const claims = decodeJwt(accessToken);
    expect(claims).toMatchObject({
      iss: ISSUER,
      aud: AUDIENCE,
      sub: 'user-1',
      iat: now,
      exp: now + 900,
      sid: 'session-1',
      roles: ['editor'],
      amr: ['pwd', 'otp'],
      acr: 'aal2',
      auth_time: now,
    });
    expect(typeof claims.jti).toBe('string');
    expect(claims).not.toHaveProperty('cnf');
    expect(accessTokenExpiresAt).toBe(now + 900);
  });

  it('gives every token a different id', async () => {
    const env = unboundEnv();
    const ids = new Set<unknown>();
    for (let index = 0; index < 5; index++) ids.add(decodeJwt(await issueUnbound(env)).jti);
    expect(ids.size).toBe(5);
  });

  it('stamps the device key thumbprint into tokens of a bound session', async () => {
    const env = createTokenEnv();
    const key = await createDpopKey();
    const session = sampleSession(env.clock, { dpopJkt: key.jkt });
    const { accessToken } = await env.tokens.issue(sampleUser(), session);
    expect(decodeJwt(accessToken).cnf).toEqual({ jkt: key.jkt });
  });

  it('adds custom claims and refuses to let them replace standard ones', async () => {
    const env = unboundEnv({ tokens: { claims: (user: { id: string }) => ({ tenant: `tenant-of-${user.id}` }) } });
    const token = await issueUnbound(env);
    expect(decodeJwt(token).tenant).toBe('tenant-of-user-1');
    expect((await env.tokens.verify(token)).claims.tenant).toBe('tenant-of-user-1');

    for (const reserved of ['sub', 'roles', 'exp', 'cnf', 'sid']) {
      const bad = unboundEnv({ tokens: { claims: () => ({ [reserved]: 'forged' }) } });
      await expectAuthError(issueUnbound(bad), 'CONFIGURATION_INVALID');
    }
  });

  it('signs with ES256 when configured', async () => {
    const env = unboundEnv({ tokens: { algorithm: 'ES256' } });
    const token = await issueUnbound(env);
    expect(decodeProtectedHeader(token).alg).toBe('ES256');
    expect((await env.tokens.verify(token)).subject.id).toBe('user-1');
  });

  it('signs with the fully specified Ed25519 name when configured', async () => {
    const env = unboundEnv({ tokens: { algorithm: 'Ed25519' } });
    const token = await issueUnbound(env);
    expect(decodeProtectedHeader(token).alg).toBe('Ed25519');
    expect((await env.tokens.verify(token)).subject.id).toBe('user-1');
  });
});

describe('access token verification', () => {
  it('accepts a valid token and returns the subject and authentication context', async () => {
    const env = unboundEnv();
    const verified = await env.tokens.verify(await issueUnbound(env));
    expect(verified.subject).toEqual({ id: 'user-1', roles: ['editor'] });
    expect(verified.context).toEqual({
      sessionId: 'session-1',
      methods: ['pwd'],
      assurance: 'aal1',
      authenticatedAt: Math.floor(env.clock() / 1000),
      deviceBound: false,
    });
  });

  it('rejects an expired token', async () => {
    const env = unboundEnv();
    const token = await issueUnbound(env);

    env.clock.advanceSec(899);
    await env.tokens.verify(token);

    // 5 seconds of clock tolerance are allowed past the expiry.
    env.clock.advanceSec(5);
    await env.tokens.verify(token);

    env.clock.advanceSec(2);
    const error = await expectAuthError(env.tokens.verify(token), 'TOKEN_EXPIRED');
    expect(error.status).toBe(401);
  });

  it('rejects a token that is not valid yet', async () => {
    const env = unboundEnv();
    const future = Math.floor(env.clock() / 1000) + 3600;
    const token = await signWithActiveKey(env, { nbf: future });
    await expectAuthError(env.tokens.verify(token), 'TOKEN_CLAIMS_INVALID');
  });

  it('rejects a token signed with an algorithm that is not on the allowlist', async () => {
    const env = unboundEnv();
    const kid = (await env.keys.signingKey()).kid;
    const { privateKey } = await generateKeyPair('ES256');
    const now = Math.floor(env.clock() / 1000);
    const token = await new SignJWT({ sid: 's', roles: [], amr: ['pwd'], acr: 'aal1', auth_time: now })
      .setProtectedHeader({ alg: 'ES256', kid, typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('user-1')
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .setJti('x')
      .sign(privateKey);
    await expectAuthError(env.tokens.verify(token), 'TOKEN_ALGORITHM_NOT_ALLOWED');
  });

  it('rejects an unsigned token (alg: none)', async () => {
    const env = unboundEnv();
    const claims = decodeJwt(await issueUnbound(env));
    const kid = (await env.keys.signingKey()).kid;
    for (const alg of ['none', 'None', 'NONE']) {
      const forged = `${encodeSegment({ alg, kid, typ: 'at+jwt' })}.${encodeSegment({ ...claims, roles: ['admin'] })}.`;
      await expectAuthError(env.tokens.verify(forged), 'TOKEN_ALGORITHM_NOT_ALLOWED');
    }
  });

  it('rejects an HMAC token signed with the public key as the secret', async () => {
    const env = unboundEnv();
    const claims = decodeJwt(await issueUnbound(env));
    const { kid } = await env.keys.signingKey();
    const [publicJwk] = (await env.keys.jwks()).keys;
    const publicKey = await importJWK(publicJwk as JWK, 'EdDSA', { extractable: true });
    const secrets = [
      new TextEncoder().encode(await exportSPKI(publicKey as CryptoKey)),
      new TextEncoder().encode(JSON.stringify(publicJwk)),
      Buffer.from(String(publicJwk!.x), 'base64url'),
    ];
    for (const secret of secrets) {
      const forged = await new SignJWT({ ...claims, roles: ['admin'] })
        .setProtectedHeader({ alg: 'HS256', kid, typ: 'at+jwt' })
        .sign(secret);
      await expectAuthError(env.tokens.verify(forged), 'TOKEN_ALGORITHM_NOT_ALLOWED');
    }
  });

  it('rejects a token whose payload was changed after signing', async () => {
    const env = unboundEnv();
    const token = await issueUnbound(env);
    const [header, , signature] = token.split('.');
    const forgedPayload = encodeSegment({ ...decodeJwt(token), roles: ['admin'] });
    await expectAuthError(env.tokens.verify(`${header}.${forgedPayload}.${signature}`), 'TOKEN_SIGNATURE_INVALID');
  });

  it('rejects a token whose signature was changed', async () => {
    const env = unboundEnv();
    const token = await issueUnbound(env);
    const flipped = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');
    await expectAuthError(env.tokens.verify(flipped), 'TOKEN_SIGNATURE_INVALID');
  });

  it('rejects the wrong issuer, audience and token type', async () => {
    const env = unboundEnv();
    await expectAuthError(env.tokens.verify(await signWithActiveKey(env, { iss: 'https://evil.example' })), 'TOKEN_CLAIMS_INVALID');
    await expectAuthError(env.tokens.verify(await signWithActiveKey(env, { aud: 'https://other.example' })), 'TOKEN_CLAIMS_INVALID');
    await expectAuthError(env.tokens.verify(await signWithActiveKey(env, {}, { typ: 'JWT' })), 'TOKEN_CLAIMS_INVALID');
    await expectAuthError(env.tokens.verify(await signWithActiveKey(env, {}, { typ: 'dpop+jwt' })), 'TOKEN_CLAIMS_INVALID');
  });

  it('accepts any one of several configured audiences', async () => {
    const env = unboundEnv({ audience: ['https://api.example.com', 'https://files.example.com'] });
    const token = await issueUnbound(env);
    expect(decodeJwt(token).aud).toEqual(['https://api.example.com', 'https://files.example.com']);
    await env.tokens.verify(token);
  });

  it('rejects a token with missing or mistyped claims', async () => {
    const env = unboundEnv();
    const cases: Record<string, unknown>[] = [
      { sid: undefined },
      { jti: undefined },
      { sub: undefined },
      { roles: 'admin' },
      { roles: [1, 2] },
      { amr: 'pwd' },
      { acr: 'aal3' },
      { auth_time: 'yesterday' },
      { cnf: 'thumbprint' },
      { cnf: {} },
    ];
    for (const claims of cases) {
      await expectAuthError(env.tokens.verify(await signWithActiveKey(env, claims)), 'TOKEN_CLAIMS_INVALID');
    }
  });

  it('rejects a token signed by an unknown key', async () => {
    const env = unboundEnv();
    const other = unboundEnv();
    const foreign = await issueUnbound(other);
    await expectAuthError(env.tokens.verify(foreign), 'TOKEN_KEY_UNKNOWN');
  });

  it('rejects a token that claims a known key id but was signed by another key', async () => {
    const env = unboundEnv();
    const kid = (await env.keys.signingKey()).kid;
    const { privateKey } = await generateKeyPair('EdDSA');
    const now = Math.floor(env.clock() / 1000);
    const forged = await new SignJWT({ sid: 's', roles: ['admin'], amr: ['pwd'], acr: 'aal1', auth_time: now })
      .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('user-1')
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .setJti('x')
      .sign(privateKey);
    await expectAuthError(env.tokens.verify(forged), 'TOKEN_SIGNATURE_INVALID');
  });

  it('rejects a token without a key id', async () => {
    const env = unboundEnv();
    const { privateKey } = await env.keys.signingKey();
    const now = Math.floor(env.clock() / 1000);
    const token = await new SignJWT({ sid: 's', roles: [], amr: ['pwd'], acr: 'aal1', auth_time: now })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('user-1')
      .setIssuedAt(now)
      .setExpirationTime(now + 900)
      .setJti('x')
      .sign(privateKey);
    await expectAuthError(env.tokens.verify(token), 'TOKEN_KEY_UNKNOWN');
  });

  it('uses a key only with the algorithm it was created for', async () => {
    // Both names are allowed here, but the key was created as EdDSA, so a header saying Ed25519 is refused.
    const env = unboundEnv({ tokens: { algorithm: 'EdDSA', allowedAlgorithms: ['EdDSA', 'Ed25519'] } });
    const token = await signWithActiveKey(env, {}, { alg: 'Ed25519' });
    expect(decodeProtectedHeader(token).alg).toBe('Ed25519');
    await expectAuthError(env.tokens.verify(token), 'TOKEN_ALGORITHM_NOT_ALLOWED');
  });

  it('rejects missing and malformed input', async () => {
    const env = unboundEnv();
    await expectAuthError(env.tokens.verify(''), 'TOKEN_MISSING');
    await expectAuthError(env.tokens.verify(undefined as unknown as string), 'TOKEN_MISSING');
    await expectAuthError(env.tokens.verify('not-a-jwt'), 'TOKEN_MALFORMED');
    await expectAuthError(env.tokens.verify('a.b'), 'TOKEN_MALFORMED');
    await expectAuthError(env.tokens.verify('a.b.c.d.e'), 'TOKEN_MALFORMED');
    await expectAuthError(env.tokens.verify('!!!.###.$$$'), 'TOKEN_MALFORMED');
    await expectAuthError(env.tokens.verify(`${'a'.repeat(20_000)}.b.c`), 'TOKEN_MALFORMED');
  });

  it('logs anomalous rejections but not routine expiry', async () => {
    const env = unboundEnv();
    const token = await issueUnbound(env);
    env.sink.clear();

    env.clock.advanceSec(1000);
    await expectAuthError(env.tokens.verify(token), 'TOKEN_EXPIRED');
    expect(env.sink.ofType('token.rejected')).toHaveLength(0);

    const forged = `${encodeSegment({ alg: 'none', typ: 'at+jwt' })}.${encodeSegment({})}.`;
    await expectAuthError(env.tokens.verify(forged, { ip: '203.0.113.9' }), 'TOKEN_ALGORITHM_NOT_ALLOWED');
    const [event] = env.sink.ofType('token.rejected');
    expect(event).toMatchObject({ outcome: 'failure', reason: 'TOKEN_ALGORITHM_NOT_ALLOWED', ip: '203.0.113.9' });
  });
});

describe('device-bound tokens', () => {
  async function boundToken(env: ReturnType<typeof createTokenEnv>) {
    const key = await createDpopKey();
    const session = sampleSession(env.clock, { dpopJkt: key.jkt });
    const { accessToken } = await env.tokens.issue(sampleUser(), session);
    return { key, accessToken };
  }

  it('accepts a bound token with a proof from the bound key', async () => {
    const env = createTokenEnv();
    const { key, accessToken } = await boundToken(env);
    const proof = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    const verified = await env.tokens.verify(accessToken, { dpop: { proof, method: 'GET', url: API_URL } });
    expect(verified.context.deviceBound).toBe(true);
  });

  it('rejects a bound token presented without a proof', async () => {
    const env = createTokenEnv();
    const { accessToken } = await boundToken(env);
    await expectAuthError(env.tokens.verify(accessToken), 'DPOP_PROOF_REQUIRED');
    await expectAuthError(env.tokens.verify(accessToken, {}), 'DPOP_PROOF_REQUIRED');
  });

  it('rejects a stolen bound token used with the thief’s own key', async () => {
    const env = createTokenEnv();
    const { accessToken } = await boundToken(env);
    const thief = await createDpopKey();
    const proof = await createDpopProof(thief, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    await expectAuthError(env.tokens.verify(accessToken, { dpop: { proof, method: 'GET', url: API_URL } }), 'DPOP_KEY_MISMATCH');
    expect(env.sink.ofType('dpop.rejected')[0]).toMatchObject({
      reason: 'DPOP_KEY_MISMATCH',
      userId: 'user-1',
      sessionId: 'session-1',
      data: { during: 'request' },
    });
  });

  it('rejects a proof that does not carry the hash of this token', async () => {
    const env = createTokenEnv();
    const { key, accessToken } = await boundToken(env);
    const withoutHash = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock() });
    await expectAuthError(
      env.tokens.verify(accessToken, { dpop: { proof: withoutHash, method: 'GET', url: API_URL } }),
      'DPOP_PROOF_INVALID',
    );
    const otherToken = (await env.tokens.issue(sampleUser(), sampleSession(env.clock, { dpopJkt: key.jkt }))).accessToken;
    const forOther = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken: otherToken });
    await expectAuthError(
      env.tokens.verify(accessToken, { dpop: { proof: forOther, method: 'GET', url: API_URL } }),
      'DPOP_PROOF_INVALID',
    );
  });

  it('rejects a replayed proof even with a valid token', async () => {
    const env = createTokenEnv();
    const { key, accessToken } = await boundToken(env);
    const proof = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    const ctx = { dpop: { proof, method: 'GET', url: API_URL } };
    await env.tokens.verify(accessToken, ctx);
    await expectAuthError(env.tokens.verify(accessToken, ctx), 'DPOP_PROOF_REPLAYED');
  });

  it('rejects an unbound token when device binding is required', async () => {
    const env = createTokenEnv();
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    await expectAuthError(env.tokens.verify(accessToken), 'DPOP_PROOF_REQUIRED');
  });

  it('accepts an unbound token when device binding is optional', async () => {
    const env = createTokenEnv({ dpop: { mode: 'optional' } });
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    expect((await env.tokens.verify(accessToken)).context.deviceBound).toBe(false);
  });
});

describe('session check', () => {
  async function tokenForStoredSession(env: ReturnType<typeof createTokenEnv>) {
    const session = sampleSession(env.clock);
    await env.adapter.sessions.create(session, {
      id: 'rt-1',
      tokenHash: 'hash-1',
      createdAt: new Date(env.clock()),
      expiresAt: new Date(env.clock() + 1000),
    });
    return (await env.tokens.issue(sampleUser(), session)).accessToken;
  }

  it('accepts a revoked session’s token by default and rejects it when asked to check', async () => {
    const env = unboundEnv();
    const token = await tokenForStoredSession(env);
    await env.tokens.verify(token, {}, { checkSession: true });

    await env.adapter.sessions.revoke('session-1', 'logout', new Date(env.clock()));
    await env.tokens.verify(token);
    await expectAuthError(env.tokens.verify(token, {}, { checkSession: true }), 'SESSION_REVOKED');
  });

  it('rejects a token whose session is unknown when asked to check', async () => {
    const env = unboundEnv();
    const token = await issueUnbound(env);
    await expectAuthError(env.tokens.verify(token, {}, { checkSession: true }), 'SESSION_REVOKED');
  });
});
