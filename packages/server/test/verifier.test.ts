import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import { createAccessTokenVerifier } from '../src/verifier/index.js';
import {
  AUDIENCE,
  ISSUER,
  createDpopKey,
  createDpopProof,
  createTokenEnv,
  expectAuthError,
  sampleSession,
  sampleUser,
} from './helpers.js';

const API_URL = 'https://files.example.com/files/7';
const servers: Server[] = [];

afterAll(() => {
  for (const server of servers) server.close();
});

async function issuer(config = {}) {
  const env = createTokenEnv(config);
  await env.keys.signingKey();
  return env;
}

describe('createAccessTokenVerifier', () => {
  it('verifies a bound token against a JWKS, with the proof', async () => {
    const env = await issuer();
    const key = await createDpopKey();
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock, { dpopJkt: key.jkt }));
    const verify = createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: await env.keys.jwks(), now: env.clock });

    const dpopProof = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    const verified = await verify(accessToken, { method: 'GET', url: API_URL, dpopProof });
    expect(verified.subject).toEqual({ id: 'user-1', roles: ['editor'] });
    expect(verified.context.deviceBound).toBe(true);
    expect(verified.claims.cnf).toEqual({ jkt: key.jkt });
  });

  it('rejects a bound token without a proof, with another key’s proof, and on replay', async () => {
    const env = await issuer();
    const key = await createDpopKey();
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock, { dpopJkt: key.jkt }));
    const verify = createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: await env.keys.jwks(), now: env.clock });

    await expectAuthError(verify(accessToken, { method: 'GET', url: API_URL }), 'DPOP_PROOF_REQUIRED');

    const thief = await createDpopKey();
    const stolen = await createDpopProof(thief, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    await expectAuthError(verify(accessToken, { method: 'GET', url: API_URL, dpopProof: stolen }), 'DPOP_KEY_MISMATCH');

    const dpopProof = await createDpopProof(key, { method: 'GET', url: API_URL, nowMs: env.clock(), accessToken });
    await verify(accessToken, { method: 'GET', url: API_URL, dpopProof });
    await expectAuthError(verify(accessToken, { method: 'GET', url: API_URL, dpopProof }), 'DPOP_PROOF_REPLAYED');
  });

  it('rejects unbound tokens by default and accepts them when binding is optional', async () => {
    const env = await issuer({ dpop: { mode: 'optional' } });
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    const jwks = await env.keys.jwks();

    const strict = createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks, now: env.clock });
    await expectAuthError(strict(accessToken), 'DPOP_PROOF_REQUIRED');

    const relaxed = createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks, now: env.clock, dpop: { mode: 'optional' } });
    expect((await relaxed(accessToken)).context.deviceBound).toBe(false);
  });

  it('applies the same JWT checks as the auth server', async () => {
    const env = await issuer({ dpop: { mode: 'off' } });
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    const jwks = await env.keys.jwks();
    const base = { jwks, now: env.clock, dpop: { mode: 'off' as const } };

    await createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, ...base })(accessToken);
    await expectAuthError(createAccessTokenVerifier({ issuer: 'https://other.example', audience: AUDIENCE, ...base })(accessToken), 'TOKEN_CLAIMS_INVALID');
    await expectAuthError(createAccessTokenVerifier({ issuer: ISSUER, audience: 'https://other.example', ...base })(accessToken), 'TOKEN_CLAIMS_INVALID');
    await expectAuthError(createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, algorithms: ['ES256'], ...base })(accessToken), 'TOKEN_ALGORITHM_NOT_ALLOWED');

    const other = await issuer({ dpop: { mode: 'off' } });
    const foreign = (await other.tokens.issue(sampleUser(), sampleSession(other.clock))).accessToken;
    await expectAuthError(createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, ...base })(foreign), 'TOKEN_KEY_UNKNOWN');

    env.clock.advanceSec(906);
    await expectAuthError(createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, ...base })(accessToken), 'TOKEN_EXPIRED');
  });

  it('fetches keys from a JWKS URL', async () => {
    const env = await issuer({ dpop: { mode: 'off' } });
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    const body = JSON.stringify(await env.keys.jwks());
    let requests = 0;
    const server = createServer((_request, response) => {
      requests++;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(body);
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    const verify = createAccessTokenVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: `http://127.0.0.1:${port}/.well-known/jwks.json`,
      now: env.clock,
      dpop: { mode: 'off' },
    });
    expect((await verify(accessToken)).subject.id).toBe('user-1');
    expect((await verify(accessToken)).subject.id).toBe('user-1');
    expect(requests).toBe(1);
  });

  it('accepts a custom key resolver', async () => {
    const env = await issuer({ dpop: { mode: 'off' } });
    const { accessToken } = await env.tokens.issue(sampleUser(), sampleSession(env.clock));
    const verify = createAccessTokenVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      now: env.clock,
      dpop: { mode: 'off' },
      getKey: async (header) => (await env.keys.verificationKey(String(header.kid)))!.publicKey,
    });
    expect((await verify(accessToken)).subject.id).toBe('user-1');
  });

  it('rejects an invalid configuration at creation time', () => {
    const jwks = { keys: [] };
    expect(() => createAccessTokenVerifier({ issuer: '', audience: AUDIENCE, jwks })).toThrow(/issuer/);
    expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: [], jwks })).toThrow(/audience/);
    expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE })).toThrow(/exactly one/);
    expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks, jwksUri: 'https://x.example/jwks' })).toThrow(/exactly one/);
    expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwksUri: 'not a url' })).toThrow(/jwksUri/);
    for (const algorithm of ['none', 'HS256', 'hs512']) {
      expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks, algorithms: [algorithm] })).toThrow(/asymmetric/);
    }
    expect(() => createAccessTokenVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks, algorithms: [] })).toThrow(/asymmetric/);
  });
});
