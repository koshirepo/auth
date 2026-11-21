import { isAuthError, type AuthError, type ErrorCode } from '@koshi-repo/auth-core';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type CryptoKey, type JWK } from 'jose';
import { expect } from 'vitest';
import { memoryAdapter } from '../src/adapters/memory.js';
import type { Session, User } from '../src/adapters/types.js';
import { AuditEmitter } from '../src/audit/emitter.js';
import { memorySink } from '../src/audit/sinks.js';
import { resolveConfig, type AuthConfig } from '../src/config.js';
import { KeyManager } from '../src/keys/key-manager.js';
import type { PasswordHasher } from '../src/password/hasher.js';
import { createFakeClock, type FakeClock } from '../src/testing/clock.js';
import { TokenService } from '../src/tokens/token-service.js';
import { createClock } from '../src/util/clock.js';
import { randomBytes, sha256Base64Url } from '../src/util/crypto.js';
import { toBase64Url } from '../src/util/encoding.js';
import { DataProtector } from '../src/util/protector.js';

export const ISSUER = 'https://api.example.com';
export const AUDIENCE = 'https://api.example.com';

/** A hasher that does no work, for tests that are not about password hashing. */
export const stubHasher: PasswordHasher = {
  hash: async (password) => `stub$${password}`,
  verify: async (hash, password) => hash === `stub$${password}`,
  needsRehash: () => false,
};

export function randomDataKey(): string {
  return toBase64Url(randomBytes(32));
}

/** Asserts that a promise rejects with a library error carrying `code`, and returns the error. */
export async function expectAuthError(promise: Promise<unknown>, code: ErrorCode): Promise<AuthError> {
  let result: unknown;
  try {
    result = await promise;
  } catch (error) {
    if (!isAuthError(error)) throw error;
    expect(error.code).toBe(code);
    return error;
  }
  throw new Error(`Expected ${code}, but the call succeeded with ${JSON.stringify(result)}`);
}

/** Keys, tokens and audit wired together without the rest of the library. */
export function createTokenEnv(overrides: Partial<AuthConfig> = {}, shared: { clock?: FakeClock; adapter?: ReturnType<typeof memoryAdapter>; dataKey?: string } = {}) {
  const clock = shared.clock ?? createFakeClock();
  const adapter = shared.adapter ?? memoryAdapter({ clock });
  const sink = memorySink();
  const dataKeys = [{ id: 'k1', key: shared.dataKey ?? randomDataKey() }];
  const config = resolveConfig({
    issuer: ISSUER,
    audience: AUDIENCE,
    adapter,
    dataKeys,
    password: { hasher: stubHasher },
    audit: { sinks: [sink] },
    ...overrides,
  });
  const time = createClock(clock);
  const protector = new DataProtector(dataKeys);
  const audit = new AuditEmitter({ sinks: config.audit.sinks, failClosed: false, onError: () => undefined, clock: time });
  const keys = new KeyManager({
    store: adapter.keys,
    protector,
    clock: time,
    audit,
    algorithm: config.tokens.algorithm,
    rotateEveryDays: config.keys.rotateEveryDays,
    publishLeadSec: config.keys.publishLeadSec,
    retireAfterSec: config.tokens.accessTtlSec + config.tokens.clockToleranceSec + config.keys.jwksMaxAgeSec,
    cacheTtlSec: config.keys.cacheTtlSec,
  });
  const tokens = new TokenService({
    config,
    clock: time,
    keys,
    audit,
    sessions: adapter.sessions,
    replayStore: adapter.ephemeral,
  });
  return { clock, adapter, sink, config, time, protector, audit, keys, tokens, dataKey: dataKeys[0]!.key };
}

export function sampleUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-1',
    identifier: 'ada@example.com',
    roles: ['editor'],
    status: 'active',
    attributes: {},
    createdAt: new Date(Date.UTC(2025, 0, 1)),
    ...overrides,
  };
}

export function sampleSession(clock: FakeClock, overrides: Partial<Session> = {}): Session {
  const now = new Date(clock());
  return {
    id: 'session-1',
    userId: 'user-1',
    createdAt: now,
    lastUsedAt: now,
    expiresAt: new Date(clock() + 30 * 86_400_000),
    authenticatedAt: now,
    methods: ['pwd'],
    assurance: 'aal1',
    dpopJkt: null,
    ip: null,
    userAgent: null,
    revokedAt: null,
    revokedReason: null,
    ...overrides,
  };
}

export interface DpopTestKey {
  alg: 'ES256' | 'EdDSA';
  privateKey: CryptoKey;
  publicJwk: JWK;
  jkt: string;
}

/** A browser-style DPoP key pair. */
export async function createDpopKey(alg: 'ES256' | 'EdDSA' = 'ES256'): Promise<DpopTestKey> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  return { alg, privateKey, publicJwk, jkt: await calculateJwkThumbprint(publicJwk) };
}

export interface ProofOptions {
  method: string;
  url: string;
  /** Epoch milliseconds, normally the fake clock's current value. */
  nowMs: number;
  accessToken?: string;
  jti?: string;
  iat?: number;
  typ?: string;
  /** Overrides the embedded key. */
  jwk?: Record<string, unknown>;
  /** Extra or replacement claims. A value of undefined removes the claim. */
  claims?: Record<string, unknown>;
}

/** Signs a DPoP proof the way the browser client does. */
export async function createDpopProof(key: DpopTestKey, options: ProofOptions): Promise<string> {
  const payload: Record<string, unknown> = {
    htm: options.method,
    htu: options.url,
    jti: options.jti ?? crypto.randomUUID(),
    iat: options.iat ?? Math.floor(options.nowMs / 1000),
  };
  if (options.accessToken !== undefined) payload.ath = await sha256Base64Url(options.accessToken);
  for (const [name, value] of Object.entries(options.claims ?? {})) {
    if (value === undefined) delete payload[name];
    else payload[name] = value;
  }
  return new SignJWT(payload)
    .setProtectedHeader({ alg: key.alg, typ: options.typ ?? 'dpop+jwt', jwk: (options.jwk ?? key.publicJwk) as JWK })
    .sign(key.privateKey);
}

/** Base64url of a JSON value, for hand-built tokens. */
export function encodeSegment(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}
