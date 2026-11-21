import type { MfaMethod } from '@acme/auth-core';
import { memoryAdapter, type MemoryAdapter } from '../src/adapters/memory.js';
import { memorySink } from '../src/audit/sinks.js';
import { createAuth, type Auth } from '../src/auth.js';
import type { AuthConfig } from '../src/config.js';
import type { RequestContext } from '../src/context.js';
import { hotp, totpStep } from '../src/mfa/totp.js';
import { argon2id } from '../src/password/argon2.js';
import type { Authenticated } from '../src/sessions/session-service.js';
import { createFakeClock, type FakeClock } from '../src/testing/clock.js';
import { fromBase32 } from '../src/util/encoding.js';
import { AUDIENCE, ISSUER, createDpopKey, createDpopProof, randomDataKey, type DpopTestKey } from './helpers.js';

export const API_ORIGIN = 'https://api.example.com';
export const APP_ORIGIN = 'https://app.example.com';
export const PASSWORD = 'correct horse battery staple';

/** Real Argon2id with tiny parameters, so the full code path runs without slowing the suite down. */
export const fastHasher = argon2id({ memoryKiB: 64, iterations: 1, unsafeAllowWeakParameters: true });

export interface AuthEnv {
  clock: FakeClock;
  adapter: MemoryAdapter;
  sink: ReturnType<typeof memorySink>;
  auth: Auth;
  dataKey: string;
}

/** A complete server with an in-memory adapter and a clock that only moves when told to. */
export function createAuthEnv(
  overrides: Partial<AuthConfig> = {},
  shared: { clock?: FakeClock; adapter?: MemoryAdapter; dataKey?: string } = {},
): AuthEnv {
  const clock = shared.clock ?? createFakeClock();
  const adapter = shared.adapter ?? memoryAdapter({ clock });
  const sink = memorySink();
  const dataKey = shared.dataKey ?? randomDataKey();
  const auth = createAuth({
    issuer: ISSUER,
    audience: AUDIENCE,
    adapter,
    dataKeys: [{ id: 'k1', key: dataKey }],
    clock,
    password: { hasher: fastHasher },
    passkeys: { rpId: 'example.com', rpName: 'Example', origins: [APP_ORIGIN] },
    audit: { sinks: [sink] },
    ...overrides,
  });
  return { clock, adapter, sink, auth, dataKey };
}

/** One browser: a DPoP key, an IP address and a user agent. */
export interface Device {
  key: DpopTestKey;
  ip: string;
  /** A request context carrying a fresh proof for `method` and `path`. */
  ctx(method: string, path: string, accessToken?: string): Promise<RequestContext>;
  /** The same context without a proof, as a client without the key would send. */
  bare(): RequestContext;
}

export async function createDevice(
  clock: FakeClock,
  options: { ip?: string; userAgent?: string } = {},
): Promise<Device> {
  const key = await createDpopKey();
  const ip = options.ip ?? '203.0.113.10';
  const userAgent = options.userAgent ?? 'vitest-device';
  return {
    key,
    ip,
    bare: () => ({ ip, userAgent }),
    async ctx(method, path, accessToken) {
      const url = `${API_ORIGIN}${path}`;
      const proof = await createDpopProof(key, {
        method,
        url,
        nowMs: clock(),
        ...(accessToken !== undefined ? { accessToken } : {}),
      });
      return { ip, userAgent, dpop: { proof, method, url } };
    },
  };
}

export async function createUser(env: AuthEnv, identifier = 'ada@example.com', roles: string[] = ['editor']) {
  return env.auth.users.create({ identifier, password: PASSWORD, roles });
}

/** Password login that must complete without a second factor. */
export async function loginWithPassword(
  env: AuthEnv,
  device: Device,
  identifier = 'ada@example.com',
  password = PASSWORD,
): Promise<Authenticated> {
  const result = await env.auth.login.withPassword({ identifier, password }, await device.ctx('POST', '/auth/login/password'));
  if (result.status !== 'authenticated') throw new Error(`Expected a completed login, got ${result.status}`);
  return result;
}

/** The TOTP code an authenticator app would show for a base32 secret at the fake clock's time. */
export async function totpCode(clock: FakeClock, base32Secret: string, stepOffset = 0): Promise<string> {
  const step = totpStep(Math.floor(clock() / 1000), 30) + stepOffset;
  return hotp(fromBase32(base32Secret), step, 6, 'SHA-1');
}

/** Enrols TOTP for a user and returns the secret and recovery codes. */
export async function enrollTotp(env: AuthEnv, userId: string): Promise<{ secret: string; recoveryCodes: string[] }> {
  const enrollment = await env.auth.mfa.beginTotpEnrollment(userId);
  const { recoveryCodes } = await env.auth.mfa.confirmTotpEnrollment(userId, {
    enrollmentId: enrollment.enrollmentId,
    code: await totpCode(env.clock, enrollment.secret),
  });
  return { secret: enrollment.secret, recoveryCodes };
}

/** Password login followed by a second factor. */
export async function loginWithMfa(
  env: AuthEnv,
  device: Device,
  code: string,
  method: MfaMethod = 'totp',
  identifier = 'ada@example.com',
): Promise<Authenticated> {
  const first = await env.auth.login.withPassword(
    { identifier, password: PASSWORD },
    await device.ctx('POST', '/auth/login/password'),
  );
  if (first.status !== 'mfa_required') throw new Error(`Expected mfa_required, got ${first.status}`);
  return env.auth.mfa.verify({ ticket: first.ticket, method, code }, await device.ctx('POST', '/auth/mfa/verify'));
}
