import { ConfigurationError, isAuthError } from '@acme/auth-core';
import { describe, expect, it } from 'vitest';
import { memoryAdapter } from '../src/adapters/memory.js';
import { createAuth } from '../src/auth.js';
import { resolveConfig, type AuthConfig } from '../src/config.js';
import { AUDIENCE, ISSUER, randomDataKey, stubHasher } from './helpers.js';

function base(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    adapter: memoryAdapter(),
    dataKeys: [{ id: 'k1', key: randomDataKey() }],
    password: { hasher: stubHasher },
    ...overrides,
  };
}

function expectInvalid(overrides: Partial<AuthConfig>, message: RegExp) {
  try {
    createAuth(base(overrides));
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigurationError);
    expect(isAuthError(error) && error.code).toBe('CONFIGURATION_INVALID');
    expect((error as Error).message).toMatch(message);
    return;
  }
  throw new Error(`Expected the configuration to be rejected with ${message}`);
}

describe('configuration defaults', () => {
  it('match the documented values', () => {
    const config = resolveConfig(base());
    expect(config.tokens).toMatchObject({ algorithm: 'EdDSA', allowedAlgorithms: ['EdDSA'], accessTtlSec: 900, clockToleranceSec: 5 });
    expect(config.keys).toEqual({ rotateEveryDays: 90, jwksMaxAgeSec: 600, publishLeadSec: 600, cacheTtlSec: 30 });
    expect(config.sessions).toEqual({
      ttlSec: 30 * 86_400,
      idleTtlSec: 7 * 86_400,
      recentAuthSec: 600,
      cookie: { name: '__Host-rt', sameSite: 'strict', path: '/', domain: undefined },
    });
    expect(config.password).toMatchObject({ minLength: 12, maxLength: 256 });
    expect(config.mfa).toEqual({
      totp: { issuer: 'api.example.com', digits: 6, period: 30, window: 1, algorithm: 'SHA-1' },
      recoveryCodes: { count: 10 },
      rateLimit: { maxFailures: 5, windowSec: 900 },
      ticketTtlSec: 300,
      ticketMaxAttempts: 5,
      enrollmentTtlSec: 600,
    });
    expect(config.dpop).toEqual({ mode: 'required', algorithms: ['ES256'], iatToleranceSec: 60 });
    expect(config.risk).toMatchObject({ stepUpAt: 40, denyAt: 90, whenStepUpUnavailable: 'deny' });
    expect(config.risk.signals).toHaveLength(3);
    expect(config.rateLimits.login).toEqual({ freeAttempts: 5, windowSec: 900, baseDelaySec: 30, maxDelaySec: 900 });
    expect(config.audit.failClosed).toBe(false);
    expect(config.audit.sinks).toHaveLength(1);
    expect(config.passkeys).toBeNull();
    expect(config.audience).toEqual([AUDIENCE]);
  });

  it('normalises identifiers by trimming and lower-casing unless told otherwise', () => {
    expect(resolveConfig(base()).normalizeIdentifier('  Ada@Example.COM ')).toBe('ada@example.com');
    const custom = resolveConfig(base({ normalizeIdentifier: (value) => value.trim() }));
    expect(custom.normalizeIdentifier(' Ada ')).toBe('Ada');
  });

  it('derives the publication lead time from the JWKS cache lifetime', () => {
    expect(resolveConfig(base({ keys: { jwksMaxAgeSec: 120 } })).keys.publishLeadSec).toBe(120);
    expect(resolveConfig(base({ keys: { jwksMaxAgeSec: 120, publishLeadSec: 900 } })).keys.publishLeadSec).toBe(900);
  });

  it('caps the idle limit at the session lifetime', () => {
    expect(resolveConfig(base({ sessions: { ttlSec: 3600 } })).sessions.idleTtlSec).toBe(3600);
  });
});

describe('configuration validation', () => {
  it('requires the essentials', () => {
    expectInvalid({ issuer: '' }, /issuer/);
    expectInvalid({ audience: [] }, /audience/);
    expectInvalid({ audience: [''] }, /audience\[0\]/);
    expectInvalid({ dataKeys: [] }, /dataKeys/);
    expectInvalid({ adapter: { ...memoryAdapter(), sessions: undefined } as never }, /adapter\.sessions/);
    expect(() => createAuth(null as never)).toThrow(ConfigurationError);
  });

  it('requires a way to sign in', () => {
    expectInvalid({ password: undefined }, /at least one of password and passkeys/);
    expect(() =>
      createAuth(base({ password: undefined, passkeys: { rpId: 'example.com', rpName: 'Example', origins: ['https://app.example.com'] } })),
    ).not.toThrow();
  });

  it('checks data keys', () => {
    expectInvalid({ dataKeys: [{ id: 'k1', key: 'dG9vLXNob3J0' }] }, /must be 32 bytes/);
    expectInvalid({ dataKeys: [{ id: '', key: randomDataKey() }] }, /non-empty id/);
    expectInvalid({ dataKeys: [{ id: 'k1', key: 'not base64 !!!' }] }, /not base64/);
    expectInvalid(
      {
        dataKeys: [
          { id: 'k1', key: randomDataKey() },
          { id: 'k1', key: randomDataKey() },
        ],
      },
      /used twice/,
    );
    expect(() => createAuth(base({ dataKeys: [{ id: 'raw', key: crypto.getRandomValues(new Uint8Array(32)) }] }))).not.toThrow();
    // Standard base64 with padding is accepted as well as base64url.
    expect(() => createAuth(base({ dataKeys: [{ id: 'std', key: Buffer.alloc(32, 7).toString('base64') }] }))).not.toThrow();
  });

  it('checks token settings', () => {
    expectInvalid({ tokens: { algorithm: 'HS256' as never } }, /tokens\.algorithm must be one of/);
    expectInvalid({ tokens: { algorithm: 'none' as never } }, /tokens\.algorithm/);
    expectInvalid({ tokens: { allowedAlgorithms: ['EdDSA', 'RS256' as never] } }, /allowedAlgorithms may only contain/);
    expectInvalid({ tokens: { algorithm: 'ES256', allowedAlgorithms: ['EdDSA'] } }, /must include tokens\.algorithm/);
    expectInvalid({ tokens: { accessTtlSec: 10 } }, /accessTtlSec must be a whole number between 30 and 3600/);
    expectInvalid({ tokens: { accessTtlSec: 86_400 } }, /accessTtlSec/);
    expectInvalid({ tokens: { accessTtlSec: 900.5 } }, /whole number/);
    expectInvalid({ tokens: { clockToleranceSec: -1 } }, /clockToleranceSec/);
  });

  it('checks session and cookie settings', () => {
    expectInvalid({ sessions: { ttlSec: 30 } }, /sessions\.ttlSec/);
    expectInvalid({ sessions: { idleTtlSec: 60 * 86_400 } }, /sessions\.idleTtlSec/);
    expectInvalid({ sessions: { ttlSec: 900, idleTtlSec: 900 } }, /longer than tokens\.accessTtlSec/);
    expectInvalid({ sessions: { cookie: { sameSite: 'none' as never } } }, /sameSite must be one of: strict, lax/);
    expectInvalid({ sessions: { cookie: { name: 'bad name' } } }, /valid cookie name/);
    expectInvalid({ sessions: { cookie: { name: 'bad;name' } } }, /valid cookie name/);
    expectInvalid({ sessions: { cookie: { path: 'auth' } } }, /must start with/);
    expectInvalid({ sessions: { cookie: { path: '/auth' } } }, /"__Host-" cookie needs path "\/"/);
    expectInvalid({ sessions: { cookie: { domain: 'example.com' } } }, /"__Host-" cookie needs/);
    expectInvalid({ sessions: { cookie: { name: '__Secure-rt', domain: 'exa mple.com' } } }, /valid domain/);
    expect(() => createAuth(base({ sessions: { cookie: { name: '__Secure-rt', path: '/auth', domain: 'example.com' } } }))).not.toThrow();
  });

  it('checks the password settings', () => {
    expectInvalid({ password: { hasher: {} as never } }, /hasher must implement/);
    expectInvalid({ password: { hasher: stubHasher, minLength: 4 } }, /minLength/);
    expectInvalid({ password: { hasher: stubHasher, minLength: 20, maxLength: 10 } }, /maxLength/);
  });

  it('checks the passkey settings', () => {
    const passkeys = { rpId: 'example.com', rpName: 'Example', origins: ['https://app.example.com'] };
    expectInvalid({ passkeys: { ...passkeys, origins: [] } }, /at least one origin/);
    expectInvalid({ passkeys: { ...passkeys, origins: ['app.example.com'] } }, /not a URL/);
    expectInvalid({ passkeys: { ...passkeys, origins: ['https://app.example.com/'] } }, /bare origin/);
    expectInvalid({ passkeys: { ...passkeys, origins: ['http://app.example.com'] } }, /needs https/);
    expectInvalid({ passkeys: { ...passkeys, rpId: '' } }, /rpId/);
    expectInvalid({ passkeys: { ...passkeys, userVerification: 'discouraged' as never } }, /userVerification/);
    // Without identifier hints, a credential that is not discoverable could never be used to sign in.
    expectInvalid({ passkeys: { ...passkeys, residentKey: 'preferred' } }, /residentKey must be "required" unless/);
    expect(() => createAuth(base({ passkeys: { ...passkeys, residentKey: 'discouraged', identifierHints: true } }))).not.toThrow();
    expect(resolveConfig(base({ passkeys })).passkeys).toMatchObject({ identifierHints: false, residentKey: 'required', userVerification: 'required' });
    expect(() => createAuth(base({ passkeys: { ...passkeys, origins: ['http://localhost:5173'] } }))).not.toThrow();
  });

  it('checks MFA, DPoP, risk and rate-limit settings', () => {
    expectInvalid({ mfa: { totp: { digits: 7 as never } } }, /digits must be 6 or 8/);
    expectInvalid({ mfa: { totp: { window: 20 } } }, /window/);
    expectInvalid({ mfa: { totp: { algorithm: 'MD5' as never } } }, /algorithm/);
    expectInvalid({ mfa: { recoveryCodes: { count: 0 } } }, /count/);
    expectInvalid({ dpop: { mode: 'sometimes' as never } }, /dpop\.mode/);
    expectInvalid({ dpop: { algorithms: [] } }, /must not be empty/);
    expectInvalid({ dpop: { algorithms: ['HS256' as never] } }, /dpop\.algorithms may only contain/);
    expectInvalid({ dpop: { iatToleranceSec: 0 } }, /iatToleranceSec/);
    expectInvalid({ risk: { stepUpAt: 80, denyAt: 50 } }, /must not be greater/);
    expectInvalid({ risk: { stepUpAt: -1 } }, /zero or more/);
    expectInvalid({ risk: { signals: ['not a function' as never] } }, /must contain functions/);
    expectInvalid({ risk: { whenStepUpUnavailable: 'ignore' as never } }, /whenStepUpUnavailable/);
    expectInvalid({ rateLimits: { login: { freeAttempts: 0 } } }, /freeAttempts/);
    expectInvalid({ rateLimits: { login: { baseDelaySec: 100, maxDelaySec: 50 } } }, /maxDelaySec/);
    expectInvalid({ audit: { sinks: [{} as never] } }, /write method/);
    expectInvalid({ keys: { rotateEveryDays: -5 } }, /rotateEveryDays/);
  });

  it('never accepts a symmetric or unsigned token algorithm, whatever is passed', () => {
    for (const algorithm of ['HS256', 'HS384', 'HS512', 'none', 'RS256', 'PS256', '']) {
      expectInvalid({ tokens: { algorithm: algorithm as never } }, /tokens\.algorithm/);
      expectInvalid({ tokens: { allowedAlgorithms: ['EdDSA', algorithm as never] } }, /allowedAlgorithms/);
    }
  });
});
