import { describe, expect, it } from 'vitest';
import {
  AUDIT_EVENT_TYPES,
  identityFromClaims,
  type AccessTokenClaims,
  type AuditEvent,
  type AuditEventType,
} from '../src/index.js';

const claims: AccessTokenClaims = {
  iss: 'https://api.example.com',
  aud: 'https://api.example.com',
  sub: 'user-1',
  iat: 100,
  exp: 1000,
  jti: 'j1',
  sid: 'session-1',
  roles: ['editor'],
  amr: ['pwd', 'otp'],
  acr: 'aal2',
  auth_time: 90,
  cnf: { jkt: 'thumbprint' },
};

describe('identityFromClaims', () => {
  it('builds the subject and authentication context from verified claims', () => {
    expect(identityFromClaims(claims)).toEqual({
      subject: { id: 'user-1', roles: ['editor'] },
      context: {
        sessionId: 'session-1',
        methods: ['pwd', 'otp'],
        assurance: 'aal2',
        authenticatedAt: 90,
        deviceBound: true,
      },
    });
  });

  it('reports an unbound token as not device bound', () => {
    const { cnf: _cnf, ...unbound } = claims;
    expect(identityFromClaims(unbound).context.deviceBound).toBe(false);
  });
});

describe('audit event types', () => {
  it('lists every event type exactly once', () => {
    expect(new Set(AUDIT_EVENT_TYPES).size).toBe(AUDIT_EVENT_TYPES.length);
    expect(AUDIT_EVENT_TYPES.length).toBe(27);
  });

  it('covers the whole AuditEvent union', () => {
    // Compile-time check: a type missing from the list makes this assignment fail.
    const exhaustive: Exclude<AuditEventType, (typeof AUDIT_EVENT_TYPES)[number]> extends never ? true : false = true;
    expect(exhaustive).toBe(true);
  });

  it('ties each event type to its own payload', () => {
    const event: AuditEvent = {
      id: 'e1',
      at: '2026-01-01T00:00:00.000Z',
      outcome: 'failure',
      type: 'login.failed',
      data: { method: 'pwd', identifierHash: 'abc' },
    };
    if (event.type === 'login.failed') {
      expect(event.data.method).toBe('pwd');
    }

    const mismatched: AuditEvent = {
      id: 'e2',
      at: '2026-01-01T00:00:00.000Z',
      outcome: 'success',
      type: 'key.created',
      // @ts-expect-error the payload of key.created has no `method`
      data: { method: 'pwd' },
    };
    expect(mismatched.type).toBe('key.created');
  });
});
