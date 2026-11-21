import type { AssuranceLevel, AuthMethod, MfaMethod, RevokeReason, RiskDecision } from './types.js';

/**
 * Fields every audit event has.
 *
 * No field can hold a credential. Values are ids, enum members, numbers and keyed hashes. `reason`
 * is an error code or a fixed enum value, never text taken from a request.
 */
export interface AuditEventBase {
  id: string;
  /** ISO 8601 timestamp. */
  at: string;
  outcome: 'success' | 'failure';
  userId?: string;
  sessionId?: string;
  ip?: string;
  /** Truncated to 256 characters. */
  userAgent?: string;
  reason?: string;
}

/** The payload of each event type. */
export interface AuditEventData {
  'login.succeeded': { method: 'pwd' | 'passkey'; riskScore: number; mfa: boolean };
  /**
   * `identifierHash` is a keyed hash of the submitted identifier. The identifier itself is not
   * recorded, because people type passwords into the username box.
   */
  'login.failed': { method: 'pwd' | 'passkey'; identifierHash?: string };
  'risk.evaluated': { score: number; decision: RiskDecision; signals: { name: string; score: number }[] };

  'mfa.challenged': { reason: 'enrolled' | 'risk'; methods: MfaMethod[] };
  'mfa.verified': { method: MfaMethod; purpose: 'login' | 'reauthentication' | 'enrolment' };
  'mfa.failed': { method: MfaMethod; purpose: 'login' | 'reauthentication' | 'enrolment' };
  'mfa.totp.enrolled': Record<string, never>;
  'mfa.totp.removed': Record<string, never>;
  'mfa.recovery_codes.generated': { count: number };
  'mfa.recovery_code.used': { remaining: number };

  'passkey.registered': { passkeyId: string; deviceType: 'singleDevice' | 'multiDevice'; backedUp: boolean };
  'passkey.removed': { passkeyId: string };

  'session.created': { methods: AuthMethod[]; assurance: AssuranceLevel; deviceBound: boolean };
  'session.refreshed': { refreshTokenId: string };
  'session.reauthenticated': { method: AuthMethod; assurance: AssuranceLevel };
  'session.revoked': { revokeReason: RevokeReason; count: number };
  'session.refresh_reuse_detected': { refreshTokenId: string };

  'token.rejected': Record<string, never>;
  'dpop.rejected': { during: 'login' | 'mfa' | 'refresh' | 'request' };

  'user.created': Record<string, never>;
  'user.disabled': Record<string, never>;
  'password.changed': { by: 'user' | 'admin' };

  'key.created': { kid: string; algorithm: string };
  'key.activated': { kid: string };
  'key.retired': { kid: string };

  'rate_limit.exceeded': { scope: 'login' | 'mfa' | 'password' };
  'access.denied': { action: string; policy: string; decisionReason: string };
}

export type AuditEventType = keyof AuditEventData;

export type AuditEventOf<T extends AuditEventType> = AuditEventBase & { type: T; data: AuditEventData[T] };

/** Every audit event, discriminated by `type`. */
export type AuditEvent = { [T in AuditEventType]: AuditEventOf<T> }[AuditEventType];

/** Every event type, for documentation and exhaustive tests. */
export const AUDIT_EVENT_TYPES = Object.freeze([
  'login.succeeded',
  'login.failed',
  'risk.evaluated',
  'mfa.challenged',
  'mfa.verified',
  'mfa.failed',
  'mfa.totp.enrolled',
  'mfa.totp.removed',
  'mfa.recovery_codes.generated',
  'mfa.recovery_code.used',
  'passkey.registered',
  'passkey.removed',
  'session.created',
  'session.refreshed',
  'session.reauthenticated',
  'session.revoked',
  'session.refresh_reuse_detected',
  'token.rejected',
  'dpop.rejected',
  'user.created',
  'user.disabled',
  'password.changed',
  'key.created',
  'key.activated',
  'key.retired',
  'rate_limit.exceeded',
  'access.denied',
] as const satisfies readonly AuditEventType[]);
