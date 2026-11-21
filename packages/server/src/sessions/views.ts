import type { AssuranceLevel, AuthMethod, PasskeyInfo, PublicUser, SessionInfo } from '@koshi-repo/auth-core';
import type { PasskeyCredential, Session, User } from '../adapters/types.js';
import { toEpochSec } from '../util/clock.js';

/** The user fields that may be sent to the browser. */
export function toPublicUser(user: User): PublicUser {
  return { id: user.id, identifier: user.identifier, roles: [...user.roles] };
}

export function toSessionInfo(session: Session, currentSessionId?: string): SessionInfo {
  const info: SessionInfo = {
    id: session.id,
    createdAt: toEpochSec(session.createdAt),
    lastUsedAt: toEpochSec(session.lastUsedAt),
    expiresAt: toEpochSec(session.expiresAt),
    authenticatedAt: toEpochSec(session.authenticatedAt),
    methods: [...session.methods],
    assurance: session.assurance,
    deviceBound: session.dpopJkt !== null,
  };
  if (session.ip !== null) info.ip = session.ip;
  if (session.userAgent !== null) info.userAgent = session.userAgent;
  if (currentSessionId !== undefined) info.current = session.id === currentSessionId;
  return info;
}

export function toPasskeyInfo(passkey: PasskeyCredential): PasskeyInfo {
  return {
    id: passkey.id,
    name: passkey.name,
    createdAt: toEpochSec(passkey.createdAt),
    lastUsedAt: passkey.lastUsedAt === null ? null : toEpochSec(passkey.lastUsedAt),
    deviceType: passkey.deviceType,
    backedUp: passkey.backedUp,
    transports: [...passkey.transports],
  };
}

const FACTOR_CLASS: Record<AuthMethod, 'knowledge' | 'one-time-code' | 'passkey'> = {
  pwd: 'knowledge',
  otp: 'one-time-code',
  recovery: 'one-time-code',
  passkey: 'passkey',
};

/**
 * `aal2` when two different kinds of factor were used, or a passkey was used with user
 * verification (the passkey proves possession, and the PIN or biometric is the second factor).
 * A session never drops back to `aal1`.
 */
export function assuranceFor(
  methods: readonly AuthMethod[],
  options: { passkeyUserVerified?: boolean; previous?: AssuranceLevel } = {},
): AssuranceLevel {
  if (options.previous === 'aal2' || options.passkeyUserVerified === true) return 'aal2';
  return new Set(methods.map((method) => FACTOR_CLASS[method])).size >= 2 ? 'aal2' : 'aal1';
}
