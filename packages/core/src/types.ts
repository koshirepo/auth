/** A value that survives JSON serialisation unchanged. */
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

/** Authentication methods recorded on a session and in the `amr` claim. */
export type AuthMethod = 'pwd' | 'otp' | 'recovery' | 'passkey';

/**
 * `aal1`: a single factor.
 * `aal2`: two factors, or one passkey with user verification.
 */
export type AssuranceLevel = 'aal1' | 'aal2';

/** Second factors a caller can submit against an MFA ticket. */
export type MfaMethod = 'totp' | 'recovery_code';

export type RevokeReason =
  | 'logout'
  | 'logout_all'
  | 'refresh_reuse'
  | 'password_changed'
  | 'user_disabled'
  | 'admin';

export type RiskDecision = 'allow' | 'step_up' | 'deny';

/** The party an access decision is made about. */
export interface Subject {
  id: string;
  roles: readonly string[];
  attributes?: Readonly<Record<string, unknown>>;
}

/** How the subject authenticated. Carried in the access token and passed to policies. */
export interface AuthContext {
  sessionId: string;
  methods: readonly AuthMethod[];
  assurance: AssuranceLevel;
  /** Epoch seconds of the last interactive authentication, including step-up. */
  authenticatedAt: number;
  /** True when the access token is bound to a DPoP key. */
  deviceBound: boolean;
}

/** Claims of an access token issued by the server package. */
export interface AccessTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  /** Session id. */
  sid: string;
  roles: string[];
  amr: AuthMethod[];
  acr: AssuranceLevel;
  auth_time: number;
  /** Present when the token is bound to a DPoP key. `jkt` is the key's RFC 7638 thumbprint. */
  cnf?: { jkt: string };
  [claim: string]: unknown;
}

/** Builds the subject and authentication context that policies receive from verified claims. */
export function identityFromClaims(claims: AccessTokenClaims): { subject: Subject; context: AuthContext } {
  return {
    subject: { id: claims.sub, roles: claims.roles },
    context: {
      sessionId: claims.sid,
      methods: claims.amr,
      assurance: claims.acr,
      authenticatedAt: claims.auth_time,
      deviceBound: claims.cnf?.jkt !== undefined,
    },
  };
}

/** The user fields that are safe to send to the browser. */
export interface PublicUser {
  id: string;
  identifier: string;
  roles: string[];
}

/** A session as shown to its owner. All times are epoch seconds. */
export interface SessionInfo {
  id: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  authenticatedAt: number;
  methods: AuthMethod[];
  assurance: AssuranceLevel;
  deviceBound: boolean;
  ip?: string;
  userAgent?: string;
  /** Set in session listings for the session that made the request. */
  current?: boolean;
}

/** A registered passkey as shown to its owner. All times are epoch seconds. */
export interface PasskeyInfo {
  id: string;
  name: string | null;
  createdAt: number;
  lastUsedAt: number | null;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  transports: string[];
}

/** Which second factors an account has. */
export interface AccountSecurity {
  totp: boolean;
  recoveryCodes: number;
  passkeys: number;
}
