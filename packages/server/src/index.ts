export { createAuth, type Auth, type ReauthFactor } from './auth.js';

export {
  resolveConfig,
  type AuditConfig,
  type AuthConfig,
  type CookieConfig,
  type DpopAlgorithm,
  type DpopConfig,
  type KeysConfig,
  type MfaConfig,
  type PasskeysConfig,
  type PasswordConfig,
  type RateLimitsConfig,
  type ResolvedConfig,
  type RiskConfig,
  type SessionsConfig,
  type TokensConfig,
} from './config.js';

export type { RequestContext } from './context.js';

// Results
export type { LoginResult } from './login/login-service.js';
export type { MfaRequired, TotpEnrollment } from './mfa/mfa-service.js';
export type { AccessGrant, Authenticated } from './sessions/session-service.js';
export type { VerifiedToken, VerifyOptions } from './tokens/token-service.js';
export type { PasskeyLoginOptions, PasskeyRegistrationOptions } from './passkeys/passkey-service.js';
export type { JwksDocument } from './keys/key-manager.js';

// Persistence
export type {
  AuditFilter,
  AuditStore,
  AuthAdapter,
  CredentialStore,
  DeviceRecord,
  DeviceSighting,
  DeviceStore,
  EphemeralStore,
  NewRefreshToken,
  PasskeyCredential,
  RefreshTokenRecord,
  Session,
  SessionStore,
  SigningAlgorithm,
  SigningKeyStatus,
  SigningKeyStore,
  StoredSigningKey,
  TotpCredential,
  User,
  UserStore,
} from './adapters/types.js';

// Audit
export { consoleSink, memorySink, storeSink, type AuditSink, type MemorySink } from './audit/sinks.js';

// Risk
export { failedAttempts, newDevice, newLocation, newNetwork } from './risk/signals.js';
export type { GeoLocation, GeoLocator, RiskAssessment, RiskInput, RiskSignal, RiskSignalResult } from './risk/types.js';

// Extension points
export type { PasswordHasher } from './password/hasher.js';
export type { ReplayStore } from './dpop/proof.js';
export type { DataKeyInput } from './util/protector.js';
