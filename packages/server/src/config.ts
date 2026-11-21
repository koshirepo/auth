import { ConfigurationError, type AuditEvent, type JsonValue, type Policy, type Rbac } from '@koshirepo/auth-core';
import type { AuthAdapter, Session, SigningAlgorithm, User } from './adapters/types.js';
import { storeSink, type AuditSink } from './audit/sinks.js';
import type { PasswordHasher } from './password/hasher.js';
import { failedAttempts, newDevice, newNetwork } from './risk/signals.js';
import type { RiskSignal } from './risk/types.js';
import type { DataKeyInput } from './util/protector.js';

export type DpopAlgorithm = 'ES256' | 'EdDSA' | 'Ed25519';

export interface TokensConfig {
  /** Algorithm new access tokens are signed with. Default `EdDSA` (Ed25519). */
  algorithm?: SigningAlgorithm;
  /**
   * Algorithms accepted when verifying. Defaults to only `algorithm`. List the previous algorithm
   * here for one key-rotation period when you change `algorithm`.
   */
  allowedAlgorithms?: readonly SigningAlgorithm[];
  /** Access token lifetime. Default 900 (15 minutes). */
  accessTtlSec?: number;
  /** Allowed clock difference when checking `exp` and `nbf`. Default 5. */
  clockToleranceSec?: number;
  /** Extra claims for the access token. Standard claims cannot be overridden. */
  claims?: (user: User, session: Session) => Record<string, JsonValue> | Promise<Record<string, JsonValue>>;
}

export interface KeysConfig {
  /** Age at which the signing key is replaced automatically. Default 90. Set 0 to rotate only by hand. */
  rotateEveryDays?: number;
  /** `max-age` of the JWKS response. Default 600. */
  jwksMaxAgeSec?: number;
  /** How long a new key is published before it starts signing. Default: `jwksMaxAgeSec`. */
  publishLeadSec?: number;
  /** How long an instance trusts its in-memory copy of the key list. Default 30. */
  cacheTtlSec?: number;
}

export interface CookieConfig {
  /** Default `__Host-rt`. A `__Host-` name requires `path: '/'` and no `domain`. */
  name?: string;
  /** Default `strict`. `lax` also sends the cookie on top-level navigations from other sites. */
  sameSite?: 'strict' | 'lax';
  /** Default `/`. */
  path?: string;
  domain?: string;
}

export interface SessionsConfig {
  /** Absolute session lifetime. Default 30 days. */
  ttlSec?: number;
  /** A session unused for this long can no longer be refreshed. Default 7 days. */
  idleTtlSec?: number;
  /** How recent the last interactive authentication must be for sensitive account changes. Default 600. */
  recentAuthSec?: number;
  cookie?: CookieConfig;
}

export interface PasswordConfig {
  hasher: PasswordHasher;
  /** Default 12. */
  minLength?: number;
  /** Default 256. Bounds the cost of hashing attacker-supplied input. */
  maxLength?: number;
  /** Extra check, for example a breached-password lookup. Return a short reason to reject. */
  check?: (
    password: string,
    info: { identifier?: string },
  ) => string | null | undefined | void | Promise<string | null | undefined | void>;
}

export interface MfaConfig {
  totp?: {
    /** Name shown in authenticator apps. Default: the host of `issuer`. */
    issuer?: string;
    /** Default 6. */
    digits?: 6 | 8;
    /** Seconds per code. Default 30. */
    period?: number;
    /** Steps accepted either side of the current one. Default 1. */
    window?: number;
    /** Default `SHA-1`, the only algorithm every authenticator app supports. */
    algorithm?: 'SHA-1' | 'SHA-256' | 'SHA-512';
  };
  recoveryCodes?: {
    /** Default 10. */
    count?: number;
  };
  rateLimit?: {
    /** Failed codes allowed per user per window. Default 5. */
    maxFailures?: number;
    /** Default 900. */
    windowSec?: number;
  };
  /** Lifetime of the ticket issued after the first factor. Default 300. */
  ticketTtlSec?: number;
  /** Failed codes allowed against one ticket. Default 5. */
  ticketMaxAttempts?: number;
}

export interface PasskeysConfig {
  /** The WebAuthn relying party id: your registrable domain, for example `example.com`. */
  rpId: string;
  rpName: string;
  /** Origins of the pages that run the WebAuthn ceremony, for example `https://app.example.com`. */
  origins: readonly string[];
  /** Default `required`, which makes a passkey sign-in count as two factors. */
  userVerification?: 'required' | 'preferred';
  /**
   * Whether a passkey sign-in may be started with an identifier. When true, the options returned
   * for a known identifier list that account's credential ids, which lets non-discoverable
   * credentials (older security keys) sign in but also reveals whether the account exists and
   * has passkeys. Default false: the identifier is ignored and only discoverable credentials,
   * which is what passkeys are, can sign in.
   */
  identifierHints?: boolean;
  /**
   * Default `required`, so every registered credential can sign in without a hint. Other values
   * are only accepted together with `identifierHints: true`.
   */
  residentKey?: 'required' | 'preferred' | 'discouraged';
  /** Default 300. */
  challengeTtlSec?: number;
}

export interface DpopConfig {
  /**
   * `required` (default): every login must carry a proof, and tokens are bound to its key.
   * `optional`: bind when a proof is sent. `off`: ignore proofs.
   */
  mode?: 'required' | 'optional' | 'off';
  /** Proof signature algorithms accepted. Default `['ES256']`. */
  algorithms?: readonly DpopAlgorithm[];
  /** Allowed difference between a proof's `iat` and the server clock. Default 60. */
  iatToleranceSec?: number;
}

export interface RiskConfig {
  /** Default: `newDevice()`, `newNetwork()` and `failedAttempts()`. */
  signals?: readonly RiskSignal[];
  /** Score from which MFA is required. Default 40. */
  stepUpAt?: number;
  /** Score from which the login is denied. Default 90. Scores are capped at 100. */
  denyAt?: number;
  /**
   * What to do when a login calls for step-up but the user has no second factor to step up to.
   * `allow` (default) lets the login through. The `risk.evaluated` audit event still records that
   * step-up was called for. `deny` refuses it, which is right only once every user has a second
   * factor or a passkey: before that it locks people out on events as ordinary as a mistyped
   * password on a new device.
   */
  whenStepUpUnavailable?: 'deny' | 'allow';
}

export interface RateLimitsConfig {
  /** Throttling of password attempts, per identifier and per IP. */
  login?: {
    /** Failures allowed before delays start. Default 5. */
    freeAttempts?: number;
    /** Failures older than this are forgotten. Default 900. */
    windowSec?: number;
    /** First delay. Each further failure doubles it. Default 30. */
    baseDelaySec?: number;
    /** Longest delay. Default 900. */
    maxDelaySec?: number;
  };
}

export interface AuditConfig {
  /** Default: the adapter's audit store. */
  sinks?: readonly AuditSink[];
  /** When true, a sink failure fails the operation being logged. Default false. */
  failClosed?: boolean;
  /** Called when a sink fails and `failClosed` is false. Default: logs the event type to stderr. */
  onError?: (error: unknown, event: AuditEvent) => void;
}

export interface AuthConfig<P extends string = string> {
  /** The `iss` claim of access tokens. */
  issuer: string;
  /** The `aud` claim of access tokens. */
  audience: string | readonly string[];
  adapter: AuthAdapter;
  /** AES-256 keys for secrets at rest. The first entry encrypts. Every entry can decrypt. */
  dataKeys: readonly DataKeyInput[];
  tokens?: TokensConfig;
  keys?: KeysConfig;
  sessions?: SessionsConfig;
  /** Enables password login. */
  password?: PasswordConfig;
  mfa?: MfaConfig;
  /** Enables passkey registration and login. */
  passkeys?: PasskeysConfig;
  dpop?: DpopConfig;
  risk?: RiskConfig;
  rateLimits?: RateLimitsConfig;
  audit?: AuditConfig;
  access?: {
    rbac?: Rbac<P, string>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    policies?: readonly Policy<any, any, any, any>[];
  };
  /** Epoch milliseconds. Default `Date.now`. */
  clock?: () => number;
  /** Maps a submitted identifier to its stored form. Default: trim and lower-case. */
  normalizeIdentifier?: (identifier: string) => string;
}

export interface ResolvedConfig {
  issuer: string;
  audience: string[];
  tokens: {
    algorithm: SigningAlgorithm;
    allowedAlgorithms: SigningAlgorithm[];
    accessTtlSec: number;
    clockToleranceSec: number;
    claims: TokensConfig['claims'];
  };
  keys: { rotateEveryDays: number; jwksMaxAgeSec: number; publishLeadSec: number; cacheTtlSec: number };
  sessions: {
    ttlSec: number;
    idleTtlSec: number;
    recentAuthSec: number;
    cookie: { name: string; sameSite: 'strict' | 'lax'; path: string; domain: string | undefined };
  };
  password: { hasher: PasswordHasher; minLength: number; maxLength: number; check: PasswordConfig['check'] } | null;
  mfa: {
    totp: { issuer: string; digits: 6 | 8; period: number; window: number; algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512' };
    recoveryCodes: { count: number };
    rateLimit: { maxFailures: number; windowSec: number };
    ticketTtlSec: number;
    ticketMaxAttempts: number;
    enrollmentTtlSec: number;
  };
  passkeys: {
    rpId: string;
    rpName: string;
    origins: string[];
    userVerification: 'required' | 'preferred';
    identifierHints: boolean;
    residentKey: 'required' | 'preferred' | 'discouraged';
    challengeTtlSec: number;
  } | null;
  dpop: { mode: 'required' | 'optional' | 'off'; algorithms: DpopAlgorithm[]; iatToleranceSec: number };
  risk: { signals: RiskSignal[]; stepUpAt: number; denyAt: number; whenStepUpUnavailable: 'deny' | 'allow' };
  rateLimits: { login: { freeAttempts: number; windowSec: number; baseDelaySec: number; maxDelaySec: number } };
  audit: { sinks: AuditSink[]; failClosed: boolean; onError: (error: unknown, event: AuditEvent) => void };
  normalizeIdentifier: (identifier: string) => string;
}

const SIGNING_ALGORITHMS: readonly SigningAlgorithm[] = ['EdDSA', 'Ed25519', 'ES256'];
const DPOP_ALGORITHMS: readonly DpopAlgorithm[] = ['ES256', 'EdDSA', 'Ed25519'];
const DAY_SEC = 86_400;

function fail(message: string): never {
  throw new ConfigurationError('CONFIGURATION_INVALID', { debug: message });
}

function integer(name: string, value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    fail(`${name} must be a whole number between ${min} and ${max}.`);
  }
  return value;
}

function oneOf<T extends string>(name: string, value: T | undefined, fallback: T, allowed: readonly T[]): T {
  if (value === undefined) return fallback;
  if (!allowed.includes(value)) fail(`${name} must be one of: ${allowed.join(', ')}.`);
  return value;
}

function nonEmptyString(name: string, value: unknown): string {
  if (typeof value !== 'string' || value.trim().length === 0) fail(`${name} must be a non-empty string.`);
  return value;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function defaultAuditErrorHandler(error: unknown, event: AuditEvent): void {
  console.error(`[auth] audit sink failed for event ${event.type} (${event.id})`, error);
}

/** Checks a config object and fills in every default. Throws `ConfigurationError` on the first problem. */
export function resolveConfig(config: AuthConfig): ResolvedConfig {
  if (typeof config !== 'object' || config === null) fail('createAuth needs a config object.');

  const issuer = nonEmptyString('issuer', config.issuer);
  const audience = (Array.isArray(config.audience) ? [...config.audience] : [config.audience]) as string[];
  if (audience.length === 0) fail('audience must not be empty.');
  audience.forEach((value, index) => nonEmptyString(`audience[${index}]`, value));

  const adapter = config.adapter;
  for (const store of ['users', 'credentials', 'sessions', 'audit', 'keys', 'devices', 'ephemeral'] as const) {
    if (typeof adapter?.[store] !== 'object' || adapter[store] === null) fail(`adapter.${store} is missing.`);
  }

  // Tokens
  const algorithm = oneOf('tokens.algorithm', config.tokens?.algorithm, 'EdDSA', SIGNING_ALGORITHMS);
  const allowedAlgorithms = [...(config.tokens?.allowedAlgorithms ?? [algorithm])];
  for (const allowed of allowedAlgorithms) {
    if (!SIGNING_ALGORITHMS.includes(allowed)) {
      fail(`tokens.allowedAlgorithms may only contain: ${SIGNING_ALGORITHMS.join(', ')}.`);
    }
  }
  if (!allowedAlgorithms.includes(algorithm)) fail('tokens.allowedAlgorithms must include tokens.algorithm.');
  const accessTtlSec = integer('tokens.accessTtlSec', config.tokens?.accessTtlSec, 900, 30, 3600);
  const clockToleranceSec = integer('tokens.clockToleranceSec', config.tokens?.clockToleranceSec, 5, 0, 300);

  // Keys
  const jwksMaxAgeSec = integer('keys.jwksMaxAgeSec', config.keys?.jwksMaxAgeSec, 600, 0, DAY_SEC);
  const keys = {
    rotateEveryDays: integer('keys.rotateEveryDays', config.keys?.rotateEveryDays, 90, 0, 3650),
    jwksMaxAgeSec,
    publishLeadSec: integer('keys.publishLeadSec', config.keys?.publishLeadSec, jwksMaxAgeSec, 0, 30 * DAY_SEC),
    cacheTtlSec: integer('keys.cacheTtlSec', config.keys?.cacheTtlSec, 30, 0, 3600),
  };

  // Sessions
  const ttlSec = integer('sessions.ttlSec', config.sessions?.ttlSec, 30 * DAY_SEC, 60, 3650 * DAY_SEC);
  const idleTtlSec = integer('sessions.idleTtlSec', config.sessions?.idleTtlSec, Math.min(7 * DAY_SEC, ttlSec), 60, ttlSec);
  if (idleTtlSec <= accessTtlSec) fail('sessions.idleTtlSec must be longer than tokens.accessTtlSec.');
  const cookieName = config.sessions?.cookie?.name ?? '__Host-rt';
  if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(cookieName)) fail('sessions.cookie.name is not a valid cookie name.');
  const cookiePath = config.sessions?.cookie?.path ?? '/';
  if (!cookiePath.startsWith('/') || /[;\s]/.test(cookiePath)) fail('sessions.cookie.path must start with "/".');
  const cookieDomain = config.sessions?.cookie?.domain;
  if (cookieDomain !== undefined && !/^[A-Za-z0-9.-]+$/.test(cookieDomain)) fail('sessions.cookie.domain is not a valid domain.');
  if (cookieName.startsWith('__Host-') && (cookiePath !== '/' || cookieDomain !== undefined)) {
    fail('A "__Host-" cookie needs path "/" and no domain. Use a "__Secure-" name to scope the cookie.');
  }
  const sessions = {
    ttlSec,
    idleTtlSec,
    recentAuthSec: integer('sessions.recentAuthSec', config.sessions?.recentAuthSec, 600, 30, DAY_SEC),
    cookie: {
      name: cookieName,
      sameSite: oneOf('sessions.cookie.sameSite', config.sessions?.cookie?.sameSite, 'strict', ['strict', 'lax'] as const),
      path: cookiePath,
      domain: cookieDomain,
    },
  };

  // Password
  let password: ResolvedConfig['password'] = null;
  if (config.password !== undefined) {
    const hasher = config.password.hasher;
    if (typeof hasher?.hash !== 'function' || typeof hasher.verify !== 'function' || typeof hasher.needsRehash !== 'function') {
      fail('password.hasher must implement hash, verify and needsRehash.');
    }
    const minLength = integer('password.minLength', config.password.minLength, 12, 8, 128);
    const maxLength = integer('password.maxLength', config.password.maxLength, 256, minLength, 4096);
    password = { hasher, minLength, maxLength, check: config.password.check };
  }

  // Passkeys
  let passkeys: ResolvedConfig['passkeys'] = null;
  if (config.passkeys !== undefined) {
    const origins = [...(config.passkeys.origins ?? [])];
    if (origins.length === 0) fail('passkeys.origins needs at least one origin.');
    for (const origin of origins) {
      let parsed: URL;
      try {
        parsed = new URL(origin);
      } catch {
        fail(`passkeys.origins contains "${origin}", which is not a URL.`);
      }
      if (parsed.origin !== origin) fail(`passkeys.origins contains "${origin}". Use the bare origin "${parsed.origin}".`);
      const local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
      if (parsed.protocol !== 'https:' && !local) fail(`passkeys.origins contains "${origin}". WebAuthn needs https.`);
    }
    const identifierHints = config.passkeys.identifierHints ?? false;
    const residentKey = oneOf('passkeys.residentKey', config.passkeys.residentKey, 'required', ['required', 'preferred', 'discouraged'] as const);
    if (!identifierHints && residentKey !== 'required') {
      fail('passkeys.residentKey must be "required" unless passkeys.identifierHints is true: without the hint, only discoverable credentials can sign in.');
    }
    passkeys = {
      rpId: nonEmptyString('passkeys.rpId', config.passkeys.rpId),
      rpName: nonEmptyString('passkeys.rpName', config.passkeys.rpName),
      origins,
      userVerification: oneOf('passkeys.userVerification', config.passkeys.userVerification, 'required', ['required', 'preferred'] as const),
      identifierHints,
      residentKey,
      challengeTtlSec: integer('passkeys.challengeTtlSec', config.passkeys.challengeTtlSec, 300, 30, 3600),
    };
  }

  if (password === null && passkeys === null) fail('Configure at least one of password and passkeys.');

  // MFA
  const digits = config.mfa?.totp?.digits ?? 6;
  if (digits !== 6 && digits !== 8) fail('mfa.totp.digits must be 6 or 8.');
  const mfa = {
    totp: {
      issuer: config.mfa?.totp?.issuer ?? hostOf(issuer),
      digits,
      period: integer('mfa.totp.period', config.mfa?.totp?.period, 30, 15, 300),
      window: integer('mfa.totp.window', config.mfa?.totp?.window, 1, 0, 5),
      algorithm: oneOf('mfa.totp.algorithm', config.mfa?.totp?.algorithm, 'SHA-1', ['SHA-1', 'SHA-256', 'SHA-512'] as const),
    },
    recoveryCodes: { count: integer('mfa.recoveryCodes.count', config.mfa?.recoveryCodes?.count, 10, 1, 50) },
    rateLimit: {
      maxFailures: integer('mfa.rateLimit.maxFailures', config.mfa?.rateLimit?.maxFailures, 5, 1, 100),
      windowSec: integer('mfa.rateLimit.windowSec', config.mfa?.rateLimit?.windowSec, 900, 30, DAY_SEC),
    },
    ticketTtlSec: integer('mfa.ticketTtlSec', config.mfa?.ticketTtlSec, 300, 30, 3600),
    ticketMaxAttempts: integer('mfa.ticketMaxAttempts', config.mfa?.ticketMaxAttempts, 5, 1, 100),
    enrollmentTtlSec: 600,
  };
  nonEmptyString('mfa.totp.issuer', mfa.totp.issuer);

  // DPoP
  const dpopAlgorithms = [...(config.dpop?.algorithms ?? (['ES256'] as const))];
  if (dpopAlgorithms.length === 0) fail('dpop.algorithms must not be empty.');
  for (const allowed of dpopAlgorithms) {
    if (!DPOP_ALGORITHMS.includes(allowed)) fail(`dpop.algorithms may only contain: ${DPOP_ALGORITHMS.join(', ')}.`);
  }
  const dpop = {
    mode: oneOf('dpop.mode', config.dpop?.mode, 'required', ['required', 'optional', 'off'] as const),
    algorithms: dpopAlgorithms,
    iatToleranceSec: integer('dpop.iatToleranceSec', config.dpop?.iatToleranceSec, 60, 5, 600),
  };

  // Risk
  const stepUpAt = config.risk?.stepUpAt ?? 40;
  const denyAt = config.risk?.denyAt ?? 90;
  if (!(stepUpAt >= 0) || !(denyAt >= 0)) fail('risk.stepUpAt and risk.denyAt must be zero or more.');
  if (stepUpAt > denyAt) fail('risk.stepUpAt must not be greater than risk.denyAt.');
  const signals = [...(config.risk?.signals ?? [newDevice(), newNetwork(), failedAttempts()])];
  for (const signal of signals) {
    if (typeof signal !== 'function') fail('risk.signals must contain functions.');
  }
  const risk = {
    signals,
    stepUpAt,
    denyAt,
    whenStepUpUnavailable: oneOf('risk.whenStepUpUnavailable', config.risk?.whenStepUpUnavailable, 'allow', ['deny', 'allow'] as const),
  };

  // Rate limits
  const baseDelaySec = integer('rateLimits.login.baseDelaySec', config.rateLimits?.login?.baseDelaySec, 30, 1, DAY_SEC);
  const rateLimits = {
    login: {
      freeAttempts: integer('rateLimits.login.freeAttempts', config.rateLimits?.login?.freeAttempts, 5, 1, 1000),
      windowSec: integer('rateLimits.login.windowSec', config.rateLimits?.login?.windowSec, 900, 30, DAY_SEC),
      baseDelaySec,
      maxDelaySec: integer('rateLimits.login.maxDelaySec', config.rateLimits?.login?.maxDelaySec, 900, baseDelaySec, DAY_SEC),
    },
  };

  // Audit
  const sinks = [...(config.audit?.sinks ?? [storeSink(adapter.audit)])];
  for (const sink of sinks) {
    if (typeof sink?.write !== 'function') fail('audit.sinks must contain objects with a write method.');
  }
  const audit = {
    sinks,
    failClosed: config.audit?.failClosed ?? false,
    onError: config.audit?.onError ?? defaultAuditErrorHandler,
  };

  return {
    issuer,
    audience,
    tokens: { algorithm, allowedAlgorithms, accessTtlSec, clockToleranceSec, claims: config.tokens?.claims },
    keys,
    sessions,
    password,
    mfa,
    passkeys,
    dpop,
    risk,
    rateLimits,
    audit,
    normalizeIdentifier: config.normalizeIdentifier ?? ((identifier: string) => identifier.trim().toLowerCase()),
  };
}
