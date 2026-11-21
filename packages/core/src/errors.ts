import type { JsonValue } from './types.js';

export type ErrorKind =
  | 'authentication'
  | 'account'
  | 'token'
  | 'session'
  | 'mfa'
  | 'passkey'
  | 'dpop'
  | 'risk'
  | 'rate_limit'
  | 'authorization'
  | 'request'
  | 'configuration'
  | 'internal'
  | 'network';

type Definition = readonly [kind: ErrorKind, status: number, message: string];

/**
 * Every error code, with its class, suggested HTTP status and fixed public message.
 *
 * Codes are part of the public contract: they are never renamed, removed or reused within a major
 * version. A snapshot test guards the list.
 */
const DEFINITIONS = {
  INVALID_CREDENTIALS: ['authentication', 401, 'The credentials are not valid.'],
  ACCOUNT_DISABLED: ['authentication', 403, 'This account is disabled.'],

  IDENTIFIER_TAKEN: ['account', 409, 'That identifier is already in use.'],
  PASSWORD_POLICY_VIOLATION: ['account', 400, 'The password does not meet the password policy.'],
  USER_NOT_FOUND: ['account', 404, 'The user does not exist.'],

  TOKEN_MISSING: ['token', 401, 'An access token is required.'],
  TOKEN_MALFORMED: ['token', 401, 'The access token is malformed.'],
  TOKEN_EXPIRED: ['token', 401, 'The access token has expired.'],
  TOKEN_SIGNATURE_INVALID: ['token', 401, 'The access token signature is not valid.'],
  TOKEN_ALGORITHM_NOT_ALLOWED: ['token', 401, 'The access token uses an algorithm that is not allowed.'],
  TOKEN_KEY_UNKNOWN: ['token', 401, 'The access token was signed with an unknown key.'],
  TOKEN_CLAIMS_INVALID: ['token', 401, 'The access token claims are not valid.'],

  REFRESH_TOKEN_MISSING: ['session', 401, 'A refresh token is required.'],
  REFRESH_TOKEN_INVALID: ['session', 401, 'The refresh token is not valid.'],
  REFRESH_TOKEN_EXPIRED: ['session', 401, 'The refresh token has expired.'],
  REFRESH_TOKEN_REUSED: ['session', 401, 'The refresh token was already used. The session has been revoked.'],
  SESSION_REVOKED: ['session', 401, 'The session has been revoked.'],
  SESSION_EXPIRED: ['session', 401, 'The session has expired.'],

  MFA_TICKET_INVALID: ['mfa', 401, 'The MFA ticket is not valid or has expired.'],
  MFA_CODE_INVALID: ['mfa', 401, 'The code is not valid.'],
  MFA_NOT_ENROLLED: ['mfa', 409, 'No second factor is enrolled.'],
  MFA_ALREADY_ENROLLED: ['mfa', 409, 'A second factor is already enrolled.'],
  STEP_UP_REQUIRED: ['mfa', 403, 'This action needs a stronger or more recent authentication.'],

  PASSKEY_CHALLENGE_INVALID: ['passkey', 400, 'The passkey challenge is not valid or has expired.'],
  PASSKEY_VERIFICATION_FAILED: ['passkey', 401, 'The passkey could not be verified.'],
  PASSKEY_NOT_FOUND: ['passkey', 404, 'The passkey does not exist.'],

  DPOP_PROOF_REQUIRED: ['dpop', 401, 'A DPoP proof is required.'],
  DPOP_PROOF_INVALID: ['dpop', 401, 'The DPoP proof is not valid.'],
  DPOP_PROOF_REPLAYED: ['dpop', 401, 'The DPoP proof was already used.'],
  DPOP_KEY_MISMATCH: ['dpop', 401, 'The DPoP proof was signed by a different key.'],

  RISK_DENIED: ['risk', 403, 'This sign-in was blocked.'],

  RATE_LIMITED: ['rate_limit', 429, 'Too many attempts. Try again later.'],

  FORBIDDEN: ['authorization', 403, 'You are not allowed to do that.'],

  REQUEST_INVALID: ['request', 400, 'The request is not valid.'],
  ORIGIN_NOT_ALLOWED: ['request', 403, 'The request origin is not allowed.'],
  NOT_FOUND: ['request', 404, 'Not found.'],

  CONFIGURATION_INVALID: ['configuration', 500, 'The auth configuration is not valid.'],

  INTERNAL_ERROR: ['internal', 500, 'Something went wrong.'],

  NETWORK_ERROR: ['network', 0, 'The auth server could not be reached.'],
} as const satisfies Record<string, Definition>;

export type ErrorCode = keyof typeof DEFINITIONS;

type CodesOf<K extends ErrorKind> = {
  [C in ErrorCode]: (typeof DEFINITIONS)[C][0] extends K ? C : never;
}[ErrorCode];

/** `ErrorCodes.TOKEN_EXPIRED === 'TOKEN_EXPIRED'`, for callers that prefer constants to string literals. */
export const ErrorCodes: { readonly [C in ErrorCode]: C } = Object.freeze(
  Object.fromEntries(Object.keys(DEFINITIONS).map((code) => [code, code])),
) as { readonly [C in ErrorCode]: C };

/** The JSON form of an error, as sent over HTTP inside `{ "error": ... }`. */
export interface ErrorBody {
  code: string;
  message: string;
  details?: Record<string, JsonValue>;
}

export interface AuthErrorOptions {
  /** Extra fields that are safe to send to clients. */
  details?: Readonly<Record<string, JsonValue>>;
  /** The underlying error. Never serialised. */
  cause?: unknown;
  /** Diagnostic text for server logs. Never serialised. */
  debug?: string;
}

const BRAND = Symbol.for('@acme/auth-core:AuthError');

const CLASS_NAMES: Record<ErrorKind, string> = {
  authentication: 'AuthenticationError',
  account: 'AccountError',
  token: 'TokenError',
  session: 'SessionError',
  mfa: 'MfaError',
  passkey: 'PasskeyError',
  dpop: 'DpopError',
  risk: 'RiskError',
  rate_limit: 'RateLimitError',
  authorization: 'AuthorizationError',
  request: 'RequestError',
  configuration: 'ConfigurationError',
  internal: 'InternalError',
  network: 'NetworkError',
};

/**
 * Base class of every error the library throws on purpose.
 *
 * `message` is the fixed public text for the code, so it is always safe to show. Anything specific
 * to one failure goes in `details` (public) or `debug` and `cause` (never serialised).
 */
export class AuthError<C extends ErrorCode = ErrorCode> extends Error {
  readonly code: C;
  readonly kind: ErrorKind;
  /** Suggested HTTP status. */
  readonly status: number;
  readonly details?: Readonly<Record<string, JsonValue>>;
  readonly debug?: string;

  constructor(code: C, options: AuthErrorOptions = {}) {
    const [kind, status, message] = DEFINITIONS[code] as Definition;
    // Configuration errors never leave the process, so their message can say what is wrong.
    const text = kind === 'configuration' && options.debug ? `${message} ${options.debug}` : message;
    super(text, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = CLASS_NAMES[kind];
    this.code = code;
    this.kind = kind;
    this.status = status;
    if (options.details !== undefined) this.details = options.details;
    if (options.debug !== undefined) this.debug = options.debug;
    Object.defineProperty(this, BRAND, { value: true, enumerable: false });
  }

  /** The public form: code, fixed message and details. No stack, cause or debug text. */
  toJSON(): ErrorBody {
    const body: ErrorBody = { code: this.code, message: DEFINITIONS[this.code][2] };
    if (this.details !== undefined) body.details = { ...this.details };
    return body;
  }
}

export class AuthenticationError extends AuthError<CodesOf<'authentication'>> {}
export class AccountError extends AuthError<CodesOf<'account'>> {}
export class TokenError extends AuthError<CodesOf<'token'>> {}
export class SessionError extends AuthError<CodesOf<'session'>> {}
export class MfaError extends AuthError<CodesOf<'mfa'>> {}
export class PasskeyError extends AuthError<CodesOf<'passkey'>> {}
export class DpopError extends AuthError<CodesOf<'dpop'>> {}
export class RiskError extends AuthError<CodesOf<'risk'>> {}
export class RateLimitError extends AuthError<CodesOf<'rate_limit'>> {}
export class AuthorizationError extends AuthError<CodesOf<'authorization'>> {}
export class RequestError extends AuthError<CodesOf<'request'>> {}
export class ConfigurationError extends AuthError<CodesOf<'configuration'>> {}
export class InternalError extends AuthError<CodesOf<'internal'>> {}
export class NetworkError extends AuthError<CodesOf<'network'>> {}

const CLASSES: Record<ErrorKind, new (code: never, options?: AuthErrorOptions) => AuthError> = {
  authentication: AuthenticationError,
  account: AccountError,
  token: TokenError,
  session: SessionError,
  mfa: MfaError,
  passkey: PasskeyError,
  dpop: DpopError,
  risk: RiskError,
  rate_limit: RateLimitError,
  authorization: AuthorizationError,
  request: RequestError,
  configuration: ConfigurationError,
  internal: InternalError,
  network: NetworkError,
};

/**
 * True for any error created by this library.
 *
 * Uses a registered symbol instead of `instanceof`, so it still works when two copies of the
 * package are loaded.
 */
export function isAuthError(value: unknown): value is AuthError {
  return typeof value === 'object' && value !== null && (value as Record<symbol, unknown>)[BRAND] === true;
}

/** True when `value` is a known error code. */
export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && Object.hasOwn(DEFINITIONS, value);
}

/** The error kind, suggested HTTP status and public message for a code. */
export function describeErrorCode(code: ErrorCode): { kind: ErrorKind; status: number; message: string } {
  const [kind, status, message] = DEFINITIONS[code] as Definition;
  return { kind, status, message };
}

/** All error codes, in definition order. */
export function listErrorCodes(): ErrorCode[] {
  return Object.keys(DEFINITIONS) as ErrorCode[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Rebuilds a typed error from a response body. Accepts either the bare body or the
 * `{ error: body }` envelope. An unknown code becomes `INTERNAL_ERROR` with the original code in
 * `details.code`.
 */
export function errorFromBody(body: unknown): AuthError {
  const inner = isPlainObject(body) && isPlainObject(body.error) ? body.error : body;
  if (isPlainObject(inner) && isErrorCode(inner.code)) {
    const [kind] = DEFINITIONS[inner.code] as Definition;
    const options: AuthErrorOptions = {};
    if (isPlainObject(inner.details)) options.details = inner.details as Record<string, JsonValue>;
    return new CLASSES[kind](inner.code as never, options);
  }
  const code = isPlainObject(inner) && typeof inner.code === 'string' ? inner.code : undefined;
  return new InternalError('INTERNAL_ERROR', code === undefined ? {} : { details: { code } });
}
