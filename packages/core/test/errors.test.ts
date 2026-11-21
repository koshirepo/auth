import { describe, expect, it } from 'vitest';
import {
  AccountError,
  AuthError,
  AuthenticationError,
  AuthorizationError,
  ConfigurationError,
  DpopError,
  ErrorCodes,
  InternalError,
  MfaError,
  NetworkError,
  PasskeyError,
  RateLimitError,
  RequestError,
  RiskError,
  SessionError,
  TokenError,
  describeErrorCode,
  errorFromBody,
  isAuthError,
  isErrorCode,
  listErrorCodes,
} from '../src/index.js';

describe('error codes', () => {
  it('are stable: this list may grow, but existing codes never change', () => {
    expect(listErrorCodes()).toEqual([
      'INVALID_CREDENTIALS',
      'ACCOUNT_DISABLED',
      'IDENTIFIER_TAKEN',
      'PASSWORD_POLICY_VIOLATION',
      'USER_NOT_FOUND',
      'TOKEN_MISSING',
      'TOKEN_MALFORMED',
      'TOKEN_EXPIRED',
      'TOKEN_SIGNATURE_INVALID',
      'TOKEN_ALGORITHM_NOT_ALLOWED',
      'TOKEN_KEY_UNKNOWN',
      'TOKEN_CLAIMS_INVALID',
      'REFRESH_TOKEN_MISSING',
      'REFRESH_TOKEN_INVALID',
      'REFRESH_TOKEN_EXPIRED',
      'REFRESH_TOKEN_REUSED',
      'SESSION_REVOKED',
      'SESSION_EXPIRED',
      'MFA_TICKET_INVALID',
      'MFA_CODE_INVALID',
      'MFA_NOT_ENROLLED',
      'MFA_ALREADY_ENROLLED',
      'STEP_UP_REQUIRED',
      'PASSKEY_CHALLENGE_INVALID',
      'PASSKEY_VERIFICATION_FAILED',
      'PASSKEY_NOT_FOUND',
      'DPOP_PROOF_REQUIRED',
      'DPOP_PROOF_INVALID',
      'DPOP_PROOF_REPLAYED',
      'DPOP_KEY_MISMATCH',
      'RISK_DENIED',
      'RATE_LIMITED',
      'FORBIDDEN',
      'REQUEST_INVALID',
      'ORIGIN_NOT_ALLOWED',
      'NOT_FOUND',
      'CONFIGURATION_INVALID',
      'INTERNAL_ERROR',
      'NETWORK_ERROR',
    ]);
  });

  it('exposes each code as a constant equal to its own name', () => {
    for (const code of listErrorCodes()) expect(ErrorCodes[code]).toBe(code);
    expect(Object.isFrozen(ErrorCodes)).toBe(true);
  });

  it('gives every code a status and a non-empty public message', () => {
    for (const code of listErrorCodes()) {
      const { status, message } = describeErrorCode(code);
      expect(message.length).toBeGreaterThan(0);
      expect(status === 0 || (status >= 400 && status <= 599)).toBe(true);
    }
  });

  it('recognises codes without being fooled by inherited object properties', () => {
    expect(isErrorCode('TOKEN_EXPIRED')).toBe(true);
    expect(isErrorCode('toString')).toBe(false);
    expect(isErrorCode('constructor')).toBe(false);
    expect(isErrorCode(42)).toBe(false);
  });
});

describe('AuthError', () => {
  it('maps each kind to its class, name and status', () => {
    const cases: [AuthError, string, number][] = [
      [new AuthenticationError('INVALID_CREDENTIALS'), 'AuthenticationError', 401],
      [new AccountError('IDENTIFIER_TAKEN'), 'AccountError', 409],
      [new TokenError('TOKEN_EXPIRED'), 'TokenError', 401],
      [new SessionError('REFRESH_TOKEN_REUSED'), 'SessionError', 401],
      [new MfaError('STEP_UP_REQUIRED'), 'MfaError', 403],
      [new PasskeyError('PASSKEY_NOT_FOUND'), 'PasskeyError', 404],
      [new DpopError('DPOP_KEY_MISMATCH'), 'DpopError', 401],
      [new RiskError('RISK_DENIED'), 'RiskError', 403],
      [new RateLimitError('RATE_LIMITED'), 'RateLimitError', 429],
      [new AuthorizationError('FORBIDDEN'), 'AuthorizationError', 403],
      [new RequestError('REQUEST_INVALID'), 'RequestError', 400],
      [new ConfigurationError('CONFIGURATION_INVALID'), 'ConfigurationError', 500],
      [new InternalError('INTERNAL_ERROR'), 'InternalError', 500],
      [new NetworkError('NETWORK_ERROR'), 'NetworkError', 0],
    ];
    for (const [error, name, status] of cases) {
      expect(error).toBeInstanceOf(AuthError);
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe(name);
      expect(error.status).toBe(status);
    }
  });

  it('rejects a code that belongs to another class at compile time', () => {
    // @ts-expect-error FORBIDDEN is not a token error code
    const wrong = new TokenError('FORBIDDEN');
    expect(wrong.code).toBe('FORBIDDEN');
  });

  it('serialises only the code, the fixed message and details', () => {
    const error = new TokenError('TOKEN_EXPIRED', {
      details: { hint: 'refresh' },
      debug: 'exp was 1700000000, secret-internal-note',
      cause: new Error('underlying failure with secret-internal-note'),
    });
    const json = JSON.stringify(error);
    expect(JSON.parse(json)).toEqual({
      code: 'TOKEN_EXPIRED',
      message: 'The access token has expired.',
      details: { hint: 'refresh' },
    });
    expect(json).not.toContain('secret-internal-note');
    expect(json).not.toContain('stack');
    expect(json).not.toContain('cause');
  });

  it('keeps the public message fixed even for configuration errors with debug text', () => {
    const error = new ConfigurationError('CONFIGURATION_INVALID', { debug: 'issuer is empty.' });
    expect(error.message).toBe('The auth configuration is not valid. issuer is empty.');
    expect(error.toJSON().message).toBe('The auth configuration is not valid.');
  });

  it('does not put debug text in the message of errors that can reach clients', () => {
    const error = new AuthenticationError('INVALID_CREDENTIALS', { debug: 'user 42 has no password hash' });
    expect(error.message).toBe('The credentials are not valid.');
  });

  it('copies details so later mutation of the JSON cannot change the error', () => {
    const error = new RateLimitError('RATE_LIMITED', { details: { retryAfterSec: 30 } });
    const body = error.toJSON();
    body.details!.retryAfterSec = 0;
    expect(error.details).toEqual({ retryAfterSec: 30 });
  });
});

describe('isAuthError', () => {
  it('accepts library errors and rejects everything else', () => {
    expect(isAuthError(new TokenError('TOKEN_EXPIRED'))).toBe(true);
    expect(isAuthError(new Error('nope'))).toBe(false);
    expect(isAuthError({ code: 'TOKEN_EXPIRED', message: 'x' })).toBe(false);
    expect(isAuthError(null)).toBe(false);
    expect(isAuthError('TOKEN_EXPIRED')).toBe(false);
  });

  it('recognises an error from a second copy of the package by its registered symbol', () => {
    const foreign = Object.create(Error.prototype) as Record<symbol, unknown>;
    Object.defineProperty(foreign, Symbol.for('@koshirepo/auth-core:AuthError'), { value: true });
    expect(foreign instanceof AuthError).toBe(false);
    expect(isAuthError(foreign)).toBe(true);
  });

  it('does not expose the brand as an enumerable property', () => {
    const error = new TokenError('TOKEN_EXPIRED');
    expect(Object.keys(error)).not.toContain('Symbol(@koshirepo/auth-core:AuthError)');
    expect(Object.getOwnPropertySymbols(error).length).toBe(1);
    expect(JSON.stringify({ ...error })).not.toContain('AuthError');
  });
});

describe('errorFromBody', () => {
  it('rebuilds the right class from a bare body or the response envelope', () => {
    const bare = errorFromBody({ code: 'MFA_CODE_INVALID', message: 'ignored' });
    expect(bare).toBeInstanceOf(MfaError);
    expect(bare.code).toBe('MFA_CODE_INVALID');
    expect(bare.message).toBe('The code is not valid.');

    const wrapped = errorFromBody({ error: { code: 'RATE_LIMITED', message: 'x', details: { retryAfterSec: 12 } } });
    expect(wrapped).toBeInstanceOf(RateLimitError);
    expect(wrapped.details).toEqual({ retryAfterSec: 12 });
  });

  it('round-trips through JSON', () => {
    const original = new AuthorizationError('FORBIDDEN', { details: { reason: 'not yours', policy: 'own-only' } });
    const copy = errorFromBody(JSON.parse(JSON.stringify({ error: original })));
    expect(copy).toBeInstanceOf(AuthorizationError);
    expect(copy.toJSON()).toEqual(original.toJSON());
  });

  it('turns unknown codes and junk into INTERNAL_ERROR', () => {
    const unknown = errorFromBody({ code: 'SOMETHING_NEW', message: 'x' });
    expect(unknown).toBeInstanceOf(InternalError);
    expect(unknown.details).toEqual({ code: 'SOMETHING_NEW' });

    for (const junk of [null, undefined, 'text', 42, [], { error: 'string' }, { code: 7 }]) {
      const error = errorFromBody(junk);
      expect(error.code).toBe('INTERNAL_ERROR');
    }
  });

  it('ignores details that are not a plain object', () => {
    expect(errorFromBody({ code: 'FORBIDDEN', details: ['a'] }).details).toBeUndefined();
    expect(errorFromBody({ code: 'FORBIDDEN', details: 'x' }).details).toBeUndefined();
  });
});
