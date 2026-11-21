import { InternalError, TokenError, isAuthError, type AccessTokenClaims } from '@acme/auth-core';
import { decodeProtectedHeader, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';

export const ACCESS_TOKEN_TYPE = 'at+jwt';

/** Claims the library sets itself. A custom claims hook may not override them. */
export const RESERVED_CLAIMS = Object.freeze([
  'iss',
  'aud',
  'sub',
  'iat',
  'exp',
  'nbf',
  'jti',
  'sid',
  'roles',
  'amr',
  'acr',
  'auth_time',
  'cnf',
]);

const MAX_TOKEN_LENGTH = 16_384;

export interface VerifyAccessJwtOptions {
  issuer: string;
  audience: readonly string[];
  /** The algorithm allowlist. A token whose `alg` is not listed is rejected before any key is looked up. */
  algorithms: readonly string[];
  clockToleranceSec: number;
  /** Epoch milliseconds. */
  nowMs: number;
  getKey: JWTVerifyGetKey;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function toClaims(payload: JWTPayload): AccessTokenClaims {
  const { sid, roles, amr, acr, auth_time: authTime, cnf } = payload as Record<string, unknown>;
  const cnfValid =
    cnf === undefined ||
    (typeof cnf === 'object' && cnf !== null && typeof (cnf as { jkt?: unknown }).jkt === 'string');
  if (
    typeof payload.sub !== 'string' ||
    typeof payload.jti !== 'string' ||
    typeof payload.iat !== 'number' ||
    typeof payload.exp !== 'number' ||
    typeof sid !== 'string' ||
    !isStringArray(roles) ||
    !isStringArray(amr) ||
    (acr !== 'aal1' && acr !== 'aal2') ||
    typeof authTime !== 'number' ||
    !cnfValid
  ) {
    throw new TokenError('TOKEN_CLAIMS_INVALID', { debug: 'A required claim is missing or has the wrong type.' });
  }
  return payload as unknown as AccessTokenClaims;
}

function mapJoseError(error: unknown): Error {
  if (isAuthError(error)) return error;
  if (error instanceof errors.JWTExpired) return new TokenError('TOKEN_EXPIRED', { cause: error });
  if (error instanceof errors.JWTClaimValidationFailed) return new TokenError('TOKEN_CLAIMS_INVALID', { cause: error });
  if (error instanceof errors.JOSEAlgNotAllowed) return new TokenError('TOKEN_ALGORITHM_NOT_ALLOWED', { cause: error });
  if (error instanceof errors.JWSSignatureVerificationFailed) {
    return new TokenError('TOKEN_SIGNATURE_INVALID', { cause: error });
  }
  if (error instanceof errors.JWKSNoMatchingKey || error instanceof errors.JWKSMultipleMatchingKeys) {
    return new TokenError('TOKEN_KEY_UNKNOWN', { cause: error });
  }
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) {
    return new InternalError('INTERNAL_ERROR', { debug: 'The JWKS could not be loaded.', cause: error });
  }
  if (error instanceof errors.JOSEError) return new TokenError('TOKEN_MALFORMED', { cause: error });
  return new InternalError('INTERNAL_ERROR', { debug: 'Access token verification failed unexpectedly.', cause: error });
}

/**
 * Verifies an access token and returns its claims.
 *
 * Order of checks: shape, then the algorithm allowlist, then `typ`, then key lookup and signature,
 * then issuer, audience, expiry and required claims. The allowlist comes first so that a token
 * with `alg: none` or a symmetric algorithm never reaches a key.
 */
export async function verifyAccessJwt(token: string, options: VerifyAccessJwtOptions): Promise<AccessTokenClaims> {
  if (typeof token !== 'string' || token.length === 0) throw new TokenError('TOKEN_MISSING');
  if (token.length > MAX_TOKEN_LENGTH || token.split('.').length !== 3) throw new TokenError('TOKEN_MALFORMED');

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch (cause) {
    throw new TokenError('TOKEN_MALFORMED', { cause });
  }
  if (typeof header.alg !== 'string' || !options.algorithms.includes(header.alg)) {
    throw new TokenError('TOKEN_ALGORITHM_NOT_ALLOWED');
  }
  if (header.typ !== ACCESS_TOKEN_TYPE) {
    throw new TokenError('TOKEN_CLAIMS_INVALID', { debug: 'The token is not an access token.' });
  }

  try {
    const { payload } = await jwtVerify(token, options.getKey, {
      algorithms: [...options.algorithms],
      issuer: options.issuer,
      audience: [...options.audience],
      typ: ACCESS_TOKEN_TYPE,
      clockTolerance: options.clockToleranceSec,
      currentDate: new Date(options.nowMs),
      requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp', 'jti', 'sid'],
    });
    return toClaims(payload);
  } catch (error) {
    throw mapJoseError(error);
  }
}
