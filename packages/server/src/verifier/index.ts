/**
 * Stateless access-token verification for resource servers.
 *
 * This entry point needs no database and no auth configuration: only the issuer, the audience and
 * a way to get the public keys. It uses WebCrypto and `fetch` only, so it also runs on edge
 * runtimes.
 */
import { ConfigurationError, DpopError, identityFromClaims, type AccessTokenClaims, type AuthContext, type Subject } from '@koshi-repo/auth-core';
import { createLocalJWKSet, createRemoteJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { memoryReplayStore, validateDpopProof, type ReplayStore } from '../dpop/proof.js';
import { verifyAccessJwt } from '../tokens/verify.js';

export { memoryReplayStore, type ReplayStore } from '../dpop/proof.js';

export interface VerifiedAccessToken {
  subject: Subject;
  context: AuthContext;
  claims: AccessTokenClaims;
}

export interface AccessTokenVerifierOptions {
  issuer: string;
  audience: string | readonly string[];
  /** The algorithm allowlist. Default `['EdDSA']`. */
  algorithms?: readonly string[];
  /** URL of the auth server's JWKS, usually `<origin>/.well-known/jwks.json`. Keys are cached and refetched on an unknown `kid`. */
  jwksUri?: string;
  /** A fixed key set, instead of `jwksUri`. */
  jwks?: { keys: Record<string, unknown>[] };
  /** A custom key resolver, instead of `jwksUri` and `jwks`. */
  getKey?: JWTVerifyGetKey;
  /** Default 5. */
  clockToleranceSec?: number;
  dpop?: {
    /**
     * `required` (default): reject tokens that are not bound to a key.
     * `optional`: accept unbound tokens, and check the proof for bound ones.
     * `off`: do not check proofs. A stolen bound token is then usable here.
     */
    mode?: 'required' | 'optional' | 'off';
    /** Default `['ES256']`. */
    algorithms?: readonly string[];
    /** Default 60. */
    iatToleranceSec?: number;
    /** Where proof ids are remembered. Default: in process memory, which is only correct for a single instance. */
    replayStore?: ReplayStore;
  };
  /** Epoch milliseconds. Default `Date.now`. */
  now?: () => number;
}

export interface VerifyRequest {
  /** HTTP method of the request that carried the token. */
  method?: string;
  /** URL of that request as the browser saw it. */
  url?: string;
  /** Value of the `DPoP` header. */
  dpopProof?: string;
}

export type AccessTokenVerifier = (token: string, request?: VerifyRequest) => Promise<VerifiedAccessToken>;

/** Creates a function that verifies access tokens issued by the auth server. */
export function createAccessTokenVerifier(options: AccessTokenVerifierOptions): AccessTokenVerifier {
  const fail = (debug: string): never => {
    throw new ConfigurationError('CONFIGURATION_INVALID', { debug });
  };
  if (typeof options.issuer !== 'string' || options.issuer.length === 0) fail('issuer is required.');
  const audience = (Array.isArray(options.audience) ? [...options.audience] : [options.audience]) as string[];
  if (audience.length === 0 || audience.some((value) => typeof value !== 'string' || value.length === 0)) {
    fail('audience is required.');
  }
  const algorithms = [...(options.algorithms ?? ['EdDSA'])];
  if (algorithms.length === 0 || algorithms.some((algorithm) => /^(none|HS\d+)$/i.test(algorithm))) {
    fail('algorithms must list asymmetric signature algorithms.');
  }

  const sources = [options.jwksUri, options.jwks, options.getKey].filter((source) => source !== undefined);
  if (sources.length !== 1) fail('Give exactly one of jwksUri, jwks and getKey.');
  let getKey: JWTVerifyGetKey;
  if (options.getKey) {
    getKey = options.getKey;
  } else if (options.jwks) {
    getKey = createLocalJWKSet(options.jwks as unknown as JSONWebKeySet);
  } else {
    let url: URL;
    try {
      url = new URL(options.jwksUri as string);
    } catch {
      return fail('jwksUri is not a URL.');
    }
    getKey = createRemoteJWKSet(url);
  }

  const now = options.now ?? Date.now;
  const dpopMode = options.dpop?.mode ?? 'required';
  const dpopAlgorithms = [...(options.dpop?.algorithms ?? ['ES256'])];
  const iatToleranceSec = options.dpop?.iatToleranceSec ?? 60;
  const replayStore = options.dpop?.replayStore ?? memoryReplayStore({ now });

  return async (token, request = {}) => {
    const claims = await verifyAccessJwt(token, {
      issuer: options.issuer,
      audience,
      algorithms,
      clockToleranceSec: options.clockToleranceSec ?? 5,
      nowMs: now(),
      getKey,
    });

    const boundKey = claims.cnf?.jkt;
    if (boundKey !== undefined && dpopMode !== 'off') {
      await validateDpopProof(
        {
          proof: request.dpopProof,
          method: request.method ?? '',
          url: request.url ?? '',
          accessToken: token,
          expectedJkt: boundKey,
        },
        { algorithms: dpopAlgorithms, iatToleranceSec, replayStore, now },
      );
    } else if (boundKey === undefined && dpopMode === 'required') {
      throw new DpopError('DPOP_PROOF_REQUIRED', { debug: 'The access token is not bound to a key.' });
    }

    return { ...identityFromClaims(claims), claims };
  };
}
