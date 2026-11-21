import { DpopError } from '@acme/auth-core';
import { EmbeddedJWK, calculateJwkThumbprint, decodeProtectedHeader, jwtVerify, type JWK } from 'jose';
import { constantTimeEqual, sha256Base64Url } from '../util/crypto.js';

export const DPOP_PROOF_TYPE = 'dpop+jwt';

/** Remembers proof ids for as long as a proof could still be accepted. */
export interface ReplayStore {
  /** Atomic. Returns true only the first time `key` is seen within `ttlSec`. */
  setIfAbsent(key: string, ttlSec: number): Promise<boolean>;
}

export interface DpopProofInput {
  proof: string | undefined;
  /** HTTP method of the request the proof came with. */
  method: string;
  /** URL of that request as the browser saw it. Query string and fragment are ignored. */
  url: string;
  /** When given, the proof must carry the hash of this access token. */
  accessToken?: string;
  /** When given, the proof must be signed by the key with this thumbprint. */
  expectedJkt?: string;
}

export interface DpopValidatorOptions {
  /** Proof signature algorithms accepted. Asymmetric only. */
  algorithms: readonly string[];
  iatToleranceSec: number;
  replayStore: ReplayStore;
  /** Epoch milliseconds. */
  now: () => number;
}

const MAX_PROOF_LENGTH = 8_192;
const SYMMETRIC_OR_NONE = /^(none|HS\d+)$/i;

function invalid(debug: string, cause?: unknown): never {
  throw new DpopError('DPOP_PROOF_INVALID', cause === undefined ? { debug } : { debug, cause });
}

/** The URL a proof is compared against: origin and path, in canonical form. */
export function normalizeHtu(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

/**
 * Validates a DPoP proof (RFC 9449, section 4.3) and returns the thumbprint of the key that
 * signed it.
 *
 * Checks, in order: one well-formed proof JWT; `typ` is `dpop+jwt`; the algorithm is asymmetric
 * and allowlisted; the embedded key is a public key and its signature verifies; `htm` and `htu`
 * match the request; `iat` is within tolerance; the access-token hash matches when a token is
 * presented; the key matches the expected thumbprint; the proof id has not been seen before.
 */
export async function validateDpopProof(
  input: DpopProofInput,
  options: DpopValidatorOptions,
): Promise<{ jkt: string; jti: string }> {
  const proof = input.proof;
  if (proof === undefined || proof.length === 0) throw new DpopError('DPOP_PROOF_REQUIRED');
  if (proof.length > MAX_PROOF_LENGTH || proof.split('.').length !== 3) invalid('The proof is not a compact JWS.');

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch (cause) {
    invalid('The proof header cannot be decoded.', cause);
  }
  if (header.typ !== DPOP_PROOF_TYPE) invalid('The proof typ is not dpop+jwt.');
  if (typeof header.alg !== 'string' || SYMMETRIC_OR_NONE.test(header.alg) || !options.algorithms.includes(header.alg)) {
    invalid('The proof algorithm is not allowed.');
  }
  const jwk = header.jwk as (JWK & Record<string, unknown>) | undefined;
  if (typeof jwk !== 'object' || jwk === null) invalid('The proof has no embedded key.');
  if (jwk.kty === 'oct' || 'd' in jwk || 'k' in jwk || 'p' in jwk || 'q' in jwk) {
    invalid('The embedded key must be a public key.');
  }

  const nowMs = options.now();
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(proof, EmbeddedJWK, {
      algorithms: [...options.algorithms],
      typ: DPOP_PROOF_TYPE,
      currentDate: new Date(nowMs),
      clockTolerance: options.iatToleranceSec,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch (cause) {
    invalid('The proof signature or claims are not valid.', cause);
  }

  const { jti, htm, htu, iat, ath } = payload;
  if (typeof jti !== 'string' || jti.length < 8 || jti.length > 256) invalid('The proof jti is missing or malformed.');
  if (typeof htm !== 'string' || htm !== input.method.toUpperCase()) invalid('The proof htm does not match the request method.');
  const expectedUrl = normalizeHtu(input.url);
  if (typeof htu !== 'string' || expectedUrl === null || normalizeHtu(htu) !== expectedUrl) {
    invalid('The proof htu does not match the request URL.');
  }
  const nowSec = Math.floor(nowMs / 1000);
  if (typeof iat !== 'number' || !Number.isFinite(iat) || Math.abs(nowSec - iat) > options.iatToleranceSec) {
    // The server time is sent back so that a client whose clock is wrong can correct its proofs
    // and retry. It reveals nothing an HTTP Date header would not.
    throw new DpopError('DPOP_PROOF_INVALID', {
      debug: 'The proof iat is outside the accepted window.',
      details: { reason: 'iat_out_of_window', serverTime: nowSec },
    });
  }
  if (input.accessToken !== undefined) {
    const expectedAth = await sha256Base64Url(input.accessToken);
    if (typeof ath !== 'string' || !constantTimeEqual(ath, expectedAth)) {
      invalid('The proof ath does not match the access token.');
    }
  }

  const jkt = await calculateJwkThumbprint(jwk, 'sha256');
  if (input.expectedJkt !== undefined && !constantTimeEqual(jkt, input.expectedJkt)) {
    throw new DpopError('DPOP_KEY_MISMATCH');
  }

  // A proof stays acceptable for at most the tolerance either side of its iat.
  const replayKey = `dpop:jti:${await sha256Base64Url(`${jkt}.${jti}`)}`;
  const firstUse = await options.replayStore.setIfAbsent(replayKey, options.iatToleranceSec * 2 + 5);
  if (!firstUse) throw new DpopError('DPOP_PROOF_REPLAYED');

  return { jkt, jti };
}

/** An in-process replay store. Correct for a single instance only. */
export function memoryReplayStore(options: { now?: () => number } = {}): ReplayStore {
  const now = options.now ?? Date.now;
  const seen = new Map<string, number>();
  let lastSweep = now();
  return {
    async setIfAbsent(key, ttlSec) {
      const current = now();
      if (current - lastSweep > 60_000) {
        for (const [entry, expiresAt] of seen) if (expiresAt <= current) seen.delete(entry);
        lastSweep = current;
      }
      const expiresAt = seen.get(key);
      if (expiresAt !== undefined && expiresAt > current) return false;
      seen.set(key, current + ttlSec * 1000);
      return true;
    },
  };
}
