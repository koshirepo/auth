import { randomBytes, sha256Base64Url } from '../util/crypto.js';
import { toBase32 } from '../util/encoding.js';

/**
 * A recovery code: 80 random bits as 16 base32 characters, shown as `XXXX-XXXX-XXXX-XXXX`.
 *
 * 80 bits is enough that a fast hash is safe for storage: guessing a code from its hash is not
 * feasible, so no slow password hash is needed.
 */
export function generateRecoveryCode(): string {
  const raw = toBase32(randomBytes(10));
  return (raw.match(/.{4}/g) as string[]).join('-');
}

/**
 * Brings what a person typed into canonical form: upper case, no separators, and the digits that
 * base32 does not use mapped to the letters they are mistaken for. Returns null if the result is
 * not a well-formed code.
 */
export function normalizeRecoveryCode(input: unknown): string | null {
  if (typeof input !== 'string' || input.length > 64) return null;
  const clean = input
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .replace(/0/g, 'O')
    .replace(/1/g, 'I')
    .replace(/8/g, 'B');
  return /^[A-Z2-7]{16}$/.test(clean) ? clean : null;
}

/** The stored form of a code. The user id is mixed in so equal codes of two users hash differently. */
export function hashRecoveryCode(userId: string, normalizedCode: string): Promise<string> {
  return sha256Base64Url(`recovery-code:${userId}:${normalizedCode}`);
}
