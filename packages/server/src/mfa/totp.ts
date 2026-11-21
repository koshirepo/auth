/**
 * HOTP (RFC 4226) and TOTP (RFC 6238).
 *
 * The HMAC is WebCrypto's. What is implemented here is the protocol arithmetic the RFCs define on
 * top of it: the counter encoding, dynamic truncation and the time-step window. The tests check it
 * against the RFC test vectors.
 */
import { constantTimeEqual, hmac, randomBytes } from '../util/crypto.js';
import { toBase32 } from '../util/encoding.js';

export type TotpAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

const SECRET_BYTES: Record<TotpAlgorithm, number> = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-512': 64 };

/** A random seed of the length RFC 4226 recommends for the hash in use. */
export function generateTotpSecret(algorithm: TotpAlgorithm): Uint8Array {
  return randomBytes(SECRET_BYTES[algorithm]);
}

/** The HOTP value for a counter, as a zero-padded decimal string. */
export async function hotp(secret: Uint8Array, counter: number, digits: number, algorithm: TotpAlgorithm): Promise<string> {
  // The counter is an 8-byte big-endian integer.
  const message = new Uint8Array(8);
  let remaining = counter;
  for (let index = 7; index >= 0; index--) {
    message[index] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  const digest = await hmac(algorithm, secret, message);
  // Dynamic truncation: the low nibble of the last byte selects four bytes, and the top bit is dropped.
  const offset = (digest[digest.length - 1] as number) & 0x0f;
  const binary =
    (((digest[offset] as number) & 0x7f) << 24) |
    ((digest[offset + 1] as number) << 16) |
    ((digest[offset + 2] as number) << 8) |
    (digest[offset + 3] as number);
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

export function totpStep(nowSec: number, period: number): number {
  return Math.floor(nowSec / period);
}

export interface TotpParameters {
  nowSec: number;
  period: number;
  digits: number;
  /** Steps accepted either side of the current one. */
  window: number;
  algorithm: TotpAlgorithm;
}

/**
 * Returns the time step `code` is valid for, or null.
 *
 * Every step in the window is computed and compared in constant time, with no early exit, so the
 * time taken does not depend on which step matched or how close a wrong guess was.
 */
export async function matchTotp(secret: Uint8Array, code: string, parameters: TotpParameters): Promise<number | null> {
  if (typeof code !== 'string' || code.length !== parameters.digits || !/^\d+$/.test(code)) return null;
  const current = totpStep(parameters.nowSec, parameters.period);
  let matched: number | null = null;
  for (let offset = -parameters.window; offset <= parameters.window; offset++) {
    const step = current + offset;
    if (step < 0) continue;
    const expected = await hotp(secret, step, parameters.digits, parameters.algorithm);
    if (constantTimeEqual(expected, code)) matched = step;
  }
  return matched;
}

/** The `otpauth://` URI authenticator apps read from a QR code. */
export function otpauthUri(input: {
  issuer: string;
  account: string;
  secret: Uint8Array;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}): string {
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.account)}`;
  const query = [
    `secret=${toBase32(input.secret)}`,
    `issuer=${encodeURIComponent(input.issuer)}`,
    `algorithm=${input.algorithm.replace('-', '')}`,
    `digits=${input.digits}`,
    `period=${input.period}`,
  ].join('&');
  return `otpauth://totp/${label}?${query}`;
}
