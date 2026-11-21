/**
 * Thin wrappers over WebCrypto. Nothing here implements a primitive: hashing, HMAC, HKDF and
 * random bytes all come from the platform.
 */
import { toBase64Url, utf8Encode } from './encoding.js';

function toBytes(data: string | Uint8Array): Uint8Array {
  return typeof data === 'string' ? utf8Encode(data) : data;
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** A URL-safe random secret. The default of 32 bytes gives 256 bits of entropy. */
export function randomToken(bytes = 32): string {
  return toBase64Url(randomBytes(bytes));
}

/** A random identifier for records. Not a secret. */
export function randomId(): string {
  return crypto.randomUUID();
}

export async function sha256(data: string | Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toBytes(data)));
}

export async function sha256Base64Url(data: string | Uint8Array): Promise<string> {
  return toBase64Url(await sha256(data));
}

export type HmacHash = 'SHA-1' | 'SHA-256' | 'SHA-512';

export async function hmac(hash: HmacHash, key: Uint8Array, data: string | Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, toBytes(data)));
}

/** Derives a purpose-specific key from a master key with HKDF-SHA-256. */
export async function hkdfSha256(key: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const master = await crypto.subtle.importKey('raw', key, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8Encode(info) },
    master,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Compares two strings without returning early at the first difference, so the time taken does
 * not reveal how much of a guess was right.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = utf8Encode(a);
  const right = utf8Encode(b);
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
