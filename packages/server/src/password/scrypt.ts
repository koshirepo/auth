import { Buffer } from 'node:buffer';
import { createHmac, randomBytes, scrypt as nodeScrypt, timingSafeEqual } from 'node:crypto';
import { ConfigurationError } from '@koshirepo/auth-core';
import type { PasswordHasher } from './hasher.js';

export interface ScryptOptions {
  /** log2 of the CPU and memory cost N. Default 14, so N = 16384 and about 16 MiB. */
  logN?: number;
  /** Block size. Default 8. */
  r?: number;
  /** Parallelisation. Default 5. Together with the defaults above, an OWASP-recommended setting. */
  p?: number;
  /**
   * A secret mixed into every hash and kept outside the database, so a stolen database alone
   * cannot be attacked offline. Changing or losing it invalidates every stored password.
   */
  pepper?: string | Uint8Array;
  /** Allows parameters below the safe minimum. For tests only. */
  unsafeAllowWeakParameters?: boolean;
}

const KEY_BYTES = 32;
const SALT_BYTES = 16;
// The lowest work in OWASP's table of scrypt settings: N = 2^13, r = 8, p = 10.
const MIN_WORK = 2 ** 13 * 8 * 10;
// Limits on what `verify` will compute, so a corrupted or planted hash cannot exhaust the Worker.
const MAX_LOG_N = 17;
const MAX_R = 32;
const MAX_P = 32;
const MAX_MEMORY_BYTES = 256 * 1024 * 1024;

const PHC = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

const encode = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64').replace(/=+$/, '');
const decode = (text: string): Buffer => Buffer.from(text, 'base64');

function derive(password: string | Buffer, salt: Uint8Array, logN: number, r: number, p: number, length: number): Promise<Buffer> {
  const N = 2 ** logN;
  const maxmem = 128 * N * r + 128 * r * p + 1024 * 1024;
  return new Promise((resolve, reject) => {
    nodeScrypt(password, salt, length, { N, r, p, maxmem }, (error, key) => (error ? reject(error) : resolve(key)));
  });
}

/**
 * scrypt password hashing through the platform's `node:crypto`, which is BoringSSL on Cloudflare
 * Workers and OpenSSL on Node. Use it where the `argon2` native addon cannot load: on Workers it
 * needs the `nodejs_compat` compatibility flag. Hashes are PHC strings that record their parameters.
 */
export function scrypt(options: ScryptOptions = {}): PasswordHasher {
  const logN = options.logN ?? 14;
  const r = options.r ?? 8;
  const p = options.p ?? 5;
  for (const [name, value, max] of [['logN', logN, MAX_LOG_N], ['r', r, MAX_R], ['p', p, MAX_P]] as const) {
    if (!Number.isInteger(value) || value < 1 || value > max) {
      throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `scrypt ${name} must be a whole number from 1 to ${max}.` });
    }
  }
  if ((r < 8 || 2 ** logN * r * p < MIN_WORK) && options.unsafeAllowWeakParameters !== true) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: 'These scrypt parameters are below the OWASP minimum. Use for example logN 14, r 8, p 5.',
    });
  }

  const pepper = options.pepper;
  const input = (password: string): string | Buffer =>
    pepper === undefined ? password : createHmac('sha256', pepper).update(password, 'utf8').digest();

  return {
    async hash(password) {
      const salt = randomBytes(SALT_BYTES);
      const key = await derive(input(password), salt, logN, r, p, KEY_BYTES);
      return `$scrypt$ln=${logN},r=${r},p=${p}$${encode(salt)}$${encode(key)}`;
    },
    async verify(hash, password) {
      const match = PHC.exec(hash);
      if (!match) return false;
      const [storedLogN, storedR, storedP] = [Number(match[1]), Number(match[2]), Number(match[3])];
      if (storedLogN < 1 || storedLogN > MAX_LOG_N || storedR < 1 || storedR > MAX_R || storedP < 1 || storedP > MAX_P) return false;
      if (128 * 2 ** storedLogN * storedR > MAX_MEMORY_BYTES) return false;
      const salt = decode(match[4] as string);
      const expected = decode(match[5] as string);
      if (expected.length < 16 || expected.length > 64) return false;
      try {
        const actual = await derive(input(password), salt, storedLogN, storedR, storedP, expected.length);
        return timingSafeEqual(actual, expected);
      } catch {
        return false;
      }
    },
    needsRehash(hash) {
      const match = PHC.exec(hash);
      if (!match) return true;
      return Number(match[1]) < logN || Number(match[2]) < r || Number(match[3]) < p;
    },
  };
}
