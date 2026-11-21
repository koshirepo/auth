import { ConfigurationError } from '@koshirepo/auth-core';
import * as argon2 from 'argon2';
import type { PasswordHasher } from './hasher.js';

export interface Argon2idOptions {
  /** Memory in KiB. Default 19456 (19 MiB), the OWASP minimum together with 2 iterations. */
  memoryKiB?: number;
  /** Passes over the memory. Default 2. */
  iterations?: number;
  /** Lanes. Default 1. */
  parallelism?: number;
  /**
   * A secret mixed into every hash and kept outside the database, so a stolen database alone
   * cannot be attacked offline. Changing or losing it invalidates every stored password.
   */
  pepper?: string | Uint8Array;
  /** Allows parameters below the safe minimum. For tests only. */
  unsafeAllowWeakParameters?: boolean;
}

const MIN_MEMORY_KIB = 7_168;

/**
 * Argon2id password hashing through the `argon2` package, which binds the Argon2 reference
 * implementation. Hashes are PHC strings that record their own parameters.
 *
 * `argon2` is a native addon, so this hasher needs Node.
 */
export function argon2id(options: Argon2idOptions = {}): PasswordHasher {
  const memoryCost = options.memoryKiB ?? 19_456;
  const timeCost = options.iterations ?? 2;
  const parallelism = options.parallelism ?? 1;
  for (const [name, value] of [['memoryKiB', memoryCost], ['iterations', timeCost], ['parallelism', parallelism]] as const) {
    if (!Number.isInteger(value) || value < 1) {
      throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `argon2id ${name} must be a positive whole number.` });
    }
  }
  if (memoryCost < MIN_MEMORY_KIB && options.unsafeAllowWeakParameters !== true) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: `argon2id memoryKiB must be at least ${MIN_MEMORY_KIB}. OWASP recommends 19456 with 2 iterations.`,
    });
  }
  const secret = options.pepper === undefined ? undefined : Buffer.from(options.pepper);
  const withSecret = secret === undefined ? {} : { secret };

  return {
    hash(password) {
      return argon2.hash(password, { type: argon2.argon2id, memoryCost, timeCost, parallelism, ...withSecret });
    },
    async verify(hash, password) {
      try {
        return await argon2.verify(hash, password, withSecret);
      } catch {
        return false;
      }
    },
    needsRehash(hash) {
      const match = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(hash);
      if (!match) return true;
      const [version, memory, time] = [Number(match[1]), Number(match[2]), Number(match[3])];
      return version < 19 || memory < memoryCost || time < timeCost;
    },
  };
}
