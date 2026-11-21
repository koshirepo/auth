import { ConfigurationError, InternalError } from '@koshirepo/auth-core';
import { CompactEncrypt, compactDecrypt } from 'jose';
import { hkdfSha256, hmac } from './crypto.js';
import { fromBase64Url, toBase64Url, utf8Decode, utf8Encode } from './encoding.js';

/** A 256-bit key for encrypting secrets at rest. `key` is 32 bytes, as bytes or base64/base64url. */
export interface DataKeyInput {
  id: string;
  key: string | Uint8Array;
}

/**
 * Encrypts values that must be readable again (TOTP seeds, private signing keys) and produces
 * keyed hashes for values that must be comparable but not readable.
 *
 * Encryption is JWE compact serialisation with direct AES-256-GCM, produced by `jose`. The key id
 * travels in the JWE header, so old ciphertexts stay readable after a new key is put first.
 */
export class DataProtector {
  private readonly keys = new Map<string, Uint8Array>();
  private readonly currentId: string;
  private readonly derived = new Map<string, Uint8Array>();

  constructor(inputs: readonly DataKeyInput[]) {
    if (!Array.isArray(inputs) || inputs.length === 0) {
      throw new ConfigurationError('CONFIGURATION_INVALID', { debug: 'dataKeys needs at least one key.' });
    }
    for (const input of inputs) {
      if (typeof input.id !== 'string' || input.id.length === 0) {
        throw new ConfigurationError('CONFIGURATION_INVALID', { debug: 'Every data key needs a non-empty id.' });
      }
      if (this.keys.has(input.id)) {
        throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `Data key id "${input.id}" is used twice.` });
      }
      let bytes: Uint8Array;
      try {
        bytes = typeof input.key === 'string' ? fromBase64Url(input.key) : input.key;
      } catch {
        throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `Data key "${input.id}" is not base64.` });
      }
      if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
        throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `Data key "${input.id}" must be 32 bytes.` });
      }
      this.keys.set(input.id, bytes);
    }
    this.currentId = (inputs[0] as DataKeyInput).id;
  }

  private get current(): Uint8Array {
    return this.keys.get(this.currentId) as Uint8Array;
  }

  async encrypt(plaintext: string): Promise<string> {
    return new CompactEncrypt(utf8Encode(plaintext))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', kid: this.currentId })
      .encrypt(this.current);
  }

  async decrypt(ciphertext: string): Promise<string> {
    try {
      const { plaintext } = await compactDecrypt(
        ciphertext,
        (header) => {
          const key = typeof header.kid === 'string' ? this.keys.get(header.kid) : undefined;
          if (!key) throw new Error(`No data key with id "${String(header.kid)}".`);
          return key;
        },
        { keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'] },
      );
      return utf8Decode(plaintext);
    } catch (cause) {
      throw new InternalError('INTERNAL_ERROR', { debug: 'A stored secret could not be decrypted.', cause });
    }
  }

  /**
   * HMAC-SHA-256 under a key derived for `purpose`. Used for login identifiers in audit events and
   * rate-limit keys, where the raw value must not be stored.
   */
  async keyedHash(purpose: string, value: string): Promise<string> {
    let key = this.derived.get(purpose);
    if (!key) {
      // The finished key is kept, not the promise: Workers cannot await another request's work.
      key = await hkdfSha256(this.current, `koshi-auth:${purpose}`);
      this.derived.set(purpose, key);
    }
    return toBase64Url(await hmac('SHA-256', key, value));
  }
}
