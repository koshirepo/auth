import { SignJWT, base64url, calculateJwkThumbprint, type JWK } from 'jose';
import type { LockManagerLike } from './locks.js';

/** Where the device key lives between page loads. */
export interface DpopKeyStore {
  load(): Promise<CryptoKeyPair | null>;
  save(keys: CryptoKeyPair): Promise<void>;
  clear(): Promise<void>;
}

/** Keeps the key for the lifetime of the page only. Every reload is a new device to the server. */
export function memoryKeyStore(): DpopKeyStore {
  let stored: CryptoKeyPair | null = null;
  return {
    load: async () => stored,
    save: async (keys) => {
      stored = keys;
    },
    clear: async () => {
      stored = null;
    },
  };
}

const STORE = 'keys';
const RECORD = 'dpop';

/**
 * Keeps the key in IndexedDB. `CryptoKey` objects are stored as they are, so the private key
 * never exists as bytes that script could read or send anywhere.
 */
export function indexedDbKeyStore(options: { databaseName?: string } = {}): DpopKeyStore {
  const databaseName = options.databaseName ?? 'acme-auth';

  const open = (): Promise<IDBDatabase> =>
    new Promise((resolve, reject) => {
      const request = indexedDB.open(databaseName, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('IndexedDB could not be opened.'));
    });

  const run = async <T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> => {
    const database = await open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const transaction = database.transaction(STORE, mode);
        const request = action(transaction.objectStore(STORE));
        transaction.oncomplete = () => resolve(request.result);
        transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed.'));
        transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction was aborted.'));
      });
    } finally {
      database.close();
    }
  };

  return {
    async load() {
      const stored = await run<CryptoKeyPair | undefined>('readonly', (store) => store.get(RECORD));
      return stored?.privateKey && stored.publicKey ? stored : null;
    },
    async save(keys) {
      await run('readwrite', (store) => store.put(keys, RECORD));
    },
    async clear() {
      await run('readwrite', (store) => store.delete(RECORD));
    },
  };
}

/** IndexedDB where it exists, otherwise memory. */
export function defaultKeyStore(): DpopKeyStore {
  return typeof indexedDB === 'undefined' ? memoryKeyStore() : indexedDbKeyStore();
}

interface LoadedKey {
  privateKey: CryptoKey;
  publicJwk: JWK;
}

/**
 * Creates the device key on first use and signs DPoP proofs (RFC 9449) with it.
 *
 * The key is ES256, which every browser's WebCrypto supports, and its private half is generated
 * as non-extractable. Script running in the page can ask for a signature but cannot export the key.
 */
export class DpopSigner {
  private loading: Promise<LoadedKey> | null = null;

  constructor(
    private readonly store: DpopKeyStore,
    /** Epoch milliseconds, already corrected for any known offset from the server clock. */
    private readonly now: () => number,
    private readonly locks: LockManagerLike | null,
  ) {}

  /** A proof for one request. `accessToken` is included by hash when the request carries one. */
  async proof(method: string, url: string, accessToken?: string): Promise<string> {
    const { privateKey, publicJwk } = await this.key();
    const target = new URL(url);
    const claims: Record<string, unknown> = {
      jti: crypto.randomUUID(),
      htm: method.toUpperCase(),
      // The proof covers the URL without its query string and fragment.
      htu: `${target.origin}${target.pathname}`,
      iat: Math.floor(this.now() / 1000),
    };
    if (accessToken !== undefined) {
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
      claims.ath = base64url.encode(new Uint8Array(digest));
    }
    return new SignJWT(claims).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk }).sign(privateKey);
  }

  /** The RFC 7638 thumbprint the server knows this device by. */
  async thumbprint(): Promise<string> {
    return calculateJwkThumbprint((await this.key()).publicJwk);
  }

  private key(): Promise<LoadedKey> {
    this.loading ??= this.loadOrCreate().catch((error: unknown) => {
      this.loading = null;
      throw error;
    });
    return this.loading;
  }

  private async loadOrCreate(): Promise<LoadedKey> {
    const existing = await this.store.load();
    if (existing) return this.describe(existing);
    // Two tabs opening at once must agree on one key, so creation happens under a lock.
    const create = async (): Promise<CryptoKeyPair> => {
      const raced = await this.store.load();
      if (raced) return raced;
      const generated = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      await this.store.save(generated);
      return generated;
    };
    const pair = this.locks ? await this.locks.request('acme-auth:dpop-key', create) : await create();
    return this.describe(pair);
  }

  private async describe(pair: CryptoKeyPair): Promise<LoadedKey> {
    const exported = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const publicJwk: JWK = { kty: exported.kty as string, crv: exported.crv as string, x: exported.x as string, y: exported.y as string };
    return { privateKey: pair.privateKey, publicJwk };
  }
}
