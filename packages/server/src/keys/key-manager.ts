import { InternalError, type JsonObject } from '@koshirepo/auth-core';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from 'jose';
import type { SigningAlgorithm, SigningKeyStore, StoredSigningKey } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { Clock } from '../util/clock.js';
import type { DataProtector } from '../util/protector.js';

export interface KeyManagerOptions {
  store: SigningKeyStore;
  protector: DataProtector;
  clock: Clock;
  audit: AuditEmitter;
  /** Algorithm for new keys. */
  algorithm: SigningAlgorithm;
  rotateEveryDays: number;
  /** How long a new key is published before it signs. */
  publishLeadSec: number;
  /** How long a key stays published after it stops signing. */
  retireAfterSec: number;
  cacheTtlSec: number;
}

export interface JwksDocument {
  keys: JsonObject[];
}

interface Snapshot {
  records: StoredSigningKey[];
  loadedAtMs: number;
}

const DAY_MS = 86_400_000;
const FORCED_RELOAD_COOLDOWN_MS = 5_000;

/**
 * Owns the signing-key lifecycle: pending, active, retiring, retired.
 *
 * There is no background timer. Every transition is checked when the key list is loaded, which
 * happens at most once per `cacheTtlSec`. Each transition is one atomic store operation, so
 * several instances reconciling at the same time converge on the same state.
 */
export class KeyManager {
  private snapshot: Snapshot | null = null;
  private loading: Promise<Snapshot> | null = null;
  private lastForcedReloadMs = Number.NEGATIVE_INFINITY;
  private readonly privateKeys = new Map<string, CryptoKey>();
  private readonly publicKeys = new Map<string, CryptoKey>();

  constructor(private readonly options: KeyManagerOptions) {}

  /** The key that signs new tokens. Creates the first key on first use. */
  async signingKey(): Promise<{ kid: string; algorithm: SigningAlgorithm; privateKey: CryptoKey }> {
    const { records } = await this.load(false);
    const active = records.find((record) => record.status === 'active');
    if (!active) throw new InternalError('INTERNAL_ERROR', { debug: 'There is no active signing key.' });
    let privateKey = this.privateKeys.get(active.kid);
    if (!privateKey) {
      const jwk = JSON.parse(await this.options.protector.decrypt(active.encryptedPrivateJwk)) as JWK;
      privateKey = (await importJWK(jwk, active.algorithm)) as CryptoKey;
      this.privateKeys.set(active.kid, privateKey);
    }
    return { kid: active.kid, algorithm: active.algorithm, privateKey };
  }

  /** The public key for `kid` if it is pending, active or retiring. Null for unknown and retired keys. */
  async verificationKey(kid: string): Promise<{ algorithm: SigningAlgorithm; publicKey: CryptoKey } | null> {
    let record = (await this.load(false)).records.find((candidate) => candidate.kid === kid);
    if (!record) {
      // Another instance may have rotated. Reload, but not on every unknown kid an attacker sends.
      const now = this.options.clock.nowMs();
      if (now - this.lastForcedReloadMs >= FORCED_RELOAD_COOLDOWN_MS) {
        this.lastForcedReloadMs = now;
        record = (await this.load(true)).records.find((candidate) => candidate.kid === kid);
      }
    }
    if (!record) return null;
    let publicKey = this.publicKeys.get(kid);
    if (!publicKey) {
      publicKey = (await importJWK(record.publicJwk as JWK, record.algorithm)) as CryptoKey;
      this.publicKeys.set(kid, publicKey);
    }
    return { algorithm: record.algorithm, publicKey };
  }

  /** Public keys of every key that may still verify a token. Never contains private fields. */
  async jwks(): Promise<JwksDocument> {
    const { records } = await this.load(false);
    return {
      keys: records.map((record) => ({ ...record.publicJwk, kid: record.kid, use: 'sig', alg: record.algorithm })),
    };
  }

  /**
   * Starts a rotation by publishing a new pending key, and returns its id. If a rotation is
   * already under way, returns the key that is already pending.
   */
  async rotate(): Promise<{ kid: string }> {
    const { records } = await this.load(true);
    const pending = records.find((record) => record.status === 'pending');
    if (pending) return { kid: pending.kid };
    const active = records.find((record) => record.status === 'active');
    const kid = await this.createPending(active?.kid ?? null);
    this.snapshot = null;
    if (kid !== null) return { kid };
    const raced = (await this.load(true)).records.find((record) => record.status === 'pending');
    if (!raced) throw new InternalError('INTERNAL_ERROR', { debug: 'Key rotation could not create a pending key.' });
    return { kid: raced.kid };
  }

  private load(force: boolean): Promise<Snapshot> {
    const now = this.options.clock.nowMs();
    if (!force && this.snapshot && now - this.snapshot.loadedAtMs < this.options.cacheTtlSec * 1000) {
      return Promise.resolve(this.snapshot);
    }
    this.loading ??= this.reconcile().finally(() => {
      this.loading = null;
    });
    return this.loading;
  }

  private async reconcile(): Promise<Snapshot> {
    for (let attempt = 0; attempt < 8; attempt++) {
      const records = (await this.options.store.list()).filter((record) => record.status !== 'retired');
      if (!(await this.advance(records))) {
        this.snapshot = { records, loadedAtMs: this.options.clock.nowMs() };
        return this.snapshot;
      }
    }
    throw new InternalError('INTERNAL_ERROR', { debug: 'Signing key state did not settle.' });
  }

  /** Performs at most one lifecycle transition. Returns true if the key list should be read again. */
  private async advance(records: StoredSigningKey[]): Promise<boolean> {
    const { store, audit, clock } = this.options;
    const now = clock.now();
    const nowMs = now.getTime();
    const active = records.find((record) => record.status === 'active');
    const pending = records.find((record) => record.status === 'pending');

    if (!active && !pending) {
      await this.createPending(null);
      return true;
    }

    if (pending && (!active || pending.createdAt.getTime() + this.options.publishLeadSec * 1000 <= nowMs)) {
      if (await store.activate(pending.kid, now)) {
        await audit.emit('key.activated', { outcome: 'success', data: { kid: pending.kid } });
      }
      return true;
    }

    for (const record of records) {
      if (
        record.status === 'retiring' &&
        record.retiringAt !== null &&
        record.retiringAt.getTime() + this.options.retireAfterSec * 1000 <= nowMs
      ) {
        if (await store.retire(record.kid, now)) {
          this.privateKeys.delete(record.kid);
          this.publicKeys.delete(record.kid);
          await audit.emit('key.retired', { outcome: 'success', data: { kid: record.kid } });
        }
        return true;
      }
    }

    if (active && !pending) {
      const tooOld =
        this.options.rotateEveryDays > 0 &&
        active.activatedAt !== null &&
        active.activatedAt.getTime() + this.options.rotateEveryDays * DAY_MS <= nowMs;
      const wrongAlgorithm = active.algorithm !== this.options.algorithm;
      if (tooOld || wrongAlgorithm) {
        await this.createPending(active.kid);
        return true;
      }
    }
    return false;
  }

  /**
   * Generates a key pair and stores it as pending. Returns null if another instance got there
   * first: a key is already pending, or the active key is no longer `expectedActiveKid`.
   */
  private async createPending(expectedActiveKid: string | null): Promise<string | null> {
    const { algorithm, protector, store, audit, clock } = this.options;
    const { publicKey, privateKey } = await generateKeyPair(algorithm, { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const kid = await calculateJwkThumbprint(publicJwk);
    const inserted = await store.insertPending(
      {
        kid,
        algorithm,
        publicJwk: publicJwk as JsonObject,
        encryptedPrivateJwk: await protector.encrypt(JSON.stringify(privateJwk)),
        status: 'pending',
        createdAt: clock.now(),
        activatedAt: null,
        retiringAt: null,
        retiredAt: null,
      },
      expectedActiveKid,
    );
    if (!inserted) return null;
    await audit.emit('key.created', { outcome: 'success', data: { kid, algorithm } });
    return kid;
  }
}
