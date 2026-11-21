import type { AuditEvent, JsonValue } from '@koshirepo/auth-core';
import type {
  AuthAdapter,
  DeviceRecord,
  PasskeyCredential,
  RefreshTokenRecord,
  Session,
  StoredSigningKey,
  TotpCredential,
  User,
} from './types.js';

export interface MemoryAdapterOptions {
  /** Epoch milliseconds. Pass the same clock you give `createAuth` so expiry follows a fake clock in tests. */
  clock?: () => number;
}

export interface MemoryAdapter extends AuthAdapter {
  /** Drops everything. For tests. */
  reset(): void;
}

/**
 * Keeps everything in process memory. For tests and local development, and for one process only:
 * nothing is shared between server instances and everything is lost on restart.
 *
 * Every method runs without yielding between its reads and writes, which is what makes the
 * compare-and-set operations atomic here.
 */
export function memoryAdapter(options: MemoryAdapterOptions = {}): MemoryAdapter {
  const nowMs = options.clock ?? Date.now;
  const clone = <T>(value: T): T => structuredClone(value);

  const users = new Map<string, User>();
  const userIdByIdentifier = new Map<string, string>();

  const passwordHashes = new Map<string, string>();
  const totpCredentials = new Map<string, TotpCredential>();
  const recoveryCodes = new Map<string, Set<string>>();
  const passkeys = new Map<string, PasskeyCredential>();

  const sessions = new Map<string, Session>();
  const refreshTokens = new Map<string, RefreshTokenRecord>();
  const refreshTokenIdByHash = new Map<string, string>();

  const auditEvents: AuditEvent[] = [];
  const signingKeys = new Map<string, StoredSigningKey>();
  const devices = new Map<string, DeviceRecord>();
  const ephemeral = new Map<string, { value: JsonValue; expiresAt: number }>();

  const liveEntry = (key: string) => {
    const entry = ephemeral.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= nowMs()) {
      ephemeral.delete(key);
      return undefined;
    }
    return entry;
  };

  const deleteSession = (sessionId: string) => {
    sessions.delete(sessionId);
    for (const [id, token] of refreshTokens) {
      if (token.sessionId === sessionId) {
        refreshTokens.delete(id);
        refreshTokenIdByHash.delete(token.tokenHash);
      }
    }
  };

  return {
    users: {
      async findById(id) {
        const user = users.get(id);
        return user ? clone(user) : null;
      },
      async findByIdentifier(identifier) {
        const id = userIdByIdentifier.get(identifier);
        const user = id === undefined ? undefined : users.get(id);
        return user ? clone(user) : null;
      },
      async create(user) {
        if (userIdByIdentifier.has(user.identifier) || users.has(user.id)) return null;
        users.set(user.id, clone(user));
        userIdByIdentifier.set(user.identifier, user.id);
        return clone(user);
      },
      async update(id, patch) {
        const user = users.get(id);
        if (!user) return null;
        if (patch.roles !== undefined) user.roles = [...patch.roles];
        if (patch.status !== undefined) user.status = patch.status;
        if (patch.attributes !== undefined) user.attributes = clone(patch.attributes);
        return clone(user);
      },
    },

    credentials: {
      async getPasswordHash(userId) {
        return passwordHashes.get(userId) ?? null;
      },
      async setPasswordHash(userId, hash) {
        passwordHashes.set(userId, hash);
      },

      async getTotp(userId) {
        const credential = totpCredentials.get(userId);
        return credential ? clone(credential) : null;
      },
      async saveTotp(credential) {
        totpCredentials.set(credential.userId, clone(credential));
      },
      async advanceTotpStep(userId, step) {
        const credential = totpCredentials.get(userId);
        if (!credential || credential.lastUsedStep >= step) return false;
        credential.lastUsedStep = step;
        return true;
      },
      async deleteTotp(userId) {
        return totpCredentials.delete(userId);
      },

      async replaceRecoveryCodes(userId, codeHashes) {
        if (codeHashes.length === 0) recoveryCodes.delete(userId);
        else recoveryCodes.set(userId, new Set(codeHashes));
      },
      async consumeRecoveryCode(userId, codeHash) {
        return recoveryCodes.get(userId)?.delete(codeHash) ?? false;
      },
      async countRecoveryCodes(userId) {
        return recoveryCodes.get(userId)?.size ?? 0;
      },

      async listPasskeys(userId) {
        return [...passkeys.values()]
          .filter((passkey) => passkey.userId === userId)
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
          .map(clone);
      },
      async findPasskeyByCredentialId(credentialId) {
        for (const passkey of passkeys.values()) {
          if (passkey.credentialId === credentialId) return clone(passkey);
        }
        return null;
      },
      async savePasskey(credential) {
        for (const passkey of passkeys.values()) {
          if (passkey.credentialId === credential.credentialId) return false;
        }
        passkeys.set(credential.id, clone(credential));
        return true;
      },
      async updatePasskeyUsage(id, counter, now) {
        const passkey = passkeys.get(id);
        if (!passkey) return;
        passkey.counter = counter;
        passkey.lastUsedAt = new Date(now);
      },
      async deletePasskey(userId, id) {
        const passkey = passkeys.get(id);
        if (!passkey || passkey.userId !== userId) return false;
        return passkeys.delete(id);
      },
    },

    sessions: {
      async create(session, firstToken) {
        sessions.set(session.id, clone(session));
        refreshTokens.set(firstToken.id, { ...clone(firstToken), sessionId: session.id, usedAt: null });
        refreshTokenIdByHash.set(firstToken.tokenHash, firstToken.id);
      },
      async findById(id) {
        const session = sessions.get(id);
        return session ? clone(session) : null;
      },
      async findByRefreshTokenHash(tokenHash) {
        const tokenId = refreshTokenIdByHash.get(tokenHash);
        const token = tokenId === undefined ? undefined : refreshTokens.get(tokenId);
        const session = token ? sessions.get(token.sessionId) : undefined;
        return token && session ? { session: clone(session), token: clone(token) } : null;
      },
      async rotate(tokenId, next, now) {
        const token = refreshTokens.get(tokenId);
        if (!token || token.usedAt !== null) return false;
        const session = sessions.get(token.sessionId);
        if (!session) return false;
        token.usedAt = new Date(now);
        refreshTokens.set(next.id, { ...clone(next), sessionId: token.sessionId, usedAt: null });
        refreshTokenIdByHash.set(next.tokenHash, next.id);
        session.lastUsedAt = new Date(now);
        return true;
      },
      async update(sessionId, patch) {
        const session = sessions.get(sessionId);
        if (!session) return null;
        if (patch.authenticatedAt !== undefined) session.authenticatedAt = new Date(patch.authenticatedAt);
        if (patch.methods !== undefined) session.methods = [...patch.methods];
        if (patch.assurance !== undefined) session.assurance = patch.assurance;
        return clone(session);
      },
      async listByUser(userId) {
        return [...sessions.values()]
          .filter((session) => session.userId === userId && session.revokedAt === null)
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
          .map(clone);
      },
      async revoke(sessionId, reason, now) {
        const session = sessions.get(sessionId);
        if (!session || session.revokedAt !== null) return false;
        session.revokedAt = new Date(now);
        session.revokedReason = reason;
        return true;
      },
      async revokeAllForUser(userId, reason, now, exceptSessionId) {
        let count = 0;
        for (const session of sessions.values()) {
          if (session.userId !== userId || session.revokedAt !== null || session.id === exceptSessionId) continue;
          session.revokedAt = new Date(now);
          session.revokedReason = reason;
          count++;
        }
        return count;
      },
      async deleteExpired(before) {
        let count = 0;
        for (const session of [...sessions.values()]) {
          const expired = session.expiresAt.getTime() < before.getTime();
          const revokedLongAgo = session.revokedAt !== null && session.revokedAt.getTime() < before.getTime();
          if (expired || revokedLongAgo) {
            deleteSession(session.id);
            count++;
          }
        }
        return count;
      },
    },

    audit: {
      async append(event) {
        auditEvents.push(clone(event));
      },
      async list(filter = {}) {
        const matches = auditEvents.filter(
          (event) =>
            (filter.userId === undefined || event.userId === filter.userId) &&
            (filter.type === undefined || event.type === filter.type) &&
            (filter.since === undefined || event.at >= filter.since),
        );
        const newestFirst = matches.reverse();
        return (filter.limit === undefined ? newestFirst : newestFirst.slice(0, filter.limit)).map(clone);
      },
    },

    keys: {
      async list() {
        return [...signingKeys.values()].map(clone);
      },
      async insertPending(key, expectedActiveKid) {
        if (signingKeys.has(key.kid)) return false;
        let activeKid: string | null = null;
        for (const existing of signingKeys.values()) {
          if (existing.status === 'pending') return false;
          if (existing.status === 'active') activeKid = existing.kid;
        }
        if (activeKid !== expectedActiveKid) return false;
        signingKeys.set(key.kid, { ...clone(key), status: 'pending' });
        return true;
      },
      async activate(kid, now) {
        const key = signingKeys.get(kid);
        if (!key || key.status !== 'pending') return false;
        for (const existing of signingKeys.values()) {
          if (existing.status === 'active') {
            existing.status = 'retiring';
            existing.retiringAt = new Date(now);
          }
        }
        key.status = 'active';
        key.activatedAt = new Date(now);
        return true;
      },
      async retire(kid, now) {
        const key = signingKeys.get(kid);
        if (!key || key.status !== 'retiring') return false;
        key.status = 'retired';
        key.retiredAt = new Date(now);
        return true;
      },
    },

    devices: {
      async listByUser(userId) {
        return [...devices.values()].filter((device) => device.userId === userId).map(clone);
      },
      async upsert(sighting) {
        const key = `${sighting.userId}\u0000${sighting.deviceKey}`;
        const existing = devices.get(key);
        if (existing) {
          existing.lastSeenAt = new Date(sighting.now);
          existing.lastIp = sighting.ip;
          existing.lastCountry = sighting.country;
          existing.lastLatitude = sighting.latitude;
          existing.lastLongitude = sighting.longitude;
          return;
        }
        devices.set(key, {
          userId: sighting.userId,
          deviceKey: sighting.deviceKey,
          firstSeenAt: new Date(sighting.now),
          lastSeenAt: new Date(sighting.now),
          lastIp: sighting.ip,
          lastCountry: sighting.country,
          lastLatitude: sighting.latitude,
          lastLongitude: sighting.longitude,
        });
      },
    },

    ephemeral: {
      async set(key, value, ttlSec) {
        ephemeral.set(key, { value: clone(value), expiresAt: nowMs() + ttlSec * 1000 });
      },
      async get(key) {
        const entry = liveEntry(key);
        return entry ? clone(entry.value) : null;
      },
      async take(key) {
        const entry = liveEntry(key);
        if (!entry) return null;
        ephemeral.delete(key);
        return entry.value;
      },
      async setIfAbsent(key, ttlSec) {
        if (liveEntry(key)) return false;
        ephemeral.set(key, { value: true, expiresAt: nowMs() + ttlSec * 1000 });
        return true;
      },
      async increment(key, ttlSec) {
        const entry = liveEntry(key);
        if (!entry) {
          ephemeral.set(key, { value: 1, expiresAt: nowMs() + ttlSec * 1000 });
          return 1;
        }
        const next = (typeof entry.value === 'number' ? entry.value : 0) + 1;
        entry.value = next;
        return next;
      },
      async purgeExpired() {
        let count = 0;
        const now = nowMs();
        for (const [key, entry] of ephemeral) {
          if (entry.expiresAt <= now) {
            ephemeral.delete(key);
            count++;
          }
        }
        return count;
      },
    },

    reset() {
      users.clear();
      userIdByIdentifier.clear();
      passwordHashes.clear();
      totpCredentials.clear();
      recoveryCodes.clear();
      passkeys.clear();
      sessions.clear();
      refreshTokens.clear();
      refreshTokenIdByHash.clear();
      auditEvents.length = 0;
      signingKeys.clear();
      devices.clear();
      ephemeral.clear();
    },
  };
}
