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
} from '../types.js';
import { checkTablePrefix, type D1DatabaseLike } from './migrations.js';

export {
  migrate,
  migrations,
  migrationSql,
  type D1DatabaseLike,
  type D1Migration,
  type D1StatementLike,
} from './migrations.js';

export interface D1AdapterOptions {
  /**
   * The D1 binding, `env.DB`. Pass the binding itself, not `env.DB.withSession()`: a read replica
   * can lag behind the primary, and this adapter must see a revoked session or a used token at once.
   */
  db: D1DatabaseLike;
  /** Prefix of the table names, since D1 has no schemas. Default `auth_`. */
  tablePrefix?: string;
  /** Epoch milliseconds, used for the expiry of short-lived state. Default `Date.now`. */
  clock?: () => number;
  /** Replace individual stores, for example to keep users in a table you already have. */
  stores?: Partial<AuthAdapter>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

// Timestamps are stored as fixed-width ISO 8601 UTC, so comparing the text compares the times.
const iso = (value: Date): string => value.toISOString();
const isoOrNull = (value: Date | null): string | null => (value === null ? null : value.toISOString());
const date = (value: unknown): Date => new Date(value as string);
const dateOrNull = (value: unknown): Date | null => (value === null || value === undefined ? null : date(value));
const json = (value: unknown): string => JSON.stringify(value);
const parse = <T>(value: unknown): T => JSON.parse(value as string) as T;

function toUser(row: Row): User {
  return {
    id: row.id,
    identifier: row.identifier,
    roles: parse(row.roles),
    status: row.status,
    attributes: parse(row.attributes),
    createdAt: date(row.created_at),
  };
}

function toTotp(row: Row): TotpCredential {
  return {
    userId: row.user_id,
    encryptedSecret: row.encrypted_secret,
    algorithm: row.algorithm,
    digits: Number(row.digits),
    period: Number(row.period),
    lastUsedStep: Number(row.last_used_step),
    createdAt: date(row.created_at),
  };
}

function toPasskey(row: Row): PasskeyCredential {
  return {
    id: row.id,
    userId: row.user_id,
    credentialId: row.credential_id,
    publicKey: row.public_key,
    counter: Number(row.counter),
    transports: parse(row.transports),
    deviceType: row.device_type,
    backedUp: Number(row.backed_up) === 1,
    name: row.name,
    createdAt: date(row.created_at),
    lastUsedAt: dateOrNull(row.last_used_at),
  };
}

function toSession(row: Row): Session {
  return {
    id: row.id,
    userId: row.user_id,
    createdAt: date(row.created_at),
    lastUsedAt: date(row.last_used_at),
    expiresAt: date(row.expires_at),
    authenticatedAt: date(row.authenticated_at),
    methods: parse(row.methods),
    assurance: row.assurance,
    dpopJkt: row.dpop_jkt,
    ip: row.ip,
    userAgent: row.user_agent,
    revokedAt: dateOrNull(row.revoked_at),
    revokedReason: row.revoked_reason,
  };
}

function toSigningKey(row: Row): StoredSigningKey {
  return {
    kid: row.kid,
    algorithm: row.algorithm,
    publicJwk: parse(row.public_jwk),
    encryptedPrivateJwk: row.encrypted_private_jwk,
    status: row.status,
    createdAt: date(row.created_at),
    activatedAt: dateOrNull(row.activated_at),
    retiringAt: dateOrNull(row.retiring_at),
    retiredAt: dateOrNull(row.retired_at),
  };
}

function toDevice(row: Row): DeviceRecord {
  return {
    userId: row.user_id,
    deviceKey: row.device_key,
    firstSeenAt: date(row.first_seen_at),
    lastSeenAt: date(row.last_seen_at),
    lastIp: row.last_ip,
    lastCountry: row.last_country,
    lastLatitude: row.last_latitude === null ? null : Number(row.last_latitude),
    lastLongitude: row.last_longitude === null ? null : Number(row.last_longitude),
  };
}

/**
 * Stores everything in Cloudflare D1.
 *
 * A method that changes one row is a single statement. A method that changes several uses
 * `db.batch()`, which D1 runs as one transaction. SQLite has no data-modifying CTEs, so in those
 * batches the statement that consumes a value runs last and the earlier ones are conditional on
 * it not being consumed yet: if the condition fails, the whole batch changes nothing.
 */
export function d1Adapter(options: D1AdapterOptions): AuthAdapter {
  const { db } = options;
  const p = checkTablePrefix(options.tablePrefix ?? 'auth_');
  const nowMs = options.clock ?? Date.now;
  const nowIso = () => new Date(nowMs()).toISOString();
  const expiryIso = (ttlSec: number) => new Date(nowMs() + ttlSec * 1000).toISOString();

  const statement = (text: string, params: unknown[] = []) => db.prepare(text).bind(...params);
  const rows = async (text: string, params: unknown[] = []): Promise<Row[]> =>
    (await statement(text, params).all()).results ?? [];
  const first = async (text: string, params: unknown[] = []): Promise<Row | null> => (await rows(text, params))[0] ?? null;

  const adapter: AuthAdapter = {
    users: {
      async findById(id) {
        const row = await first(`SELECT * FROM ${p}users WHERE id = ?1`, [id]);
        return row ? toUser(row) : null;
      },
      async findByIdentifier(identifier) {
        const row = await first(`SELECT * FROM ${p}users WHERE identifier = ?1`, [identifier]);
        return row ? toUser(row) : null;
      },
      async create(user) {
        const row = await first(
          `INSERT INTO ${p}users (id, identifier, roles, status, attributes, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT DO NOTHING
           RETURNING *`,
          [user.id, user.identifier, json(user.roles), user.status, json(user.attributes), iso(user.createdAt)],
        );
        return row ? toUser(row) : null;
      },
      async update(id, patch) {
        const row = await first(
          `UPDATE ${p}users
           SET roles = COALESCE(?2, roles),
               status = COALESCE(?3, status),
               attributes = COALESCE(?4, attributes)
           WHERE id = ?1
           RETURNING *`,
          [
            id,
            patch.roles === undefined ? null : json(patch.roles),
            patch.status ?? null,
            patch.attributes === undefined ? null : json(patch.attributes),
          ],
        );
        return row ? toUser(row) : null;
      },
    },

    credentials: {
      async getPasswordHash(userId) {
        const row = await first(`SELECT hash FROM ${p}password_credentials WHERE user_id = ?1`, [userId]);
        return row ? row.hash : null;
      },
      async setPasswordHash(userId, hash, now) {
        await statement(
          `INSERT INTO ${p}password_credentials (user_id, hash, updated_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT (user_id) DO UPDATE SET hash = excluded.hash, updated_at = excluded.updated_at`,
          [userId, hash, iso(now)],
        ).run();
      },

      async getTotp(userId) {
        const row = await first(`SELECT * FROM ${p}totp_credentials WHERE user_id = ?1`, [userId]);
        return row ? toTotp(row) : null;
      },
      async saveTotp(credential) {
        await statement(
          `INSERT INTO ${p}totp_credentials (user_id, encrypted_secret, algorithm, digits, period, last_used_step, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT (user_id) DO UPDATE SET
             encrypted_secret = excluded.encrypted_secret,
             algorithm = excluded.algorithm,
             digits = excluded.digits,
             period = excluded.period,
             last_used_step = excluded.last_used_step,
             created_at = excluded.created_at`,
          [
            credential.userId,
            credential.encryptedSecret,
            credential.algorithm,
            credential.digits,
            credential.period,
            credential.lastUsedStep,
            iso(credential.createdAt),
          ],
        ).run();
      },
      async advanceTotpStep(userId, step) {
        const updated = await rows(
          `UPDATE ${p}totp_credentials SET last_used_step = ?2
           WHERE user_id = ?1 AND last_used_step < ?2
           RETURNING user_id`,
          [userId, step],
        );
        return updated.length === 1;
      },
      async deleteTotp(userId) {
        const deleted = await rows(`DELETE FROM ${p}totp_credentials WHERE user_id = ?1 RETURNING user_id`, [userId]);
        return deleted.length === 1;
      },

      async replaceRecoveryCodes(userId, codeHashes, now) {
        // One bound JSON array, because D1 limits how many parameters a statement can have.
        await db.batch([
          statement(`DELETE FROM ${p}recovery_codes WHERE user_id = ?1`, [userId]),
          statement(
            `INSERT INTO ${p}recovery_codes (user_id, code_hash, created_at)
             SELECT ?1, value, ?3 FROM json_each(?2)`,
            [userId, json(codeHashes), iso(now)],
          ),
        ]);
      },
      async consumeRecoveryCode(userId, codeHash) {
        const deleted = await rows(
          `DELETE FROM ${p}recovery_codes WHERE user_id = ?1 AND code_hash = ?2 RETURNING code_hash`,
          [userId, codeHash],
        );
        return deleted.length === 1;
      },
      async countRecoveryCodes(userId) {
        const row = await first(`SELECT count(*) AS count FROM ${p}recovery_codes WHERE user_id = ?1`, [userId]);
        return Number(row?.count ?? 0);
      },

      async listPasskeys(userId) {
        return (await rows(`SELECT * FROM ${p}passkeys WHERE user_id = ?1 ORDER BY created_at, id`, [userId])).map(toPasskey);
      },
      async findPasskeyByCredentialId(credentialId) {
        const row = await first(`SELECT * FROM ${p}passkeys WHERE credential_id = ?1`, [credentialId]);
        return row ? toPasskey(row) : null;
      },
      async savePasskey(credential) {
        const inserted = await rows(
          `INSERT INTO ${p}passkeys
             (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name, created_at, last_used_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          [
            credential.id,
            credential.userId,
            credential.credentialId,
            credential.publicKey,
            credential.counter,
            json(credential.transports),
            credential.deviceType,
            credential.backedUp ? 1 : 0,
            credential.name,
            iso(credential.createdAt),
            isoOrNull(credential.lastUsedAt),
          ],
        );
        return inserted.length === 1;
      },
      async updatePasskeyUsage(id, counter, now) {
        await statement(`UPDATE ${p}passkeys SET counter = ?2, last_used_at = ?3 WHERE id = ?1`, [id, counter, iso(now)]).run();
      },
      async deletePasskey(userId, id) {
        const deleted = await rows(`DELETE FROM ${p}passkeys WHERE id = ?1 AND user_id = ?2 RETURNING id`, [id, userId]);
        return deleted.length === 1;
      },
    },

    sessions: {
      async create(session, firstToken) {
        await db.batch([
          statement(
            `INSERT INTO ${p}sessions
               (id, user_id, created_at, last_used_at, expires_at, authenticated_at, methods, assurance,
                dpop_jkt, ip, user_agent, revoked_at, revoked_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
            [
              session.id,
              session.userId,
              iso(session.createdAt),
              iso(session.lastUsedAt),
              iso(session.expiresAt),
              iso(session.authenticatedAt),
              json(session.methods),
              session.assurance,
              session.dpopJkt,
              session.ip,
              session.userAgent,
              isoOrNull(session.revokedAt),
              session.revokedReason,
            ],
          ),
          statement(
            `INSERT INTO ${p}refresh_tokens (id, session_id, token_hash, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)`,
            [firstToken.id, session.id, firstToken.tokenHash, iso(firstToken.createdAt), iso(firstToken.expiresAt)],
          ),
        ]);
      },
      async findById(id) {
        const row = await first(`SELECT * FROM ${p}sessions WHERE id = ?1`, [id]);
        return row ? toSession(row) : null;
      },
      async findByRefreshTokenHash(tokenHash) {
        const row = await first(
          `SELECT sessions.*,
                  tokens.id AS token_id,
                  tokens.token_hash AS token_hash,
                  tokens.created_at AS token_created_at,
                  tokens.expires_at AS token_expires_at,
                  tokens.used_at AS token_used_at
           FROM ${p}refresh_tokens AS tokens
           JOIN ${p}sessions AS sessions ON sessions.id = tokens.session_id
           WHERE tokens.token_hash = ?1`,
          [tokenHash],
        );
        if (!row) return null;
        const token: RefreshTokenRecord = {
          id: row.token_id,
          sessionId: row.id,
          tokenHash: row.token_hash,
          createdAt: date(row.token_created_at),
          expiresAt: date(row.token_expires_at),
          usedAt: dateOrNull(row.token_used_at),
        };
        return { session: toSession(row), token };
      },
      async rotate(tokenId, next, now) {
        // One transaction. The first two statements apply only while the token is unused, and the
        // last one marks it used, so of two concurrent calls the second changes nothing.
        const results = await db.batch([
          statement(
            `INSERT INTO ${p}refresh_tokens (id, session_id, token_hash, created_at, expires_at)
             SELECT ?1, session_id, ?2, ?3, ?4 FROM ${p}refresh_tokens WHERE id = ?5 AND used_at IS NULL`,
            [next.id, next.tokenHash, iso(next.createdAt), iso(next.expiresAt), tokenId],
          ),
          statement(
            `UPDATE ${p}sessions SET last_used_at = ?1
             WHERE id = (SELECT session_id FROM ${p}refresh_tokens WHERE id = ?2 AND used_at IS NULL)`,
            [iso(now), tokenId],
          ),
          statement(`UPDATE ${p}refresh_tokens SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL RETURNING id`, [
            iso(now),
            tokenId,
          ]),
        ]);
        return results[2]?.results?.length === 1;
      },
      async update(sessionId, patch) {
        const row = await first(
          `UPDATE ${p}sessions
           SET authenticated_at = COALESCE(?2, authenticated_at),
               methods = COALESCE(?3, methods),
               assurance = COALESCE(?4, assurance)
           WHERE id = ?1
           RETURNING *`,
          [
            sessionId,
            patch.authenticatedAt === undefined ? null : iso(patch.authenticatedAt),
            patch.methods === undefined ? null : json(patch.methods),
            patch.assurance ?? null,
          ],
        );
        return row ? toSession(row) : null;
      },
      async listByUser(userId) {
        const found = await rows(
          `SELECT * FROM ${p}sessions WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC, id`,
          [userId],
        );
        return found.map(toSession);
      },
      async revoke(sessionId, reason, now) {
        const updated = await rows(
          `UPDATE ${p}sessions SET revoked_at = ?2, revoked_reason = ?3
           WHERE id = ?1 AND revoked_at IS NULL
           RETURNING id`,
          [sessionId, iso(now), reason],
        );
        return updated.length === 1;
      },
      async revokeAllForUser(userId, reason, now, exceptSessionId) {
        const updated = await rows(
          `UPDATE ${p}sessions SET revoked_at = ?2, revoked_reason = ?3
           WHERE user_id = ?1 AND revoked_at IS NULL AND (?4 IS NULL OR id <> ?4)
           RETURNING id`,
          [userId, iso(now), reason, exceptSessionId ?? null],
        );
        return updated.length;
      },
      async deleteExpired(before) {
        // Explicit rather than relying on the cascade, so tokens go even where foreign keys are off.
        const cutoff = iso(before);
        const condition = `expires_at < ?1 OR (revoked_at IS NOT NULL AND revoked_at < ?1)`;
        const results = await db.batch([
          statement(`DELETE FROM ${p}refresh_tokens WHERE session_id IN (SELECT id FROM ${p}sessions WHERE ${condition})`, [cutoff]),
          statement(`DELETE FROM ${p}sessions WHERE ${condition} RETURNING id`, [cutoff]),
        ]);
        return results[1]?.results?.length ?? 0;
      },
    },

    audit: {
      async append(event) {
        await statement(
          `INSERT INTO ${p}audit_events (id, type, at, outcome, user_id, session_id, event)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
          [event.id, event.type, new Date(event.at).toISOString(), event.outcome, event.userId ?? null, event.sessionId ?? null, json(event)],
        ).run();
      },
      async list(filter = {}) {
        const conditions: string[] = [];
        const params: unknown[] = [];
        if (filter.userId !== undefined) {
          params.push(filter.userId);
          conditions.push(`user_id = ?${params.length}`);
        }
        if (filter.type !== undefined) {
          params.push(filter.type);
          conditions.push(`type = ?${params.length}`);
        }
        if (filter.since !== undefined) {
          // Normalised, because the stored text is compared and `since` may carry an offset.
          params.push(new Date(filter.since).toISOString());
          conditions.push(`at >= ?${params.length}`);
        }
        let limit = '';
        if (filter.limit !== undefined) {
          params.push(Math.max(0, Math.floor(filter.limit)));
          limit = ` LIMIT ?${params.length}`;
        }
        const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
        const found = await rows(`SELECT event FROM ${p}audit_events${where} ORDER BY at DESC, id DESC${limit}`, params);
        return found.map((row) => parse<AuditEvent>(row.event));
      },
    },

    keys: {
      async list() {
        return (await rows(`SELECT * FROM ${p}signing_keys ORDER BY created_at, kid`)).map(toSigningKey);
      },
      async insertPending(key, expectedActiveKid) {
        // SQLite's IS compares NULL as a value. The partial unique index settles any remaining race.
        const inserted = await rows(
          `INSERT INTO ${p}signing_keys (kid, algorithm, public_jwk, encrypted_private_jwk, status, created_at)
           SELECT ?1, ?2, ?3, ?4, 'pending', ?5
           WHERE NOT EXISTS (SELECT 1 FROM ${p}signing_keys WHERE status = 'pending')
             AND (SELECT kid FROM ${p}signing_keys WHERE status = 'active' LIMIT 1) IS ?6
           ON CONFLICT DO NOTHING
           RETURNING kid`,
          [key.kid, key.algorithm, json(key.publicJwk), key.encryptedPrivateJwk, iso(key.createdAt), expectedActiveKid],
        );
        return inserted.length === 1;
      },
      async activate(kid, now) {
        // One transaction. The demotion applies only while `kid` is still pending.
        const results = await db.batch([
          statement(
            `UPDATE ${p}signing_keys SET status = 'retiring', retiring_at = ?2
             WHERE status = 'active' AND kid <> ?1
               AND EXISTS (SELECT 1 FROM ${p}signing_keys WHERE kid = ?1 AND status = 'pending')`,
            [kid, iso(now)],
          ),
          statement(
            `UPDATE ${p}signing_keys SET status = 'active', activated_at = ?2
             WHERE kid = ?1 AND status = 'pending'
             RETURNING kid`,
            [kid, iso(now)],
          ),
        ]);
        return results[1]?.results?.length === 1;
      },
      async retire(kid, now) {
        const updated = await rows(
          `UPDATE ${p}signing_keys SET status = 'retired', retired_at = ?2
           WHERE kid = ?1 AND status = 'retiring'
           RETURNING kid`,
          [kid, iso(now)],
        );
        return updated.length === 1;
      },
    },

    devices: {
      async listByUser(userId) {
        return (await rows(`SELECT * FROM ${p}devices WHERE user_id = ?1 ORDER BY first_seen_at`, [userId])).map(toDevice);
      },
      async upsert(sighting) {
        await statement(
          `INSERT INTO ${p}devices
             (user_id, device_key, first_seen_at, last_seen_at, last_ip, last_country, last_latitude, last_longitude)
           VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7)
           ON CONFLICT (user_id, device_key) DO UPDATE SET
             last_seen_at = excluded.last_seen_at,
             last_ip = excluded.last_ip,
             last_country = excluded.last_country,
             last_latitude = excluded.last_latitude,
             last_longitude = excluded.last_longitude`,
          [
            sighting.userId,
            sighting.deviceKey,
            iso(sighting.now),
            sighting.ip,
            sighting.country,
            sighting.latitude,
            sighting.longitude,
          ],
        ).run();
      },
    },

    ephemeral: {
      async set(key, value, ttlSec) {
        await statement(
          `INSERT INTO ${p}ephemeral (key, value, expires_at)
           VALUES (?1, ?2, ?3)
           ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at`,
          [key, json(value), expiryIso(ttlSec)],
        ).run();
      },
      async get(key) {
        const row = await first(`SELECT value FROM ${p}ephemeral WHERE key = ?1 AND expires_at > ?2`, [key, nowIso()]);
        return row ? parse<JsonValue>(row.value) : null;
      },
      async take(key) {
        const row = await first(`DELETE FROM ${p}ephemeral WHERE key = ?1 RETURNING value, (expires_at > ?2) AS live`, [
          key,
          nowIso(),
        ]);
        return row && Number(row.live) === 1 ? parse<JsonValue>(row.value) : null;
      },
      async setIfAbsent(key, ttlSec) {
        // Inserts, or replaces an entry that has already expired. A live entry matches neither branch.
        const written = await rows(
          `INSERT INTO ${p}ephemeral AS entry (key, value, expires_at)
           VALUES (?1, 'true', ?3)
           ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at
             WHERE entry.expires_at <= ?2
           RETURNING key`,
          [key, nowIso(), expiryIso(ttlSec)],
        );
        return written.length === 1;
      },
      async increment(key, ttlSec) {
        const row = await first(
          `INSERT INTO ${p}ephemeral AS entry (key, value, expires_at)
           VALUES (?1, '1', ?3)
           ON CONFLICT (key) DO UPDATE SET
             value = CASE
               WHEN entry.expires_at <= ?2 OR json_type(entry.value) <> 'integer' THEN '1'
               ELSE CAST(CAST(entry.value AS INTEGER) + 1 AS TEXT)
             END,
             expires_at = CASE WHEN entry.expires_at <= ?2 THEN excluded.expires_at ELSE entry.expires_at END
           RETURNING value`,
          [key, nowIso(), expiryIso(ttlSec)],
        );
        return Number(row?.value ?? 0);
      },
      async purgeExpired() {
        const deleted = await rows(`DELETE FROM ${p}ephemeral WHERE expires_at <= ?1 RETURNING key`, [nowIso()]);
        return deleted.length;
      },
    },
  };

  return { ...adapter, ...options.stores };
}
