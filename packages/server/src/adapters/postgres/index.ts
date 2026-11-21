import type { AuditEvent, JsonValue } from '@acme/auth-core';
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
import { quoteSchema, type SqlExecutor } from './migrations.js';

export { migrate, migrations, type Migration, type SqlExecutor } from './migrations.js';

export interface PostgresAdapterOptions {
  /** Anything with `query(text, params)` returning `{ rows }`. A `pg` Pool works as is. */
  db: SqlExecutor;
  /** Schema that holds the tables. Default `auth`. Create the tables with `migrate()`. */
  schema?: string;
  /** Epoch milliseconds, used for the expiry of short-lived state. Default `Date.now`. */
  clock?: () => number;
  /** Replace individual stores, for example to keep users in a table you already have. */
  stores?: Partial<AuthAdapter>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = Record<string, any>;

const iso = (date: Date): string => date.toISOString();
const isoOrNull = (date: Date | null): string | null => (date === null ? null : date.toISOString());
const date = (value: unknown): Date => new Date(value as string | number | Date);
const dateOrNull = (value: unknown): Date | null => (value === null || value === undefined ? null : date(value));
const json = (value: unknown): string => JSON.stringify(value);

function toUser(row: Row): User {
  return {
    id: row.id,
    identifier: row.identifier,
    roles: row.roles,
    status: row.status,
    attributes: row.attributes,
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
    transports: row.transports,
    deviceType: row.device_type,
    backedUp: row.backed_up,
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
    methods: row.methods,
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
    publicJwk: row.public_jwk,
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
 * Stores everything in Postgres with plain SQL.
 *
 * Every method is a single statement, using data-modifying CTEs where two rows change together.
 * That makes each method atomic without a transaction API, so the adapter works with pooled and
 * HTTP-based drivers alike, and it is what the compare-and-set guarantees of the adapter contract
 * rest on.
 */
export function postgresAdapter(options: PostgresAdapterOptions): AuthAdapter {
  const { db } = options;
  const s = quoteSchema(options.schema ?? 'auth');
  const nowIso = () => new Date((options.clock ?? Date.now)()).toISOString();
  const expiryIso = (ttlSec: number) => new Date((options.clock ?? Date.now)() + ttlSec * 1000).toISOString();

  const rows = async (text: string, params: unknown[] = []): Promise<Row[]> => (await db.query(text, params)).rows;
  const first = async (text: string, params: unknown[] = []): Promise<Row | null> => (await rows(text, params))[0] ?? null;

  const adapter: AuthAdapter = {
    users: {
      async findById(id) {
        const row = await first(`SELECT * FROM ${s}.users WHERE id = $1`, [id]);
        return row ? toUser(row) : null;
      },
      async findByIdentifier(identifier) {
        const row = await first(`SELECT * FROM ${s}.users WHERE identifier = $1`, [identifier]);
        return row ? toUser(row) : null;
      },
      async create(user) {
        const row = await first(
          `INSERT INTO ${s}.users (id, identifier, roles, status, attributes, created_at)
           VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6::timestamptz)
           ON CONFLICT DO NOTHING
           RETURNING *`,
          [user.id, user.identifier, json(user.roles), user.status, json(user.attributes), iso(user.createdAt)],
        );
        return row ? toUser(row) : null;
      },
      async update(id, patch) {
        const row = await first(
          `UPDATE ${s}.users
           SET roles = COALESCE($2::jsonb, roles),
               status = COALESCE($3::text, status),
               attributes = COALESCE($4::jsonb, attributes)
           WHERE id = $1
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
        const row = await first(`SELECT hash FROM ${s}.password_credentials WHERE user_id = $1`, [userId]);
        return row ? row.hash : null;
      },
      async setPasswordHash(userId, hash, now) {
        await db.query(
          `INSERT INTO ${s}.password_credentials (user_id, hash, updated_at)
           VALUES ($1, $2, $3::timestamptz)
           ON CONFLICT (user_id) DO UPDATE SET hash = EXCLUDED.hash, updated_at = EXCLUDED.updated_at`,
          [userId, hash, iso(now)],
        );
      },

      async getTotp(userId) {
        const row = await first(`SELECT * FROM ${s}.totp_credentials WHERE user_id = $1`, [userId]);
        return row ? toTotp(row) : null;
      },
      async saveTotp(credential) {
        await db.query(
          `INSERT INTO ${s}.totp_credentials (user_id, encrypted_secret, algorithm, digits, period, last_used_step, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)
           ON CONFLICT (user_id) DO UPDATE SET
             encrypted_secret = EXCLUDED.encrypted_secret,
             algorithm = EXCLUDED.algorithm,
             digits = EXCLUDED.digits,
             period = EXCLUDED.period,
             last_used_step = EXCLUDED.last_used_step,
             created_at = EXCLUDED.created_at`,
          [
            credential.userId,
            credential.encryptedSecret,
            credential.algorithm,
            credential.digits,
            credential.period,
            credential.lastUsedStep,
            iso(credential.createdAt),
          ],
        );
      },
      async advanceTotpStep(userId, step) {
        const updated = await rows(
          `UPDATE ${s}.totp_credentials SET last_used_step = $2
           WHERE user_id = $1 AND last_used_step < $2
           RETURNING user_id`,
          [userId, step],
        );
        return updated.length === 1;
      },
      async deleteTotp(userId) {
        const deleted = await rows(`DELETE FROM ${s}.totp_credentials WHERE user_id = $1 RETURNING user_id`, [userId]);
        return deleted.length === 1;
      },

      async replaceRecoveryCodes(userId, codeHashes, now) {
        await db.query(
          `WITH removed AS (
             DELETE FROM ${s}.recovery_codes WHERE user_id = $1
           )
           INSERT INTO ${s}.recovery_codes (user_id, code_hash, created_at)
           SELECT $1, code_hash, $3::timestamptz
           FROM jsonb_array_elements_text($2::jsonb) AS code_hash`,
          [userId, json(codeHashes), iso(now)],
        );
      },
      async consumeRecoveryCode(userId, codeHash) {
        const deleted = await rows(
          `DELETE FROM ${s}.recovery_codes WHERE user_id = $1 AND code_hash = $2 RETURNING code_hash`,
          [userId, codeHash],
        );
        return deleted.length === 1;
      },
      async countRecoveryCodes(userId) {
        const row = await first(`SELECT count(*)::int AS count FROM ${s}.recovery_codes WHERE user_id = $1`, [userId]);
        return Number(row?.count ?? 0);
      },

      async listPasskeys(userId) {
        return (await rows(`SELECT * FROM ${s}.passkeys WHERE user_id = $1 ORDER BY created_at, id`, [userId])).map(toPasskey);
      },
      async findPasskeyByCredentialId(credentialId) {
        const row = await first(`SELECT * FROM ${s}.passkeys WHERE credential_id = $1`, [credentialId]);
        return row ? toPasskey(row) : null;
      },
      async savePasskey(credential) {
        const inserted = await rows(
          `INSERT INTO ${s}.passkeys
             (id, user_id, credential_id, public_key, counter, transports, device_type, backed_up, name, created_at, last_used_at)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10::timestamptz, $11::timestamptz)
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
            credential.backedUp,
            credential.name,
            iso(credential.createdAt),
            isoOrNull(credential.lastUsedAt),
          ],
        );
        return inserted.length === 1;
      },
      async updatePasskeyUsage(id, counter, now) {
        await db.query(`UPDATE ${s}.passkeys SET counter = $2, last_used_at = $3::timestamptz WHERE id = $1`, [
          id,
          counter,
          iso(now),
        ]);
      },
      async deletePasskey(userId, id) {
        const deleted = await rows(`DELETE FROM ${s}.passkeys WHERE id = $1 AND user_id = $2 RETURNING id`, [id, userId]);
        return deleted.length === 1;
      },
    },

    sessions: {
      async create(session, firstToken) {
        await db.query(
          `WITH new_session AS (
             INSERT INTO ${s}.sessions
               (id, user_id, created_at, last_used_at, expires_at, authenticated_at, methods, assurance,
                dpop_jkt, ip, user_agent, revoked_at, revoked_reason)
             VALUES ($1, $2, $3::timestamptz, $4::timestamptz, $5::timestamptz, $6::timestamptz, $7::jsonb, $8,
                     $9, $10, $11, $12::timestamptz, $13)
             RETURNING id
           )
           INSERT INTO ${s}.refresh_tokens (id, session_id, token_hash, created_at, expires_at)
           SELECT $14, id, $15, $16::timestamptz, $17::timestamptz FROM new_session`,
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
            firstToken.id,
            firstToken.tokenHash,
            iso(firstToken.createdAt),
            iso(firstToken.expiresAt),
          ],
        );
      },
      async findById(id) {
        const row = await first(`SELECT * FROM ${s}.sessions WHERE id = $1`, [id]);
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
           FROM ${s}.refresh_tokens AS tokens
           JOIN ${s}.sessions AS sessions ON sessions.id = tokens.session_id
           WHERE tokens.token_hash = $1`,
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
        // The UPDATE takes a row lock, so of two concurrent calls the second waits, then sees
        // used_at set and matches nothing. Its INSERT then has no row to select from.
        const row = await first(
          `WITH used AS (
             UPDATE ${s}.refresh_tokens SET used_at = $2::timestamptz
             WHERE id = $1 AND used_at IS NULL
             RETURNING session_id
           ), inserted AS (
             INSERT INTO ${s}.refresh_tokens (id, session_id, token_hash, created_at, expires_at)
             SELECT $3, session_id, $4, $5::timestamptz, $6::timestamptz FROM used
             RETURNING session_id
           ), touched AS (
             UPDATE ${s}.sessions SET last_used_at = $2::timestamptz
             WHERE id IN (SELECT session_id FROM inserted)
             RETURNING id
           )
           SELECT (SELECT count(*) FROM inserted)::int AS rotated, (SELECT count(*) FROM touched)::int AS touched`,
          [tokenId, iso(now), next.id, next.tokenHash, iso(next.createdAt), iso(next.expiresAt)],
        );
        return Number(row?.rotated ?? 0) === 1;
      },
      async update(sessionId, patch) {
        const row = await first(
          `UPDATE ${s}.sessions
           SET authenticated_at = COALESCE($2::timestamptz, authenticated_at),
               methods = COALESCE($3::jsonb, methods),
               assurance = COALESCE($4::text, assurance)
           WHERE id = $1
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
          `SELECT * FROM ${s}.sessions WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC, id`,
          [userId],
        );
        return found.map(toSession);
      },
      async revoke(sessionId, reason, now) {
        const updated = await rows(
          `UPDATE ${s}.sessions SET revoked_at = $2::timestamptz, revoked_reason = $3
           WHERE id = $1 AND revoked_at IS NULL
           RETURNING id`,
          [sessionId, iso(now), reason],
        );
        return updated.length === 1;
      },
      async revokeAllForUser(userId, reason, now, exceptSessionId) {
        const updated = await rows(
          `UPDATE ${s}.sessions SET revoked_at = $2::timestamptz, revoked_reason = $3
           WHERE user_id = $1 AND revoked_at IS NULL AND ($4::text IS NULL OR id <> $4::text)
           RETURNING id`,
          [userId, iso(now), reason, exceptSessionId ?? null],
        );
        return updated.length;
      },
      async deleteExpired(before) {
        const deleted = await rows(
          `DELETE FROM ${s}.sessions
           WHERE expires_at < $1::timestamptz OR (revoked_at IS NOT NULL AND revoked_at < $1::timestamptz)
           RETURNING id`,
          [iso(before)],
        );
        return deleted.length;
      },
    },

    audit: {
      async append(event) {
        await db.query(
          `INSERT INTO ${s}.audit_events (id, type, at, outcome, user_id, session_id, event)
           VALUES ($1, $2, $3::timestamptz, $4, $5, $6, $7::jsonb)`,
          [event.id, event.type, event.at, event.outcome, event.userId ?? null, event.sessionId ?? null, json(event)],
        );
      },
      async list(filter = {}) {
        const conditions: string[] = [];
        const params: unknown[] = [];
        if (filter.userId !== undefined) {
          params.push(filter.userId);
          conditions.push(`user_id = $${params.length}`);
        }
        if (filter.type !== undefined) {
          params.push(filter.type);
          conditions.push(`type = $${params.length}`);
        }
        if (filter.since !== undefined) {
          params.push(filter.since);
          conditions.push(`at >= $${params.length}::timestamptz`);
        }
        let limit = '';
        if (filter.limit !== undefined) {
          params.push(Math.max(0, Math.floor(filter.limit)));
          limit = ` LIMIT $${params.length}::int`;
        }
        const where = conditions.length > 0 ? ` WHERE ${conditions.join(' AND ')}` : '';
        const found = await rows(
          `SELECT event FROM ${s}.audit_events${where} ORDER BY at DESC, id DESC${limit}`,
          params,
        );
        return found.map((row) => row.event as AuditEvent);
      },
    },

    keys: {
      async list() {
        return (await rows(`SELECT * FROM ${s}.signing_keys ORDER BY created_at, kid`)).map(toSigningKey);
      },
      async insertPending(key, expectedActiveKid) {
        // The partial unique index on pending keys turns a concurrent insert into a conflict.
        const inserted = await rows(
          `INSERT INTO ${s}.signing_keys (kid, algorithm, public_jwk, encrypted_private_jwk, status, created_at)
           SELECT $1, $2, $3::jsonb, $4, 'pending', $5::timestamptz
           WHERE NOT EXISTS (SELECT 1 FROM ${s}.signing_keys WHERE status = 'pending')
             AND (SELECT kid FROM ${s}.signing_keys WHERE status = 'active' LIMIT 1) IS NOT DISTINCT FROM $6::text
           ON CONFLICT DO NOTHING
           RETURNING kid`,
          [key.kid, key.algorithm, json(key.publicJwk), key.encryptedPrivateJwk, iso(key.createdAt), expectedActiveKid],
        );
        return inserted.length === 1;
      },
      async activate(kid, now) {
        const row = await first(
          `WITH promoted AS (
             UPDATE ${s}.signing_keys SET status = 'active', activated_at = $2::timestamptz
             WHERE kid = $1 AND status = 'pending'
             RETURNING kid
           ), demoted AS (
             UPDATE ${s}.signing_keys SET status = 'retiring', retiring_at = $2::timestamptz
             WHERE status = 'active' AND kid <> $1 AND EXISTS (SELECT 1 FROM promoted)
             RETURNING kid
           )
           SELECT (SELECT count(*) FROM promoted)::int AS promoted, (SELECT count(*) FROM demoted)::int AS demoted`,
          [kid, iso(now)],
        );
        return Number(row?.promoted ?? 0) === 1;
      },
      async retire(kid, now) {
        const updated = await rows(
          `UPDATE ${s}.signing_keys SET status = 'retired', retired_at = $2::timestamptz
           WHERE kid = $1 AND status = 'retiring'
           RETURNING kid`,
          [kid, iso(now)],
        );
        return updated.length === 1;
      },
    },

    devices: {
      async listByUser(userId) {
        return (await rows(`SELECT * FROM ${s}.devices WHERE user_id = $1 ORDER BY first_seen_at`, [userId])).map(toDevice);
      },
      async upsert(sighting) {
        await db.query(
          `INSERT INTO ${s}.devices
             (user_id, device_key, first_seen_at, last_seen_at, last_ip, last_country, last_latitude, last_longitude)
           VALUES ($1, $2, $3::timestamptz, $3::timestamptz, $4, $5, $6::double precision, $7::double precision)
           ON CONFLICT (user_id, device_key) DO UPDATE SET
             last_seen_at = EXCLUDED.last_seen_at,
             last_ip = EXCLUDED.last_ip,
             last_country = EXCLUDED.last_country,
             last_latitude = EXCLUDED.last_latitude,
             last_longitude = EXCLUDED.last_longitude`,
          [
            sighting.userId,
            sighting.deviceKey,
            iso(sighting.now),
            sighting.ip,
            sighting.country,
            sighting.latitude,
            sighting.longitude,
          ],
        );
      },
    },

    ephemeral: {
      async set(key, value, ttlSec) {
        await db.query(
          `INSERT INTO ${s}.ephemeral (key, value, expires_at)
           VALUES ($1, $2::jsonb, $3::timestamptz)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
          [key, json(value), expiryIso(ttlSec)],
        );
      },
      async get(key) {
        const row = await first(`SELECT value FROM ${s}.ephemeral WHERE key = $1 AND expires_at > $2::timestamptz`, [
          key,
          nowIso(),
        ]);
        return row ? (row.value as JsonValue) : null;
      },
      async take(key) {
        const row = await first(
          `DELETE FROM ${s}.ephemeral WHERE key = $1 RETURNING value, (expires_at > $2::timestamptz) AS live`,
          [key, nowIso()],
        );
        return row && row.live === true ? (row.value as JsonValue) : null;
      },
      async setIfAbsent(key, ttlSec) {
        // Inserts, or replaces an entry that has already expired. A live entry matches neither branch.
        const written = await rows(
          `INSERT INTO ${s}.ephemeral AS entry (key, value, expires_at)
           VALUES ($1, 'true'::jsonb, $3::timestamptz)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
             WHERE entry.expires_at <= $2::timestamptz
           RETURNING key`,
          [key, nowIso(), expiryIso(ttlSec)],
        );
        return written.length === 1;
      },
      async increment(key, ttlSec) {
        const row = await first(
          `INSERT INTO ${s}.ephemeral AS entry (key, value, expires_at)
           VALUES ($1, '1'::jsonb, $3::timestamptz)
           ON CONFLICT (key) DO UPDATE SET
             value = CASE
               WHEN entry.expires_at <= $2::timestamptz OR jsonb_typeof(entry.value) <> 'number' THEN '1'::jsonb
               ELSE to_jsonb((entry.value #>> '{}')::bigint + 1)
             END,
             expires_at = CASE
               WHEN entry.expires_at <= $2::timestamptz THEN EXCLUDED.expires_at
               ELSE entry.expires_at
             END
           RETURNING value`,
          [key, nowIso(), expiryIso(ttlSec)],
        );
        return Number(row?.value ?? 0);
      },
      async purgeExpired() {
        const deleted = await rows(`DELETE FROM ${s}.ephemeral WHERE expires_at <= $1::timestamptz RETURNING key`, [nowIso()]);
        return deleted.length;
      },
    },
  };

  return { ...adapter, ...options.stores };
}
