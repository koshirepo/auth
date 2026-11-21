import { ConfigurationError } from '@koshirepo/auth-core';

/** The one method the Postgres adapter needs from a driver. A `pg` Pool or Client fits as is. */
export interface SqlExecutor {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  query(text: string, params?: unknown[]): Promise<{ rows: any[] }>;
}

export interface Migration {
  id: string;
  /** One SQL statement per entry, so drivers that reject multi-statement queries can run them. */
  statements: string[];
}

/** Validates a schema name and returns it quoted for use in SQL. */
export function quoteSchema(schema: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: 'The schema name may contain only lower-case letters, digits and underscores, and must not start with a digit.',
    });
  }
  return `"${schema}"`;
}

/** The migrations for a schema, in order. */
export function migrations(schema = 'auth'): Migration[] {
  const s = quoteSchema(schema);
  return [
    {
      id: '0001_initial',
      statements: [
        `CREATE TABLE ${s}.users (
          id text PRIMARY KEY,
          identifier text NOT NULL UNIQUE,
          roles jsonb NOT NULL DEFAULT '[]'::jsonb,
          status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
          attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
          created_at timestamptz NOT NULL
        )`,
        `CREATE TABLE ${s}.password_credentials (
          user_id text PRIMARY KEY,
          hash text NOT NULL,
          updated_at timestamptz NOT NULL
        )`,
        `CREATE TABLE ${s}.totp_credentials (
          user_id text PRIMARY KEY,
          encrypted_secret text NOT NULL,
          algorithm text NOT NULL,
          digits integer NOT NULL,
          period integer NOT NULL,
          last_used_step bigint NOT NULL,
          created_at timestamptz NOT NULL
        )`,
        `CREATE TABLE ${s}.recovery_codes (
          user_id text NOT NULL,
          code_hash text NOT NULL,
          created_at timestamptz NOT NULL,
          PRIMARY KEY (user_id, code_hash)
        )`,
        `CREATE TABLE ${s}.passkeys (
          id text PRIMARY KEY,
          user_id text NOT NULL,
          credential_id text NOT NULL UNIQUE,
          public_key text NOT NULL,
          counter bigint NOT NULL,
          transports jsonb NOT NULL DEFAULT '[]'::jsonb,
          device_type text NOT NULL,
          backed_up boolean NOT NULL,
          name text,
          created_at timestamptz NOT NULL,
          last_used_at timestamptz
        )`,
        `CREATE INDEX passkeys_user_id ON ${s}.passkeys (user_id)`,
        `CREATE TABLE ${s}.sessions (
          id text PRIMARY KEY,
          user_id text NOT NULL,
          created_at timestamptz NOT NULL,
          last_used_at timestamptz NOT NULL,
          expires_at timestamptz NOT NULL,
          authenticated_at timestamptz NOT NULL,
          methods jsonb NOT NULL,
          assurance text NOT NULL,
          dpop_jkt text,
          ip text,
          user_agent text,
          revoked_at timestamptz,
          revoked_reason text
        )`,
        `CREATE INDEX sessions_user_id ON ${s}.sessions (user_id)`,
        `CREATE INDEX sessions_expires_at ON ${s}.sessions (expires_at)`,
        `CREATE TABLE ${s}.refresh_tokens (
          id text PRIMARY KEY,
          session_id text NOT NULL REFERENCES ${s}.sessions (id) ON DELETE CASCADE,
          token_hash text NOT NULL UNIQUE,
          created_at timestamptz NOT NULL,
          expires_at timestamptz NOT NULL,
          used_at timestamptz
        )`,
        `CREATE INDEX refresh_tokens_session_id ON ${s}.refresh_tokens (session_id)`,
        `CREATE TABLE ${s}.devices (
          user_id text NOT NULL,
          device_key text NOT NULL,
          first_seen_at timestamptz NOT NULL,
          last_seen_at timestamptz NOT NULL,
          last_ip text,
          last_country text,
          last_latitude double precision,
          last_longitude double precision,
          PRIMARY KEY (user_id, device_key)
        )`,
        `CREATE TABLE ${s}.signing_keys (
          kid text PRIMARY KEY,
          algorithm text NOT NULL,
          public_jwk jsonb NOT NULL,
          encrypted_private_jwk text NOT NULL,
          status text NOT NULL CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
          created_at timestamptz NOT NULL,
          activated_at timestamptz,
          retiring_at timestamptz,
          retired_at timestamptz
        )`,
        // At most one key can be pending. This is what makes concurrent rotations safe.
        `CREATE UNIQUE INDEX signing_keys_one_pending ON ${s}.signing_keys (status) WHERE status = 'pending'`,
        `CREATE TABLE ${s}.audit_events (
          id text PRIMARY KEY,
          type text NOT NULL,
          at timestamptz NOT NULL,
          outcome text NOT NULL,
          user_id text,
          session_id text,
          event jsonb NOT NULL
        )`,
        `CREATE INDEX audit_events_at ON ${s}.audit_events (at DESC)`,
        `CREATE INDEX audit_events_user_id ON ${s}.audit_events (user_id, at DESC)`,
        `CREATE TABLE ${s}.ephemeral (
          key text PRIMARY KEY,
          value jsonb NOT NULL,
          expires_at timestamptz NOT NULL
        )`,
        `CREATE INDEX ephemeral_expires_at ON ${s}.ephemeral (expires_at)`,
      ],
    },
  ];
}

/**
 * Creates the schema if needed and applies every migration that has not been applied yet.
 * Returns the ids it applied. Safe to call on every start.
 *
 * Statements run one at a time without a wrapping transaction, because the executor interface has
 * no transaction API. If a migration fails part-way, fix the cause and drop the schema before
 * retrying, or run the statements from `migrations()` through your own migration tool.
 */
export async function migrate(db: SqlExecutor, options: { schema?: string } = {}): Promise<string[]> {
  const schema = options.schema ?? 'auth';
  const s = quoteSchema(schema);
  await db.query(`CREATE SCHEMA IF NOT EXISTS ${s}`);
  await db.query(
    `CREATE TABLE IF NOT EXISTS ${s}.schema_migrations (id text PRIMARY KEY, applied_at timestamptz NOT NULL)`,
  );
  const { rows } = await db.query(`SELECT id FROM ${s}.schema_migrations`);
  const applied = new Set(rows.map((row) => String(row.id)));
  const newlyApplied: string[] = [];
  for (const migration of migrations(schema)) {
    if (applied.has(migration.id)) continue;
    for (const statement of migration.statements) await db.query(statement);
    await db.query(`INSERT INTO ${s}.schema_migrations (id, applied_at) VALUES ($1, $2::timestamptz)`, [
      migration.id,
      new Date().toISOString(),
    ]);
    newlyApplied.push(migration.id);
  }
  return newlyApplied;
}
