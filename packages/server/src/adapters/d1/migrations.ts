import { ConfigurationError } from '@koshirepo/auth-core';

/** The parts of a D1 prepared statement this adapter uses. */
export interface D1StatementLike {
  // The return type is loose so that Cloudflare's own `D1PreparedStatement` fits without a dependency on its types.
  bind(...values: unknown[]): D1StatementLike;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  all(): Promise<{ results?: any[] }>;
  run(): Promise<unknown>;
}

/** The parts of a D1 binding this adapter uses. `env.DB` fits as is. */
export interface D1DatabaseLike {
  prepare(query: string): D1StatementLike;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  batch(statements: any[]): Promise<{ results?: any[] }[]>;
}

export interface D1Migration {
  id: string;
  /** One SQL statement per entry. */
  statements: string[];
}

/**
 * Validates a table prefix. D1 has no schemas, so a prefix is what keeps these tables apart from
 * your application's. It ends up in SQL text, so only a safe alphabet is allowed.
 */
export function checkTablePrefix(prefix: string): string {
  if (!/^[a-z_][a-z0-9_]{0,40}$/.test(prefix)) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: 'The table prefix may contain only lower-case letters, digits and underscores, and must not start with a digit.',
    });
  }
  return prefix;
}

/** The migrations for a table prefix, in order. */
export function migrations(tablePrefix = 'auth_'): D1Migration[] {
  const p = checkTablePrefix(tablePrefix);
  return [
    {
      id: '0001_initial',
      statements: [
        `CREATE TABLE ${p}users (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL UNIQUE,
  roles TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  attributes TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
) STRICT`,
        `CREATE TABLE ${p}password_credentials (
  user_id TEXT PRIMARY KEY,
  hash TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT`,
        `CREATE TABLE ${p}totp_credentials (
  user_id TEXT PRIMARY KEY,
  encrypted_secret TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  digits INTEGER NOT NULL,
  period INTEGER NOT NULL,
  last_used_step INTEGER NOT NULL,
  created_at TEXT NOT NULL
) STRICT`,
        `CREATE TABLE ${p}recovery_codes (
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, code_hash)
) STRICT`,
        `CREATE TABLE ${p}passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT NOT NULL DEFAULT '[]',
  device_type TEXT NOT NULL,
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  name TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
) STRICT`,
        `CREATE INDEX ${p}passkeys_user_id ON ${p}passkeys (user_id)`,
        `CREATE TABLE ${p}sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  authenticated_at TEXT NOT NULL,
  methods TEXT NOT NULL,
  assurance TEXT NOT NULL,
  dpop_jkt TEXT,
  ip TEXT,
  user_agent TEXT,
  revoked_at TEXT,
  revoked_reason TEXT
) STRICT`,
        `CREATE INDEX ${p}sessions_user_id ON ${p}sessions (user_id)`,
        `CREATE INDEX ${p}sessions_expires_at ON ${p}sessions (expires_at)`,
        `CREATE TABLE ${p}refresh_tokens (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES ${p}sessions (id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
) STRICT`,
        `CREATE INDEX ${p}refresh_tokens_session_id ON ${p}refresh_tokens (session_id)`,
        `CREATE TABLE ${p}devices (
  user_id TEXT NOT NULL,
  device_key TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_ip TEXT,
  last_country TEXT,
  last_latitude REAL,
  last_longitude REAL,
  PRIMARY KEY (user_id, device_key)
) STRICT`,
        `CREATE TABLE ${p}signing_keys (
  kid TEXT PRIMARY KEY,
  algorithm TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  encrypted_private_jwk TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
  created_at TEXT NOT NULL,
  activated_at TEXT,
  retiring_at TEXT,
  retired_at TEXT
) STRICT`,
        // At most one key can be pending. This is what makes concurrent rotations safe.
        `CREATE UNIQUE INDEX ${p}signing_keys_one_pending ON ${p}signing_keys (status) WHERE status = 'pending'`,
        `CREATE TABLE ${p}audit_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  at TEXT NOT NULL,
  outcome TEXT NOT NULL,
  user_id TEXT,
  session_id TEXT,
  event TEXT NOT NULL
) STRICT`,
        `CREATE INDEX ${p}audit_events_at ON ${p}audit_events (at DESC)`,
        `CREATE INDEX ${p}audit_events_user_id ON ${p}audit_events (user_id, at DESC)`,
        `CREATE TABLE ${p}ephemeral (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT`,
        `CREATE INDEX ${p}ephemeral_expires_at ON ${p}ephemeral (expires_at)`,
      ],
    },
  ];
}

const NOW_SQL = `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`;

const trackingTable = (p: string) =>
  `CREATE TABLE IF NOT EXISTS ${p}schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL) STRICT`;

const recordMigration = (p: string, id: string) =>
  `INSERT INTO ${p}schema_migrations (id, applied_at) VALUES ('${id}', ${NOW_SQL})`;

/**
 * The whole schema as one SQL file, for `wrangler d1 migrations apply`. It records itself, so
 * `migrate()` and the file can be mixed without applying anything twice.
 */
export function migrationSql(tablePrefix = 'auth_'): string {
  const p = checkTablePrefix(tablePrefix);
  const statements = [trackingTable(p)];
  for (const migration of migrations(p)) {
    statements.push(...migration.statements, recordMigration(p, migration.id));
  }
  return `${statements.join(';\n\n')};\n`;
}

/**
 * Applies every migration that has not been applied yet and returns the ids it applied. Each
 * migration runs in one D1 batch, which is a transaction, so a failure leaves nothing behind and
 * two concurrent runs cannot both apply it.
 *
 * Run it from a deploy step or an admin route, not on every request.
 */
export async function migrate(db: D1DatabaseLike, options: { tablePrefix?: string } = {}): Promise<string[]> {
  const p = checkTablePrefix(options.tablePrefix ?? 'auth_');
  await db.prepare(trackingTable(p)).run();
  const { results } = await db.prepare(`SELECT id FROM ${p}schema_migrations`).all();
  const applied = new Set((results ?? []).map((row) => String(row.id)));
  const newlyApplied: string[] = [];
  for (const migration of migrations(p)) {
    if (applied.has(migration.id)) continue;
    await db.batch([...migration.statements, recordMigration(p, migration.id)].map((statement) => db.prepare(statement)));
    newlyApplied.push(migration.id);
  }
  return newlyApplied;
}
