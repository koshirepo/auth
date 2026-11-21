CREATE TABLE IF NOT EXISTS auth_schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL) STRICT;

CREATE TABLE auth_users (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL UNIQUE,
  roles TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  attributes TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE auth_password_credentials (
  user_id TEXT PRIMARY KEY,
  hash TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE auth_totp_credentials (
  user_id TEXT PRIMARY KEY,
  encrypted_secret TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  digits INTEGER NOT NULL,
  period INTEGER NOT NULL,
  last_used_step INTEGER NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

CREATE TABLE auth_recovery_codes (
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, code_hash)
) STRICT;

CREATE TABLE auth_passkeys (
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
) STRICT;

CREATE INDEX auth_passkeys_user_id ON auth_passkeys (user_id);

CREATE TABLE auth_sessions (
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
) STRICT;

CREATE INDEX auth_sessions_user_id ON auth_sessions (user_id);

CREATE INDEX auth_sessions_expires_at ON auth_sessions (expires_at);

CREATE TABLE auth_refresh_tokens (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES auth_sessions (id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
) STRICT;

CREATE INDEX auth_refresh_tokens_session_id ON auth_refresh_tokens (session_id);

CREATE TABLE auth_devices (
  user_id TEXT NOT NULL,
  device_key TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  last_ip TEXT,
  last_country TEXT,
  last_latitude REAL,
  last_longitude REAL,
  PRIMARY KEY (user_id, device_key)
) STRICT;

CREATE TABLE auth_signing_keys (
  kid TEXT PRIMARY KEY,
  algorithm TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  encrypted_private_jwk TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'retiring', 'retired')),
  created_at TEXT NOT NULL,
  activated_at TEXT,
  retiring_at TEXT,
  retired_at TEXT
) STRICT;

CREATE UNIQUE INDEX auth_signing_keys_one_pending ON auth_signing_keys (status) WHERE status = 'pending';

CREATE TABLE auth_audit_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  at TEXT NOT NULL,
  outcome TEXT NOT NULL,
  user_id TEXT,
  session_id TEXT,
  event TEXT NOT NULL
) STRICT;

CREATE INDEX auth_audit_events_at ON auth_audit_events (at DESC);

CREATE INDEX auth_audit_events_user_id ON auth_audit_events (user_id, at DESC);

CREATE TABLE auth_ephemeral (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX auth_ephemeral_expires_at ON auth_ephemeral (expires_at);

INSERT INTO auth_schema_migrations (id, applied_at) VALUES ('0001_initial', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
