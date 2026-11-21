import type { AssuranceLevel, AuditEvent, AuditEventType, AuthMethod, JsonObject, JsonValue, RevokeReason } from '@koshirepo/auth-core';

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

export interface User {
  id: string;
  /** The login identifier, already normalised (by default trimmed and lower-cased). */
  identifier: string;
  roles: string[];
  status: 'active' | 'disabled';
  attributes: JsonObject;
  createdAt: Date;
}

export interface UserStore {
  findById(id: string): Promise<User | null>;
  findByIdentifier(identifier: string): Promise<User | null>;
  /** Returns null when the identifier is already taken. */
  create(user: User): Promise<User | null>;
  /** Returns null when the user does not exist. */
  update(id: string, patch: Partial<Pick<User, 'roles' | 'status' | 'attributes'>>): Promise<User | null>;
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

export interface TotpCredential {
  userId: string;
  /** The seed, encrypted by the server before it reaches the adapter. */
  encryptedSecret: string;
  algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512';
  digits: number;
  period: number;
  /** The last time step a code was accepted for. Codes for this step or earlier are replays. */
  lastUsedStep: number;
  createdAt: Date;
}

export interface PasskeyCredential {
  id: string;
  userId: string;
  /** The WebAuthn credential id, base64url. Unique across all users. */
  credentialId: string;
  /** The COSE public key, base64url. */
  publicKey: string;
  counter: number;
  transports: string[];
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  name: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export interface CredentialStore {
  /** The PHC-format password hash, or null when the user has no password. */
  getPasswordHash(userId: string): Promise<string | null>;
  setPasswordHash(userId: string, hash: string, now: Date): Promise<void>;

  getTotp(userId: string): Promise<TotpCredential | null>;
  /** Replaces any existing TOTP credential of the user. */
  saveTotp(credential: TotpCredential): Promise<void>;
  /** Atomic. Advances the last accepted TOTP step only if `step` is later. False means replay. */
  advanceTotpStep(userId: string, step: number): Promise<boolean>;
  deleteTotp(userId: string): Promise<boolean>;

  /** Replaces all of the user's recovery codes. An empty list removes them. */
  replaceRecoveryCodes(userId: string, codeHashes: readonly string[], now: Date): Promise<void>;
  /** Atomic. Removes the matching unused recovery code. False means unknown or already used. */
  consumeRecoveryCode(userId: string, codeHash: string, now: Date): Promise<boolean>;
  countRecoveryCodes(userId: string): Promise<number>;

  listPasskeys(userId: string): Promise<PasskeyCredential[]>;
  findPasskeyByCredentialId(credentialId: string): Promise<PasskeyCredential | null>;
  /** Returns false when the credential id is already registered. */
  savePasskey(credential: PasskeyCredential): Promise<boolean>;
  updatePasskeyUsage(id: string, counter: number, now: Date): Promise<void>;
  deletePasskey(userId: string, id: string): Promise<boolean>;
}

// ---------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------

/** One login. Every refresh token issued during its lifetime belongs to it. */
export interface Session {
  id: string;
  userId: string;
  createdAt: Date;
  lastUsedAt: Date;
  /** Absolute expiry. Refreshing does not extend it. */
  expiresAt: Date;
  /** Time of the last interactive authentication, including step-up. */
  authenticatedAt: Date;
  methods: AuthMethod[];
  assurance: AssuranceLevel;
  /** Thumbprint of the DPoP key this session is bound to, or null when unbound. */
  dpopJkt: string | null;
  ip: string | null;
  userAgent: string | null;
  revokedAt: Date | null;
  revokedReason: RevokeReason | null;
}

export interface RefreshTokenRecord {
  id: string;
  sessionId: string;
  /** SHA-256 of the token. The token itself is never stored. */
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
}

export interface NewRefreshToken {
  id: string;
  tokenHash: string;
  createdAt: Date;
  expiresAt: Date;
}

export interface SessionStore {
  create(session: Session, firstToken: NewRefreshToken): Promise<void>;
  findById(id: string): Promise<Session | null>;
  findByRefreshTokenHash(tokenHash: string): Promise<{ session: Session; token: RefreshTokenRecord } | null>;
  /**
   * Atomic. Marks `tokenId` used, inserts `next` into the same session and updates the session's
   * `lastUsedAt`, but only if `tokenId` is still unused. Otherwise changes nothing and returns
   * false. Of two concurrent calls for the same token, exactly one returns true.
   */
  rotate(tokenId: string, next: NewRefreshToken, now: Date): Promise<boolean>;
  /** Returns null when the session does not exist. */
  update(
    sessionId: string,
    patch: { authenticatedAt?: Date; methods?: AuthMethod[]; assurance?: AssuranceLevel },
  ): Promise<Session | null>;
  /** Sessions of the user that are not revoked, newest first. */
  listByUser(userId: string): Promise<Session[]>;
  /** Returns true if this call revoked the session, false if it was already revoked or unknown. */
  revoke(sessionId: string, reason: RevokeReason, now: Date): Promise<boolean>;
  /** Revokes every live session of the user and returns how many were revoked. */
  revokeAllForUser(userId: string, reason: RevokeReason, now: Date, exceptSessionId?: string): Promise<number>;
  /** Deletes sessions, with their tokens, that expired or were revoked before `before`. */
  deleteExpired(before: Date): Promise<number>;
}

// ---------------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------------

export interface AuditFilter {
  userId?: string;
  type?: AuditEventType;
  /** ISO 8601, inclusive. */
  since?: string;
  limit?: number;
}

export interface AuditStore {
  append(event: AuditEvent): Promise<void>;
  /** Newest first. */
  list(filter?: AuditFilter): Promise<AuditEvent[]>;
}

// ---------------------------------------------------------------------------------------------
// Signing keys
// ---------------------------------------------------------------------------------------------

export type SigningAlgorithm = 'EdDSA' | 'Ed25519' | 'ES256';

export type SigningKeyStatus = 'pending' | 'active' | 'retiring' | 'retired';

export interface StoredSigningKey {
  /** RFC 7638 thumbprint of the public key. */
  kid: string;
  algorithm: SigningAlgorithm;
  publicJwk: JsonObject;
  /** The private JWK, encrypted by the server before it reaches the adapter. */
  encryptedPrivateJwk: string;
  status: SigningKeyStatus;
  createdAt: Date;
  activatedAt: Date | null;
  retiringAt: Date | null;
  retiredAt: Date | null;
}

export interface SigningKeyStore {
  list(): Promise<StoredSigningKey[]>;
  /**
   * Atomic. Inserts the key as pending only if no other key is pending and the active key is still
   * `expectedActiveKid` (null meaning there is no active key). Returns false otherwise.
   *
   * The second condition stops an instance with a stale view from starting a rotation that
   * another instance has already completed.
   */
  insertPending(key: StoredSigningKey, expectedActiveKid: string | null): Promise<boolean>;
  /**
   * Atomic. Promotes `kid` from pending to active and moves the current active key, if any, to
   * retiring. Returns false, changing nothing, if `kid` is not pending.
   */
  activate(kid: string, now: Date): Promise<boolean>;
  /** Atomic. Moves `kid` from retiring to retired. Returns false if it is not retiring. */
  retire(kid: string, now: Date): Promise<boolean>;
}

// ---------------------------------------------------------------------------------------------
// Devices (risk scoring)
// ---------------------------------------------------------------------------------------------

/** A device a user has signed in from, identified by its DPoP key thumbprint. */
export interface DeviceRecord {
  userId: string;
  deviceKey: string;
  firstSeenAt: Date;
  lastSeenAt: Date;
  lastIp: string | null;
  lastCountry: string | null;
  lastLatitude: number | null;
  lastLongitude: number | null;
}

export interface DeviceSighting {
  userId: string;
  deviceKey: string;
  ip: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  now: Date;
}

export interface DeviceStore {
  listByUser(userId: string): Promise<DeviceRecord[]>;
  /** Inserts the device, or updates its last-seen fields if it is already known. */
  upsert(sighting: DeviceSighting): Promise<void>;
}

// ---------------------------------------------------------------------------------------------
// Short-lived state
// ---------------------------------------------------------------------------------------------

/**
 * Key-value state with expiry: WebAuthn challenges, MFA tickets, rate-limit counters and replay
 * caches. An expired entry behaves exactly like a missing one.
 */
export interface EphemeralStore {
  set(key: string, value: JsonValue, ttlSec: number): Promise<void>;
  get(key: string): Promise<JsonValue | null>;
  /** Atomic read-and-delete. Of two concurrent calls, at most one gets the value. */
  take(key: string): Promise<JsonValue | null>;
  /** Atomic. Stores a marker and returns true only if the key is not already present. */
  setIfAbsent(key: string, ttlSec: number): Promise<boolean>;
  /**
   * Atomic. Adds one to the counter and returns the new value. The expiry is set when the counter
   * is created and is not extended by later increments.
   */
  increment(key: string, ttlSec: number): Promise<number>;
  /** Deletes expired entries and returns how many were removed. */
  purgeExpired(): Promise<number>;
}

// ---------------------------------------------------------------------------------------------

export interface AuthAdapter {
  users: UserStore;
  credentials: CredentialStore;
  sessions: SessionStore;
  audit: AuditStore;
  keys: SigningKeyStore;
  devices: DeviceStore;
  ephemeral: EphemeralStore;
}
