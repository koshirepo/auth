/**
 * Hashes and verifies passwords. The library ships an Argon2id implementation in
 * `@koshi-repo/auth-server/password/argon2`. Supply your own to use a different library or runtime.
 */
export interface PasswordHasher {
  /** Returns a self-describing hash string (PHC format) that records the parameters used. */
  hash(password: string): Promise<string>;
  /** Must not throw for a malformed hash. Return false instead. */
  verify(hash: string, password: string): Promise<boolean>;
  /** True when `hash` was made with weaker parameters than the hasher currently uses. */
  needsRehash(hash: string): boolean;
}
