import { AccountError } from '@koshirepo/auth-core';
import type { CredentialStore } from '../adapters/types.js';
import type { ResolvedConfig } from '../config.js';
import type { Clock } from '../util/clock.js';
import { randomToken } from '../util/crypto.js';

export interface PasswordServiceOptions {
  config: NonNullable<ResolvedConfig['password']>;
  credentials: CredentialStore;
  clock: Clock;
}

export class PasswordService {
  private dummyHash: string | null = null;

  constructor(private readonly options: PasswordServiceOptions) {}

  /** Throws `PASSWORD_POLICY_VIOLATION` with `details.reason` if the password is not acceptable. */
  async assertAcceptable(password: unknown, info: { identifier?: string } = {}): Promise<void> {
    const { config } = this.options;
    const reject = (reason: string): never => {
      throw new AccountError('PASSWORD_POLICY_VIOLATION', { details: { reason } });
    };
    if (typeof password !== 'string') reject('not_a_string');
    const text = password as string;
    // Count code points, so one emoji is one character.
    const length = [...text].length;
    if (length < config.minLength) reject('too_short');
    if (length > config.maxLength) reject('too_long');
    if (config.check) {
      const verdict = await config.check(text, info);
      if (typeof verdict === 'string' && verdict.length > 0) reject('rejected');
    }
  }

  /** Hashes and stores a password. The caller checks the policy first. */
  async set(userId: string, password: string): Promise<void> {
    const hash = await this.options.config.hasher.hash(password);
    await this.options.credentials.setPasswordHash(userId, hash, this.options.clock.now());
  }

  /**
   * Checks a password for a user.
   *
   * When the user is unknown or has no password, a fixed dummy hash is verified instead, so the
   * work done, and therefore the response time, does not reveal whether the account exists.
   */
  async verify(userId: string | null, password: string): Promise<boolean> {
    const { config, credentials, clock } = this.options;
    // An over-long password cannot be the right one. Skipping the hash bounds the cost of junk input.
    if (typeof password !== 'string' || [...password].length > config.maxLength) return false;

    const stored = userId === null ? null : await credentials.getPasswordHash(userId);
    const hash = stored ?? (await this.getDummyHash());
    let matches = false;
    try {
      matches = await config.hasher.verify(hash, password);
    } catch {
      matches = false;
    }
    if (stored === null || userId === null || !matches) return false;

    if (config.hasher.needsRehash(stored)) {
      await credentials.setPasswordHash(userId, await config.hasher.hash(password), clock.now());
    }
    return true;
  }

  private async getDummyHash(): Promise<string> {
    // The finished value is kept, not the promise: Workers cannot await another request's work.
    this.dummyHash ??= await this.options.config.hasher.hash(randomToken());
    return this.dummyHash;
  }
}
