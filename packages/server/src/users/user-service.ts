import { AccountError, AuthenticationError, RequestError, isAuthError, type JsonObject } from '@acme/auth-core';
import type { AuthAdapter, User } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { PasswordService } from '../password/password-service.js';
import type { Throttle } from '../ratelimit/throttle.js';
import type { SessionService } from '../sessions/session-service.js';
import type { Clock } from '../util/clock.js';
import { randomId } from '../util/crypto.js';

export interface UserServiceOptions {
  config: ResolvedConfig;
  adapter: AuthAdapter;
  clock: Clock;
  audit: AuditEmitter;
  throttle: Throttle;
  password: PasswordService | null;
  sessions: SessionService;
}

const MAX_IDENTIFIER_LENGTH = 320;

/**
 * Account primitives. Sign-up pages, email verification and password reset are deliberately not
 * part of the library. Build them on top of these.
 */
export class UserService {
  constructor(private readonly options: UserServiceOptions) {}

  async create(
    input: { identifier: string; password?: string; roles?: string[]; attributes?: JsonObject },
    ctx: RequestContext = {},
  ): Promise<User> {
    const { config, adapter, clock, audit, password } = this.options;
    if (typeof input?.identifier !== 'string') throw new RequestError('REQUEST_INVALID', { details: { field: 'identifier' } });
    const identifier = config.normalizeIdentifier(input.identifier);
    if (identifier.length === 0 || identifier.length > MAX_IDENTIFIER_LENGTH) {
      throw new RequestError('REQUEST_INVALID', { details: { field: 'identifier' } });
    }
    if (input.password !== undefined) {
      if (!password) throw new RequestError('REQUEST_INVALID', { details: { reason: 'password_login_disabled' } });
      await password.assertAcceptable(input.password, { identifier });
    }

    const user = await adapter.users.create({
      id: randomId(),
      identifier,
      roles: [...(input.roles ?? [])],
      status: 'active',
      attributes: input.attributes ?? {},
      createdAt: clock.now(),
    });
    if (!user) throw new AccountError('IDENTIFIER_TAKEN');
    if (input.password !== undefined && password) await password.set(user.id, input.password);
    await audit.emit('user.created', { outcome: 'success', userId: user.id, data: {} }, ctx);
    return user;
  }

  async get(userId: string): Promise<User | null> {
    return this.options.adapter.users.findById(userId);
  }

  /** Sets a password without knowing the old one, and ends every session of the user. For administrators and reset flows. */
  async setPassword(userId: string, newPassword: string, ctx: RequestContext = {}): Promise<void> {
    const { audit, sessions } = this.options;
    const { user, password } = await this.requirePasswordUser(userId);
    await password.assertAcceptable(newPassword, { identifier: user.identifier });
    await password.set(userId, newPassword);
    await audit.emit('password.changed', { outcome: 'success', userId, data: { by: 'admin' } }, ctx);
    await sessions.revokeAll(userId, { reason: 'password_changed' }, ctx);
  }

  /**
   * Changes a password given the current one, and ends the user's other sessions. Pass
   * `keepSessionId` to keep the session that made the change.
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    options: { keepSessionId?: string } = {},
    ctx: RequestContext = {},
  ): Promise<void> {
    const { config, audit, throttle, sessions } = this.options;
    const { user, password } = await this.requirePasswordUser(userId);
    const key = `password:${userId}`;
    try {
      await throttle.assertNotBlocked(key);
    } catch (error) {
      if (isAuthError(error)) {
        await audit.emit('rate_limit.exceeded', { outcome: 'failure', reason: error.code, userId, data: { scope: 'password' } }, ctx);
      }
      throw error;
    }
    if (!(await password.verify(userId, currentPassword))) {
      await throttle.recordFailure(key, config.rateLimits.login);
      await audit.emit('password.changed', { outcome: 'failure', reason: 'INVALID_CREDENTIALS', userId, data: { by: 'user' } }, ctx);
      throw new AuthenticationError('INVALID_CREDENTIALS');
    }
    await password.assertAcceptable(newPassword, { identifier: user.identifier });
    await password.set(userId, newPassword);
    await throttle.reset(key);
    await audit.emit('password.changed', { outcome: 'success', userId, data: { by: 'user' } }, ctx);
    await sessions.revokeAll(
      userId,
      { reason: 'password_changed', ...(options.keepSessionId !== undefined ? { except: options.keepSessionId } : {}) },
      ctx,
    );
  }

  /** Blocks sign-in and ends every session of the user. */
  async disable(userId: string, ctx: RequestContext = {}): Promise<void> {
    const { adapter, audit, sessions } = this.options;
    if (!(await adapter.users.update(userId, { status: 'disabled' }))) throw new AccountError('USER_NOT_FOUND');
    await audit.emit('user.disabled', { outcome: 'success', userId, data: {} }, ctx);
    await sessions.revokeAll(userId, { reason: 'user_disabled' }, ctx);
  }

  private async requirePasswordUser(userId: string): Promise<{ user: User; password: PasswordService }> {
    const { adapter, password } = this.options;
    if (!password) throw new RequestError('REQUEST_INVALID', { details: { reason: 'password_login_disabled' } });
    const user = await adapter.users.findById(userId);
    if (!user) throw new AccountError('USER_NOT_FOUND');
    return { user, password };
  }
}
