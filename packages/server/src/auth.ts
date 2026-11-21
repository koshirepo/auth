import {
  AuthenticationError,
  AuthorizationError,
  PasskeyError,
  RequestError,
  createAuthorizer,
  isAuthError,
  type AccountSecurity,
  type Authorizer,
  type Decision,
  type JsonObject,
  type MfaMethod,
  type PasskeyInfo,
  type RevokeReason,
  type SessionInfo,
} from '@koshirepo/auth-core';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { User } from './adapters/types.js';
import { AuditEmitter } from './audit/emitter.js';
import { resolveConfig, type AuthConfig, type ResolvedConfig } from './config.js';
import type { RequestContext } from './context.js';
import { DpopGuard } from './dpop/guard.js';
import { KeyManager, type JwksDocument } from './keys/key-manager.js';
import { LoginService, type LoginResult } from './login/login-service.js';
import { MfaService, type TotpEnrollment } from './mfa/mfa-service.js';
import { PasskeyService, type PasskeyLoginOptions, type PasskeyRegistrationOptions } from './passkeys/passkey-service.js';
import { PasswordService } from './password/password-service.js';
import { Throttle } from './ratelimit/throttle.js';
import { RiskEngine } from './risk/engine.js';
import { SessionService, type AccessGrant, type Authenticated } from './sessions/session-service.js';
import { TokenService, type VerifiedToken, type VerifyOptions } from './tokens/token-service.js';
import { UserService } from './users/user-service.js';
import { createClock } from './util/clock.js';
import { DataProtector } from './util/protector.js';

/** A factor presented to re-authenticate inside an existing session. */
export type ReauthFactor =
  | { method: 'password'; password: string }
  | { method: MfaMethod; code: string }
  | { method: 'passkey'; challengeId: string; response: AuthenticationResponseJSON };

/**
 * The server API. Every method takes plain values and an optional `RequestContext`, knows nothing
 * about HTTP, and reports failure by throwing an `AuthError` subclass.
 */
export interface Auth<P extends string = string> {
  /** The configuration with every default filled in. */
  readonly config: ResolvedConfig;
  /** The server's clock. Framework adapters use it so that tests with an injected clock stay consistent. */
  readonly clock: { nowMs(): number; nowSec(): number };

  login: {
    withPassword(input: { identifier: string; password: string }, ctx?: RequestContext): Promise<LoginResult>;
    /** Options for a passkey sign-in. The identifier is optional. */
    passkeyOptions(input?: { identifier?: string }, ctx?: RequestContext): Promise<PasskeyLoginOptions>;
    withPasskey(input: { challengeId: string; response: AuthenticationResponseJSON }, ctx?: RequestContext): Promise<LoginResult>;
  };

  mfa: {
    /** Completes a login that returned `mfa_required`. */
    verify(input: { ticket: string; method: MfaMethod; code: string }, ctx?: RequestContext): Promise<Authenticated>;
    beginTotpEnrollment(userId: string): Promise<TotpEnrollment>;
    confirmTotpEnrollment(
      userId: string,
      input: { enrollmentId: string; code: string },
      ctx?: RequestContext,
    ): Promise<{ recoveryCodes: string[] }>;
    removeTotp(userId: string, ctx?: RequestContext): Promise<void>;
    regenerateRecoveryCodes(userId: string, ctx?: RequestContext): Promise<string[]>;
    /** Which second factors and how many passkeys the user has. */
    status(userId: string): Promise<AccountSecurity>;
  };

  passkeys: {
    registrationOptions(userId: string): Promise<PasskeyRegistrationOptions>;
    register(
      userId: string,
      input: { challengeId: string; response: RegistrationResponseJSON; name?: string },
      ctx?: RequestContext,
    ): Promise<PasskeyInfo>;
    list(userId: string): Promise<PasskeyInfo[]>;
    remove(userId: string, passkeyId: string, ctx?: RequestContext): Promise<void>;
  };

  sessions: {
    /** Rotates a refresh token. Reuse of an old token revokes the whole session. */
    refresh(refreshToken: string, ctx?: RequestContext): Promise<Authenticated>;
    /** Step-up: proves a factor again inside a session and returns an access token that reflects it. */
    reauthenticate(sessionId: string, factor: ReauthFactor, ctx?: RequestContext): Promise<AccessGrant>;
    get(sessionId: string): Promise<SessionInfo | null>;
    list(userId: string, currentSessionId?: string): Promise<SessionInfo[]>;
    revoke(sessionId: string, reason?: RevokeReason, ctx?: RequestContext): Promise<void>;
    revokeAll(userId: string, options?: { except?: string; reason?: RevokeReason }, ctx?: RequestContext): Promise<number>;
    /** Ends the session a refresh token belongs to, or all of that user's sessions. Never throws for a bad token. */
    logout(refreshToken: string | undefined, options?: { all?: boolean }, ctx?: RequestContext): Promise<void>;
  };

  tokens: {
    verify(accessToken: string, ctx?: RequestContext, options?: VerifyOptions): Promise<VerifiedToken>;
  };

  keys: {
    /** The public keys to serve at `/.well-known/jwks.json`. */
    jwks(): Promise<JwksDocument>;
    /** Starts a key rotation. The new key begins signing after the publication lead time. */
    rotate(): Promise<{ kid: string }>;
  };

  users: {
    create(
      input: { identifier: string; password?: string; roles?: string[]; attributes?: JsonObject },
      ctx?: RequestContext,
    ): Promise<User>;
    get(userId: string): Promise<User | null>;
    setPassword(userId: string, password: string, ctx?: RequestContext): Promise<void>;
    changePassword(
      userId: string,
      currentPassword: string,
      newPassword: string,
      options?: { keepSessionId?: string },
      ctx?: RequestContext,
    ): Promise<void>;
    disable(userId: string, ctx?: RequestContext): Promise<void>;
  };

  maintenance: {
    /**
     * Deletes expired short-lived state, and sessions that expired or were revoked more than
     * `sessionRetentionDays` ago (default 30). Run it from a scheduled job.
     */
    purgeExpired(options?: { sessionRetentionDays?: number }): Promise<{ ephemeral: number; sessions: number }>;
  };

  /** The pure RBAC and ABAC evaluator built from `access` in the config. */
  authorizer: Authorizer<P>;

  /**
   * Evaluates an access decision for a verified token, with the token's authentication context
   * and the current time filled in. On deny it writes an `access.denied` audit event and throws
   * `FORBIDDEN`.
   */
  authorize(
    token: VerifiedToken,
    action: P,
    resource?: unknown,
    options?: { context?: Record<string, unknown>; request?: RequestContext },
  ): Promise<Decision>;
}

const DAY_MS = 86_400_000;

/** Validates the configuration and wires the services together. Throws `ConfigurationError` if the config is invalid. */
export function createAuth<P extends string = string>(config: AuthConfig<P>): Auth<P> {
  const resolved = resolveConfig(config as AuthConfig);
  const adapter = config.adapter;
  const clock = createClock(config.clock);
  const protector = new DataProtector(config.dataKeys);
  const audit = new AuditEmitter({ ...resolved.audit, clock });
  const throttle = new Throttle(adapter.ephemeral, clock);

  const keys = new KeyManager({
    store: adapter.keys,
    protector,
    clock,
    audit,
    algorithm: resolved.tokens.algorithm,
    rotateEveryDays: resolved.keys.rotateEveryDays,
    publishLeadSec: resolved.keys.publishLeadSec,
    // A key must stay published until the last token it signed has expired everywhere.
    retireAfterSec: resolved.tokens.accessTtlSec + resolved.tokens.clockToleranceSec + resolved.keys.jwksMaxAgeSec,
    cacheTtlSec: resolved.keys.cacheTtlSec,
  });
  const tokens = new TokenService({
    config: resolved,
    clock,
    keys,
    audit,
    sessions: adapter.sessions,
    replayStore: adapter.ephemeral,
  });
  const dpop = new DpopGuard({ config: resolved.dpop, clock, replayStore: adapter.ephemeral, audit });
  const sessions = new SessionService({ config: resolved, adapter, clock, audit, tokens, dpop });
  const password = resolved.password
    ? new PasswordService({ config: resolved.password, credentials: adapter.credentials, clock })
    : null;
  const passkeys = resolved.passkeys ? new PasskeyService({ config: resolved.passkeys, adapter, clock, audit }) : null;
  const mfa = new MfaService({ config: resolved, adapter, clock, audit, protector, throttle });
  const risk = new RiskEngine({ config: resolved.risk, devices: adapter.devices, clock });
  const login = new LoginService({
    config: resolved,
    adapter,
    audit,
    protector,
    throttle,
    dpop,
    password,
    passkeys,
    mfa,
    risk,
    sessions,
  });
  const users = new UserService({ config: resolved, adapter, clock, audit, throttle, password, sessions });
  const authorizer = createAuthorizer<P>({
    ...(config.access?.rbac ? { rbac: config.access.rbac } : {}),
    ...(config.access?.policies ? { policies: config.access.policies } : {}),
  });

  const requirePasskeys = (): PasskeyService => {
    if (!passkeys) throw new RequestError('REQUEST_INVALID', { details: { reason: 'passkeys_disabled' } });
    return passkeys;
  };

  async function reauthenticate(sessionId: string, factor: ReauthFactor, ctx: RequestContext = {}): Promise<AccessGrant> {
    const session = await sessions.requireLive(sessionId);
    const user = await adapter.users.findById(session.userId);
    if (!user || user.status !== 'active') throw new AuthenticationError('ACCOUNT_DISABLED');

    switch (factor?.method) {
      case 'password': {
        if (!password) throw new RequestError('REQUEST_INVALID', { details: { reason: 'password_login_disabled' } });
        const key = `password:${user.id}`;
        try {
          await throttle.assertNotBlocked(key);
        } catch (error) {
          if (isAuthError(error)) {
            await audit.emit(
              'rate_limit.exceeded',
              { outcome: 'failure', reason: error.code, userId: user.id, data: { scope: 'password' } },
              ctx,
            );
          }
          throw error;
        }
        if (typeof factor.password !== 'string' || !(await password.verify(user.id, factor.password))) {
          await throttle.recordFailure(key, resolved.rateLimits.login);
          await audit.emit(
            'session.reauthenticated',
            {
              outcome: 'failure',
              reason: 'INVALID_CREDENTIALS',
              userId: user.id,
              sessionId,
              data: { method: 'pwd', assurance: session.assurance },
            },
            ctx,
          );
          throw new AuthenticationError('INVALID_CREDENTIALS');
        }
        await throttle.reset(key);
        return sessions.elevate(sessionId, 'pwd', {}, ctx);
      }
      case 'totp':
      case 'recovery_code':
        await mfa.verifyCode(user.id, factor.method, factor.code, 'reauthentication', ctx);
        return sessions.elevate(sessionId, factor.method === 'totp' ? 'otp' : 'recovery', {}, ctx);
      case 'passkey': {
        const verified = await requirePasskeys().verifyAuthentication(factor);
        // The assertion must come from one of this user's passkeys, not just any registered one.
        if (verified.userId !== user.id) throw new PasskeyError('PASSKEY_VERIFICATION_FAILED');
        return sessions.elevate(sessionId, 'passkey', { passkeyUserVerified: verified.userVerified }, ctx);
      }
      default:
        throw new RequestError('REQUEST_INVALID', { details: { field: 'method' } });
    }
  }

  return {
    config: resolved,
    clock: { nowMs: () => clock.nowMs(), nowSec: () => clock.nowSec() },

    login: {
      withPassword: (input, ctx) => login.withPassword(input, ctx),
      passkeyOptions: (input, ctx) => login.passkeyOptions(input, ctx),
      withPasskey: (input, ctx) => login.withPasskey(input, ctx),
    },

    mfa: {
      verify: (input, ctx) => login.completeMfa(input, ctx),
      beginTotpEnrollment: (userId) => mfa.beginTotpEnrollment(userId),
      confirmTotpEnrollment: (userId, input, ctx) => mfa.confirmTotpEnrollment(userId, input, ctx),
      removeTotp: (userId, ctx) => mfa.removeTotp(userId, ctx),
      regenerateRecoveryCodes: (userId, ctx) => mfa.regenerateRecoveryCodes(userId, ctx),
      async status(userId) {
        const status = await mfa.status(userId);
        return { ...status, passkeys: passkeys ? (await adapter.credentials.listPasskeys(userId)).length : 0 };
      },
    },

    passkeys: {
      // `async` so that a missing passkey configuration rejects the promise instead of throwing synchronously.
      registrationOptions: async (userId) => requirePasskeys().registrationOptions(userId),
      register: async (userId, input, ctx) => requirePasskeys().register(userId, input, ctx),
      list: async (userId) => (passkeys ? passkeys.list(userId) : []),
      remove: async (userId, passkeyId, ctx) => requirePasskeys().remove(userId, passkeyId, ctx),
    },

    sessions: {
      refresh: (refreshToken, ctx) => sessions.refresh(refreshToken, ctx),
      reauthenticate,
      get: (sessionId) => sessions.get(sessionId),
      list: (userId, currentSessionId) => sessions.list(userId, currentSessionId),
      revoke: (sessionId, reason, ctx) => sessions.revoke(sessionId, reason, ctx),
      revokeAll: (userId, options, ctx) => sessions.revokeAll(userId, options, ctx),
      logout: (refreshToken, options, ctx) => sessions.logout(refreshToken, options, ctx),
    },

    tokens: {
      verify: (accessToken, ctx, options) => tokens.verify(accessToken, ctx, options),
    },

    keys: {
      jwks: () => keys.jwks(),
      rotate: () => keys.rotate(),
    },

    users: {
      create: (input, ctx) => users.create(input, ctx),
      get: (userId) => users.get(userId),
      setPassword: (userId, newPassword, ctx) => users.setPassword(userId, newPassword, ctx),
      changePassword: (userId, currentPassword, newPassword, options, ctx) =>
        users.changePassword(userId, currentPassword, newPassword, options, ctx),
      disable: (userId, ctx) => users.disable(userId, ctx),
    },

    maintenance: {
      async purgeExpired(options = {}) {
        const retentionMs = (options.sessionRetentionDays ?? 30) * DAY_MS;
        return {
          ephemeral: await adapter.ephemeral.purgeExpired(),
          sessions: await adapter.sessions.deleteExpired(new Date(clock.nowMs() - retentionMs)),
        };
      },
    },

    authorizer,

    async authorize(token, action, resource, options = {}) {
      const decision = authorizer.evaluate(token.subject, action, resource, {
        ...options.context,
        auth: token.context,
        now: clock.nowSec(),
      });
      if (decision.effect === 'deny') {
        await audit.emit(
          'access.denied',
          {
            outcome: 'failure',
            reason: 'FORBIDDEN',
            userId: token.subject.id,
            sessionId: token.context.sessionId,
            data: { action, policy: decision.policy, decisionReason: decision.reason },
          },
          options.request,
        );
        throw new AuthorizationError('FORBIDDEN', {
          details: { reason: decision.reason, policy: decision.policy, action },
        });
      }
      return decision;
    },
  };
}
