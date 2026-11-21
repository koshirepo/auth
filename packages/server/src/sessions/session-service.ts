import {
  AuthenticationError,
  SessionError,
  type AssuranceLevel,
  type AuthMethod,
  type PublicUser,
  type RevokeReason,
  type SessionInfo,
} from '@acme/auth-core';
import type { AuthAdapter, RefreshTokenRecord, Session, User } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { DpopGuard } from '../dpop/guard.js';
import type { TokenService } from '../tokens/token-service.js';
import { toEpochSec, type Clock } from '../util/clock.js';
import { randomId, randomToken, sha256Base64Url } from '../util/crypto.js';
import { assuranceFor, toPublicUser, toSessionInfo } from './views.js';

/** An access token with the user and session it belongs to. Times are epoch seconds. */
export interface AccessGrant {
  accessToken: string;
  accessTokenExpiresAt: number;
  user: PublicUser;
  session: SessionInfo;
}

/**
 * The result of a completed login or refresh. The HTTP layer moves `refreshToken` into the
 * cookie. It must never be put in a response body or a log.
 */
export type Authenticated = AccessGrant & {
  status: 'authenticated';
  refreshToken: string;
  refreshTokenExpiresAt: number;
};

export interface SessionServiceOptions {
  config: ResolvedConfig;
  adapter: AuthAdapter;
  clock: Clock;
  audit: AuditEmitter;
  tokens: TokenService;
  dpop: DpopGuard;
}

const MAX_REFRESH_TOKEN_LENGTH = 512;
const MAX_USER_AGENT_LENGTH = 256;

/** Refresh tokens are 256 random bits, so a fast hash is enough to store them safely. */
export function hashRefreshToken(token: string): Promise<string> {
  return sha256Base64Url(token);
}

export class SessionService {
  constructor(private readonly options: SessionServiceOptions) {}

  /** Creates a session for a user who has just authenticated and issues its first tokens. */
  async start(
    user: User,
    input: { methods: AuthMethod[]; assurance: AssuranceLevel; dpopJkt: string | null },
    ctx: RequestContext,
  ): Promise<Authenticated> {
    const { config, adapter, clock, audit, tokens } = this.options;
    const now = clock.now();
    const session: Session = {
      id: randomId(),
      userId: user.id,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + config.sessions.ttlSec * 1000),
      authenticatedAt: now,
      methods: [...input.methods],
      assurance: input.assurance,
      dpopJkt: input.dpopJkt,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent?.slice(0, MAX_USER_AGENT_LENGTH) ?? null,
      revokedAt: null,
      revokedReason: null,
    };
    const refreshToken = randomToken();
    const refreshExpiresAt = this.refreshExpiry(session, now);
    await adapter.sessions.create(session, {
      id: randomId(),
      tokenHash: await hashRefreshToken(refreshToken),
      createdAt: now,
      expiresAt: refreshExpiresAt,
    });
    const issued = await tokens.issue(user, session);
    await audit.emit(
      'session.created',
      {
        outcome: 'success',
        userId: user.id,
        sessionId: session.id,
        data: { methods: session.methods, assurance: session.assurance, deviceBound: session.dpopJkt !== null },
      },
      ctx,
    );
    return {
      status: 'authenticated',
      ...issued,
      refreshToken,
      refreshTokenExpiresAt: toEpochSec(refreshExpiresAt),
      user: toPublicUser(user),
      session: toSessionInfo(session),
    };
  }

  /**
   * Exchanges a refresh token for a new one and a new access token.
   *
   * A refresh token works once. Presenting one that was already used revokes the whole session,
   * because it means the token exists in two places.
   */
  async refresh(refreshToken: string, ctx: RequestContext = {}): Promise<Authenticated> {
    const { adapter, clock, audit, tokens, dpop } = this.options;
    if (typeof refreshToken !== 'string' || refreshToken.length === 0) throw new SessionError('REFRESH_TOKEN_MISSING');
    if (refreshToken.length > MAX_REFRESH_TOKEN_LENGTH) throw new SessionError('REFRESH_TOKEN_INVALID');

    const found = await adapter.sessions.findByRefreshTokenHash(await hashRefreshToken(refreshToken));
    if (!found) throw new SessionError('REFRESH_TOKEN_INVALID');
    const { session, token } = found;
    const ids = { userId: session.userId, sessionId: session.id };
    const now = clock.now();

    if (token.usedAt !== null) return this.rejectReuse(session, token, ctx);
    if (session.revokedAt !== null) throw new SessionError('SESSION_REVOKED');
    if (session.expiresAt.getTime() <= now.getTime()) throw new SessionError('SESSION_EXPIRED');
    if (token.expiresAt.getTime() <= now.getTime()) throw new SessionError('REFRESH_TOKEN_EXPIRED');

    // A bound session can only be refreshed by the device that holds its key. The token is not
    // consumed on failure, so someone holding only a stolen cookie cannot burn the real user's token.
    if (session.dpopJkt !== null) await dpop.requireKey(ctx, session.dpopJkt, 'refresh', ids);

    const user = await adapter.users.findById(session.userId);
    if (!user || user.status !== 'active') {
      await this.revoke(session.id, 'user_disabled', ctx);
      throw new AuthenticationError('ACCOUNT_DISABLED');
    }

    const nextToken = randomToken();
    const nextId = randomId();
    const refreshExpiresAt = this.refreshExpiry(session, now);
    const rotated = await adapter.sessions.rotate(
      token.id,
      { id: nextId, tokenHash: await hashRefreshToken(nextToken), createdAt: now, expiresAt: refreshExpiresAt },
      now,
    );
    // Losing the compare-and-set means another request used this token between our read and our write.
    if (!rotated) return this.rejectReuse(session, token, ctx);

    const live: Session = { ...session, lastUsedAt: now };
    const issued = await tokens.issue(user, live);
    await audit.emit('session.refreshed', { outcome: 'success', ...ids, data: { refreshTokenId: nextId } }, ctx);
    return {
      status: 'authenticated',
      ...issued,
      refreshToken: nextToken,
      refreshTokenExpiresAt: toEpochSec(refreshExpiresAt),
      user: toPublicUser(user),
      session: toSessionInfo(live),
    };
  }

  /**
   * Records a fresh authentication on an existing session and issues an access token that
   * reflects it. The refresh token is not rotated.
   */
  async elevate(
    sessionId: string,
    method: AuthMethod,
    options: { passkeyUserVerified?: boolean } = {},
    ctx: RequestContext = {},
  ): Promise<AccessGrant> {
    const { adapter, clock, audit, tokens } = this.options;
    const session = await this.requireLive(sessionId);
    const user = await adapter.users.findById(session.userId);
    if (!user || user.status !== 'active') throw new AuthenticationError('ACCOUNT_DISABLED');

    const methods = [...new Set<AuthMethod>([...session.methods, method])];
    const assurance = assuranceFor(methods, {
      previous: session.assurance,
      ...(options.passkeyUserVerified !== undefined ? { passkeyUserVerified: options.passkeyUserVerified } : {}),
    });
    const updated = await adapter.sessions.update(sessionId, { authenticatedAt: clock.now(), methods, assurance });
    if (!updated) throw new SessionError('SESSION_REVOKED');

    const issued = await tokens.issue(user, updated);
    await audit.emit(
      'session.reauthenticated',
      { outcome: 'success', userId: user.id, sessionId, data: { method, assurance } },
      ctx,
    );
    return { ...issued, user: toPublicUser(user), session: toSessionInfo(updated) };
  }

  /** The session if it exists, is not revoked and has not expired. Throws otherwise. */
  async requireLive(sessionId: string): Promise<Session> {
    const session = await this.options.adapter.sessions.findById(sessionId);
    if (!session || session.revokedAt !== null) throw new SessionError('SESSION_REVOKED');
    if (session.expiresAt.getTime() <= this.options.clock.nowMs()) throw new SessionError('SESSION_EXPIRED');
    return session;
  }

  async get(sessionId: string): Promise<SessionInfo | null> {
    const session = await this.options.adapter.sessions.findById(sessionId);
    return session ? toSessionInfo(session) : null;
  }

  /** The user's sessions that are neither revoked nor expired, newest first. */
  async list(userId: string, currentSessionId?: string): Promise<SessionInfo[]> {
    const now = this.options.clock.nowMs();
    const sessions = await this.options.adapter.sessions.listByUser(userId);
    return sessions
      .filter((session) => session.expiresAt.getTime() > now)
      .map((session) => toSessionInfo(session, currentSessionId));
  }

  /** Revokes one session. Does nothing if it is unknown or already revoked. */
  async revoke(sessionId: string, reason: RevokeReason = 'admin', ctx: RequestContext = {}): Promise<void> {
    const { adapter, clock, audit } = this.options;
    const session = await adapter.sessions.findById(sessionId);
    if (!session) return;
    if (await adapter.sessions.revoke(sessionId, reason, clock.now())) {
      await audit.emit(
        'session.revoked',
        { outcome: 'success', userId: session.userId, sessionId, data: { revokeReason: reason, count: 1 } },
        ctx,
      );
    }
  }

  /** Revokes every session of a user, optionally keeping one. Returns how many were revoked. */
  async revokeAll(
    userId: string,
    options: { except?: string; reason?: RevokeReason } = {},
    ctx: RequestContext = {},
  ): Promise<number> {
    const { adapter, clock, audit } = this.options;
    const reason = options.reason ?? 'admin';
    const count = await adapter.sessions.revokeAllForUser(userId, reason, clock.now(), options.except);
    if (count > 0) {
      await audit.emit('session.revoked', { outcome: 'success', userId, data: { revokeReason: reason, count } }, ctx);
    }
    return count;
  }

  /**
   * Ends the session a refresh token belongs to, or all of that user's sessions. An unknown or
   * missing token is ignored, so logging out always succeeds from the caller's point of view.
   */
  async logout(refreshToken: string | undefined, options: { all?: boolean } = {}, ctx: RequestContext = {}): Promise<void> {
    if (typeof refreshToken !== 'string' || refreshToken.length === 0 || refreshToken.length > MAX_REFRESH_TOKEN_LENGTH) {
      return;
    }
    const found = await this.options.adapter.sessions.findByRefreshTokenHash(await hashRefreshToken(refreshToken));
    if (!found) return;
    if (options.all) await this.revokeAll(found.session.userId, { reason: 'logout_all' }, ctx);
    else await this.revoke(found.session.id, 'logout', ctx);
  }

  private refreshExpiry(session: Session, now: Date): Date {
    const idleLimit = now.getTime() + this.options.config.sessions.idleTtlSec * 1000;
    return new Date(Math.min(idleLimit, session.expiresAt.getTime()));
  }

  private async rejectReuse(session: Session, token: RefreshTokenRecord, ctx: RequestContext): Promise<never> {
    const { adapter, clock, audit } = this.options;
    const ids = { userId: session.userId, sessionId: session.id };
    const revoked = await adapter.sessions.revoke(session.id, 'refresh_reuse', clock.now());
    await audit.emit(
      'session.refresh_reuse_detected',
      { outcome: 'failure', reason: 'REFRESH_TOKEN_REUSED', ...ids, data: { refreshTokenId: token.id } },
      ctx,
    );
    if (revoked) {
      await audit.emit(
        'session.revoked',
        { outcome: 'success', ...ids, data: { revokeReason: 'refresh_reuse', count: 1 } },
        ctx,
      );
    }
    throw new SessionError('REFRESH_TOKEN_REUSED');
  }
}
