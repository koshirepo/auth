import {
  ConfigurationError,
  DpopError,
  SessionError,
  TokenError,
  identityFromClaims,
  isAuthError,
  type AccessTokenClaims,
  type AuthContext,
  type Subject,
} from '@acme/auth-core';
import { SignJWT } from 'jose';
import type { Session, SessionStore, User } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import { validateDpopProof, type ReplayStore } from '../dpop/proof.js';
import type { KeyManager } from '../keys/key-manager.js';
import { toEpochSec, type Clock } from '../util/clock.js';
import { randomId } from '../util/crypto.js';
import { ACCESS_TOKEN_TYPE, RESERVED_CLAIMS, verifyAccessJwt } from './verify.js';

/** The result of verifying an access token. */
export interface VerifiedToken {
  subject: Subject;
  context: AuthContext;
  claims: AccessTokenClaims;
}

export interface VerifyOptions {
  /**
   * Also look the session up and reject the token if the session was revoked or has expired.
   * Costs one store read. Without it, a token works until it expires.
   */
  checkSession?: boolean;
}

export interface TokenServiceOptions {
  config: ResolvedConfig;
  clock: Clock;
  keys: KeyManager;
  audit: AuditEmitter;
  sessions: SessionStore;
  replayStore: ReplayStore;
}

/** Token rejections that suggest tampering rather than routine expiry. */
const ANOMALOUS_REJECTIONS = new Set(['TOKEN_ALGORITHM_NOT_ALLOWED', 'TOKEN_SIGNATURE_INVALID', 'TOKEN_KEY_UNKNOWN']);

export class TokenService {
  constructor(private readonly options: TokenServiceOptions) {}

  /** Signs an access token for a session. */
  async issue(user: User, session: Session): Promise<{ accessToken: string; accessTokenExpiresAt: number }> {
    const { config, clock, keys } = this.options;
    const custom = config.tokens.claims ? await config.tokens.claims(user, session) : {};
    for (const name of Object.keys(custom)) {
      if (RESERVED_CLAIMS.includes(name)) {
        throw new ConfigurationError('CONFIGURATION_INVALID', {
          debug: `tokens.claims returned "${name}", which is a reserved claim.`,
        });
      }
    }

    const { kid, algorithm, privateKey } = await keys.signingKey();
    const issuedAt = clock.nowSec();
    const expiresAt = issuedAt + config.tokens.accessTtlSec;
    const accessToken = await new SignJWT({
      ...custom,
      sid: session.id,
      roles: user.roles,
      amr: session.methods,
      acr: session.assurance,
      auth_time: toEpochSec(session.authenticatedAt),
      ...(session.dpopJkt !== null ? { cnf: { jkt: session.dpopJkt } } : {}),
    })
      .setProtectedHeader({ alg: algorithm, kid, typ: ACCESS_TOKEN_TYPE })
      .setIssuer(config.issuer)
      .setAudience(config.audience.length === 1 ? (config.audience[0] as string) : config.audience)
      .setSubject(user.id)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .setJti(randomId())
      .sign(privateKey);
    return { accessToken, accessTokenExpiresAt: expiresAt };
  }

  /**
   * Verifies an access token: algorithm allowlist, key, signature, issuer, audience, expiry, and,
   * for a token bound to a DPoP key, the proof in `ctx.dpop`.
   */
  async verify(accessToken: string, ctx: RequestContext = {}, options: VerifyOptions = {}): Promise<VerifiedToken> {
    const { config, clock, keys, audit } = this.options;
    let claims: AccessTokenClaims;
    try {
      claims = await verifyAccessJwt(accessToken, {
        issuer: config.issuer,
        audience: config.audience,
        algorithms: config.tokens.allowedAlgorithms,
        clockToleranceSec: config.tokens.clockToleranceSec,
        nowMs: clock.nowMs(),
        getKey: async (header) => {
          const key = typeof header.kid === 'string' ? await keys.verificationKey(header.kid) : null;
          if (!key) throw new TokenError('TOKEN_KEY_UNKNOWN');
          // A key may only ever be used with the algorithm it was created for.
          if (key.algorithm !== header.alg) throw new TokenError('TOKEN_ALGORITHM_NOT_ALLOWED');
          return key.publicKey;
        },
      });
    } catch (error) {
      if (isAuthError(error) && ANOMALOUS_REJECTIONS.has(error.code)) {
        await audit.emit('token.rejected', { outcome: 'failure', reason: error.code, data: {} }, ctx);
      }
      throw error;
    }

    const boundKey = claims.cnf?.jkt;
    if (boundKey !== undefined) {
      try {
        await validateDpopProof(
          {
            proof: ctx.dpop?.proof,
            method: ctx.dpop?.method ?? '',
            url: ctx.dpop?.url ?? '',
            accessToken,
            expectedJkt: boundKey,
          },
          {
            algorithms: config.dpop.algorithms,
            iatToleranceSec: config.dpop.iatToleranceSec,
            replayStore: this.options.replayStore,
            now: () => clock.nowMs(),
          },
        );
      } catch (error) {
        if (isAuthError(error)) {
          await audit.emit(
            'dpop.rejected',
            { outcome: 'failure', reason: error.code, userId: claims.sub, sessionId: claims.sid, data: { during: 'request' } },
            ctx,
          );
        }
        throw error;
      }
    } else if (config.dpop.mode === 'required') {
      // Device binding is mandatory, so a token without a bound key must not be accepted.
      await audit.emit(
        'dpop.rejected',
        { outcome: 'failure', reason: 'DPOP_PROOF_REQUIRED', userId: claims.sub, sessionId: claims.sid, data: { during: 'request' } },
        ctx,
      );
      throw new DpopError('DPOP_PROOF_REQUIRED', { debug: 'The access token is not bound to a key.' });
    }

    if (options.checkSession) {
      const session = await this.options.sessions.findById(claims.sid);
      if (!session || session.revokedAt !== null) throw new SessionError('SESSION_REVOKED');
      if (session.expiresAt.getTime() <= clock.nowMs()) throw new SessionError('SESSION_EXPIRED');
    }

    return { ...identityFromClaims(claims), claims };
  }
}
