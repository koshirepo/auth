import {
  AuthenticationError,
  PasskeyError,
  RequestError,
  RiskError,
  isAuthError,
  type AuthMethod,
  type MfaMethod,
} from '@koshirepo/auth-core';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { AuthAdapter, User } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { DpopGuard } from '../dpop/guard.js';
import type { MfaRequired, MfaService } from '../mfa/mfa-service.js';
import type { PasskeyLoginOptions, PasskeyService } from '../passkeys/passkey-service.js';
import type { PasswordService } from '../password/password-service.js';
import type { BackoffPolicy, Throttle } from '../ratelimit/throttle.js';
import type { RiskEngine } from '../risk/engine.js';
import type { GeoLocation } from '../risk/types.js';
import type { Authenticated, SessionService } from '../sessions/session-service.js';
import { assuranceFor } from '../sessions/views.js';
import type { DataProtector } from '../util/protector.js';

/** A login either completes or waits for a second factor. Failures throw. */
export type LoginResult = Authenticated | MfaRequired;

export interface LoginServiceOptions {
  config: ResolvedConfig;
  adapter: AuthAdapter;
  audit: AuditEmitter;
  protector: DataProtector;
  throttle: Throttle;
  dpop: DpopGuard;
  password: PasswordService | null;
  passkeys: PasskeyService | null;
  mfa: MfaService;
  risk: RiskEngine;
  sessions: SessionService;
}

const MAX_IDENTIFIER_LENGTH = 320;

interface FirstFactor {
  loginMethod: 'pwd' | 'passkey';
  /** True when a passkey checked a PIN or biometric, which makes it two factors in one. */
  userVerified: boolean;
  dpopJkt: string | null;
  failures: { account: number; ip: number };
}

interface Completion {
  methods: AuthMethod[];
  dpopJkt: string | null;
  loginMethod: 'pwd' | 'passkey';
  riskScore: number;
  location: GeoLocation | null;
  passkeyUserVerified: boolean;
}

export class LoginService {
  constructor(private readonly options: LoginServiceOptions) {}

  async withPassword(input: { identifier: string; password: string }, ctx: RequestContext = {}): Promise<LoginResult> {
    const { config, adapter, audit, protector, throttle, dpop, password } = this.options;
    if (!password) throw new RequestError('REQUEST_INVALID', { details: { reason: 'password_login_disabled' } });
    if (
      typeof input?.identifier !== 'string' ||
      input.identifier.length === 0 ||
      input.identifier.length > MAX_IDENTIFIER_LENGTH ||
      typeof input.password !== 'string' ||
      input.password.length === 0
    ) {
      throw new RequestError('REQUEST_INVALID');
    }

    const identifier = config.normalizeIdentifier(input.identifier);
    // The raw identifier is never stored or logged: people type passwords into the username box.
    const identifierHash = await protector.keyedHash('login-identifier', identifier);
    const accountKey = `login:id:${identifierHash}`;
    const ipKey = ctx.ip ? `login:ip:${ctx.ip}` : null;
    const accountPolicy: BackoffPolicy = config.rateLimits.login;
    // Many people can share one address, so an address gets more room than an account.
    const ipPolicy: BackoffPolicy = { ...accountPolicy, freeAttempts: accountPolicy.freeAttempts * 4 };

    try {
      await throttle.assertNotBlocked(accountKey);
      if (ipKey) await throttle.assertNotBlocked(ipKey);
    } catch (error) {
      if (isAuthError(error)) {
        await audit.emit('rate_limit.exceeded', { outcome: 'failure', reason: error.code, data: { scope: 'login' } }, ctx);
      }
      throw error;
    }

    const dpopJkt = await dpop.bindingKey(ctx, 'login');

    const user = await adapter.users.findByIdentifier(identifier);
    const passwordMatches = await password.verify(user?.id ?? null, input.password);
    if (!user || !passwordMatches) {
      await throttle.recordFailure(accountKey, accountPolicy);
      if (ipKey) await throttle.recordFailure(ipKey, ipPolicy);
      await audit.emit(
        'login.failed',
        {
          outcome: 'failure',
          reason: 'INVALID_CREDENTIALS',
          ...(user ? { userId: user.id } : {}),
          data: { method: 'pwd', identifierHash },
        },
        ctx,
      );
      // One error for an unknown account and for a wrong password.
      throw new AuthenticationError('INVALID_CREDENTIALS');
    }
    // Checked only after the password, so it cannot be used to find out which accounts exist.
    if (user.status !== 'active') {
      await audit.emit(
        'login.failed',
        { outcome: 'failure', reason: 'ACCOUNT_DISABLED', userId: user.id, data: { method: 'pwd', identifierHash } },
        ctx,
      );
      throw new AuthenticationError('ACCOUNT_DISABLED');
    }

    const failures = {
      account: await throttle.failureCount(accountKey),
      ip: ipKey ? await throttle.failureCount(ipKey) : 0,
    };
    const result = await this.afterFirstFactor(user, { loginMethod: 'pwd', userVerified: false, dpopJkt, failures }, ctx);
    await throttle.reset(accountKey);
    return result;
  }

  async passkeyOptions(input: { identifier?: string } = {}, _ctx: RequestContext = {}): Promise<PasskeyLoginOptions> {
    const { config, adapter, passkeys } = this.options;
    if (!passkeys) throw new RequestError('REQUEST_INVALID', { details: { reason: 'passkey_login_disabled' } });
    let userId: string | null = null;
    if (input.identifier !== undefined) {
      if (typeof input.identifier !== 'string' || input.identifier.length > MAX_IDENTIFIER_LENGTH) {
        throw new RequestError('REQUEST_INVALID');
      }
      // Listing an account's credentials tells the caller the account exists. Unless that has been
      // opted into, the identifier is ignored and the authenticator offers what it has for this site.
      if (config.passkeys?.identifierHints) {
        userId = (await adapter.users.findByIdentifier(config.normalizeIdentifier(input.identifier)))?.id ?? null;
      }
    }
    return passkeys.authenticationOptions(userId);
  }

  async withPasskey(
    input: { challengeId: string; response: AuthenticationResponseJSON },
    ctx: RequestContext = {},
  ): Promise<LoginResult> {
    const { adapter, audit, dpop, passkeys } = this.options;
    if (!passkeys) throw new RequestError('REQUEST_INVALID', { details: { reason: 'passkey_login_disabled' } });
    const dpopJkt = await dpop.bindingKey(ctx, 'login');

    let verified: Awaited<ReturnType<PasskeyService['verifyAuthentication']>>;
    try {
      verified = await passkeys.verifyAuthentication(input);
    } catch (error) {
      if (isAuthError(error)) {
        const reason = error.debug === 'counter_regression' ? 'counter_regression' : error.code;
        await audit.emit('login.failed', { outcome: 'failure', reason, data: { method: 'passkey' } }, ctx);
      }
      throw error;
    }

    const user = await adapter.users.findById(verified.userId);
    if (!user) throw new PasskeyError('PASSKEY_VERIFICATION_FAILED');
    if (user.status !== 'active') {
      await audit.emit(
        'login.failed',
        { outcome: 'failure', reason: 'ACCOUNT_DISABLED', userId: user.id, data: { method: 'passkey' } },
        ctx,
      );
      throw new AuthenticationError('ACCOUNT_DISABLED');
    }
    return this.afterFirstFactor(
      user,
      { loginMethod: 'passkey', userVerified: verified.userVerified, dpopJkt, failures: { account: 0, ip: 0 } },
      ctx,
    );
  }

  /** Completes a login that returned `mfa_required`. */
  async completeMfa(input: { ticket: string; method: MfaMethod; code: string }, ctx: RequestContext = {}): Promise<Authenticated> {
    const { adapter, dpop, mfa } = this.options;
    const state = await mfa.redeemTicket(input, ctx, dpop);
    const user = await adapter.users.findById(state.userId);
    if (!user || user.status !== 'active') throw new AuthenticationError('ACCOUNT_DISABLED');
    return this.complete(
      user,
      {
        methods: [...state.methods, input.method === 'totp' ? 'otp' : 'recovery'],
        dpopJkt: state.dpopJkt,
        loginMethod: state.loginMethod,
        riskScore: state.riskScore,
        location: state.location,
        passkeyUserVerified: false,
      },
      ctx,
    );
  }

  /**
   * Runs once the first factor has succeeded: scores the risk, then either finishes the login,
   * asks for a second factor, or denies.
   *
   * Risk is evaluated only at this point, so a caller who has not proven the first factor learns
   * nothing from it.
   */
  private async afterFirstFactor(user: User, first: FirstFactor, ctx: RequestContext): Promise<LoginResult> {
    const { config, audit, mfa, risk } = this.options;
    const assessment = await risk.assess({ user, ctx, deviceKey: first.dpopJkt, failures: first.failures });
    await audit.emit(
      'risk.evaluated',
      {
        outcome: assessment.decision === 'deny' ? 'failure' : 'success',
        userId: user.id,
        data: { score: assessment.score, decision: assessment.decision, signals: assessment.signals },
      },
      ctx,
    );

    const deny = async (): Promise<never> => {
      await audit.emit(
        'login.failed',
        { outcome: 'failure', reason: 'RISK_DENIED', userId: user.id, data: { method: first.loginMethod } },
        ctx,
      );
      throw new RiskError('RISK_DENIED');
    };
    if (assessment.decision === 'deny') await deny();

    const methods: AuthMethod[] = [first.loginMethod === 'pwd' ? 'pwd' : 'passkey'];
    const assurance = assuranceFor(methods, { passkeyUserVerified: first.userVerified });
    const completion: Completion = {
      methods,
      dpopJkt: first.dpopJkt,
      loginMethod: first.loginMethod,
      riskScore: assessment.score,
      location: assessment.location,
      passkeyUserVerified: first.userVerified,
    };

    // A passkey with user verification is already two factors, so nothing more is asked of it.
    if (assurance === 'aal2') return this.complete(user, completion, ctx);

    const available = await mfa.availableMethods(user.id);
    const stepUp = assessment.decision === 'step_up';
    if (available.length > 0) {
      return mfa.issueTicket(
        {
          userId: user.id,
          methods,
          dpopJkt: first.dpopJkt,
          loginMethod: first.loginMethod,
          riskScore: assessment.score,
          location: assessment.location,
          allowed: available,
        },
        stepUp ? 'risk' : 'enrolled',
        ctx,
      );
    }
    if (stepUp && config.risk.whenStepUpUnavailable === 'deny') await deny();
    return this.complete(user, completion, ctx);
  }

  private async complete(user: User, completion: Completion, ctx: RequestContext): Promise<Authenticated> {
    const { audit, risk, sessions } = this.options;
    const assurance = assuranceFor(completion.methods, { passkeyUserVerified: completion.passkeyUserVerified });
    const result = await sessions.start(user, { methods: completion.methods, assurance, dpopJkt: completion.dpopJkt }, ctx);
    await risk.remember({ user, ctx, deviceKey: completion.dpopJkt, location: completion.location });
    await audit.emit(
      'login.succeeded',
      {
        outcome: 'success',
        userId: user.id,
        sessionId: result.session.id,
        data: { method: completion.loginMethod, riskScore: completion.riskScore, mfa: completion.methods.length > 1 },
      },
      ctx,
    );
    return result;
  }
}
