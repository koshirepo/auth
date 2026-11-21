import {
  AccountError,
  MfaError,
  RequestError,
  isAuthError,
  type AuthMethod,
  type JsonObject,
  type MfaMethod,
} from '@koshi-repo/auth-core';
import type { AuthAdapter } from '../adapters/types.js';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { DpopGuard } from '../dpop/guard.js';
import type { Throttle } from '../ratelimit/throttle.js';
import type { GeoLocation } from '../risk/types.js';
import type { Clock } from '../util/clock.js';
import { randomToken, sha256Base64Url } from '../util/crypto.js';
import { fromBase64Url, toBase32, toBase64Url } from '../util/encoding.js';
import type { DataProtector } from '../util/protector.js';
import { generateRecoveryCode, hashRecoveryCode, normalizeRecoveryCode } from './recovery-codes.js';
import { generateTotpSecret, matchTotp, otpauthUri } from './totp.js';

/** Returned by a login when a second factor is still needed. */
export interface MfaRequired {
  status: 'mfa_required';
  /** Opaque, single-use, short-lived. Send it back with the code. */
  ticket: string;
  methods: MfaMethod[];
  /** `enrolled`: the user has a second factor. `risk`: this login looked risky. */
  reason: 'enrolled' | 'risk';
  /** Epoch seconds. */
  expiresAt: number;
}

/** What the server remembers about a login that is waiting for its second factor. */
export interface MfaTicketState {
  userId: string;
  /** Methods already satisfied by the first factor. */
  methods: AuthMethod[];
  /** The DPoP key that passed the first factor. The second factor must come from the same key. */
  dpopJkt: string | null;
  loginMethod: 'pwd' | 'passkey';
  riskScore: number;
  location: GeoLocation | null;
  allowed: MfaMethod[];
}

export type MfaPurpose = 'login' | 'reauthentication' | 'enrolment';

export interface TotpEnrollment {
  enrollmentId: string;
  /** Base32, for typing into an authenticator app by hand. */
  secret: string;
  /** For rendering as a QR code. */
  otpauthUri: string;
}

export interface MfaServiceOptions {
  config: ResolvedConfig;
  adapter: AuthAdapter;
  clock: Clock;
  audit: AuditEmitter;
  protector: DataProtector;
  throttle: Throttle;
}

const MAX_CODE_LENGTH = 64;
const MAX_TICKET_LENGTH = 256;

export class MfaService {
  constructor(private readonly options: MfaServiceOptions) {}

  /** Second factors the user can use right now. Empty when none is enrolled. */
  async availableMethods(userId: string): Promise<MfaMethod[]> {
    const { credentials } = this.options.adapter;
    if (!(await credentials.getTotp(userId))) return [];
    const methods: MfaMethod[] = ['totp'];
    if ((await credentials.countRecoveryCodes(userId)) > 0) methods.push('recovery_code');
    return methods;
  }

  async status(userId: string): Promise<{ totp: boolean; recoveryCodes: number }> {
    const { credentials } = this.options.adapter;
    const totp = (await credentials.getTotp(userId)) !== null;
    return { totp, recoveryCodes: totp ? await credentials.countRecoveryCodes(userId) : 0 };
  }

  // -------------------------------------------------------------------------------------------
  // Tickets
  // -------------------------------------------------------------------------------------------

  /** Parks a login after its first factor and returns the ticket for the second. */
  async issueTicket(state: MfaTicketState, reason: 'enrolled' | 'risk', ctx: RequestContext): Promise<MfaRequired> {
    const { config, adapter, clock, audit } = this.options;
    const ticket = randomToken();
    await adapter.ephemeral.set(await this.ticketKey(ticket), state as unknown as JsonObject, config.mfa.ticketTtlSec);
    await audit.emit(
      'mfa.challenged',
      { outcome: 'success', userId: state.userId, data: { reason, methods: state.allowed } },
      ctx,
    );
    return {
      status: 'mfa_required',
      ticket,
      methods: [...state.allowed],
      reason,
      expiresAt: clock.nowSec() + config.mfa.ticketTtlSec,
    };
  }

  /**
   * Checks a ticket and the code sent with it, and consumes the ticket on success.
   *
   * A ticket is bound to the DPoP key that passed the first factor, survives a limited number of
   * wrong codes, and yields its state to exactly one successful request.
   */
  async redeemTicket(
    input: { ticket: string; method: MfaMethod; code: string },
    ctx: RequestContext,
    dpop: DpopGuard,
  ): Promise<MfaTicketState> {
    const { config, adapter } = this.options;
    if (typeof input.ticket !== 'string' || input.ticket.length === 0 || input.ticket.length > MAX_TICKET_LENGTH) {
      throw new MfaError('MFA_TICKET_INVALID');
    }
    if (input.method !== 'totp' && input.method !== 'recovery_code') {
      throw new RequestError('REQUEST_INVALID', { details: { field: 'method' } });
    }
    const key = await this.ticketKey(input.ticket);
    const state = (await adapter.ephemeral.get(key)) as MfaTicketState | null;
    if (!state) throw new MfaError('MFA_TICKET_INVALID');

    if (state.dpopJkt !== null) await dpop.requireKey(ctx, state.dpopJkt, 'mfa', { userId: state.userId });

    const attempts = await adapter.ephemeral.increment(`${key}:attempts`, config.mfa.ticketTtlSec);
    if (attempts > config.mfa.ticketMaxAttempts) {
      await adapter.ephemeral.take(key);
      throw new MfaError('MFA_TICKET_INVALID');
    }
    if (!state.allowed.includes(input.method)) throw new MfaError('MFA_CODE_INVALID');

    await this.verifyCode(state.userId, input.method, input.code, 'login', ctx);

    // Single use: if two requests got this far with the same ticket, only one takes it.
    if ((await adapter.ephemeral.take(key)) === null) throw new MfaError('MFA_TICKET_INVALID');
    return state;
  }

  // -------------------------------------------------------------------------------------------
  // Codes
  // -------------------------------------------------------------------------------------------

  /**
   * Verifies a TOTP or recovery code for a user. Throws `MFA_CODE_INVALID` for a wrong, expired or
   * replayed code alike, and `RATE_LIMITED` once the user has too many recent failures. The audit
   * log records which it was.
   */
  async verifyCode(userId: string, method: MfaMethod, code: string, purpose: MfaPurpose, ctx: RequestContext): Promise<void> {
    const { config, adapter, clock, audit, protector, throttle } = this.options;
    const limitKey = `mfa:${userId}`;
    try {
      await throttle.assertBelowLimit(limitKey, config.mfa.rateLimit.maxFailures);
    } catch (error) {
      if (isAuthError(error)) {
        await audit.emit('rate_limit.exceeded', { outcome: 'failure', reason: error.code, userId, data: { scope: 'mfa' } }, ctx);
      }
      throw error;
    }

    let accepted = false;
    let failure: 'invalid' | 'replayed' = 'invalid';

    if (typeof code === 'string' && code.length <= MAX_CODE_LENGTH) {
      if (method === 'totp') {
        const credential = await adapter.credentials.getTotp(userId);
        if (credential) {
          const secret = fromBase64Url(await protector.decrypt(credential.encryptedSecret));
          const step = await matchTotp(secret, code.trim(), {
            nowSec: clock.nowSec(),
            period: credential.period,
            digits: credential.digits,
            window: config.mfa.totp.window,
            algorithm: credential.algorithm,
          });
          if (step !== null) {
            // The store accepts each time step once. Losing here means the code was already used.
            if (await adapter.credentials.advanceTotpStep(userId, step)) accepted = true;
            else failure = 'replayed';
          }
        }
      } else {
        const normalized = normalizeRecoveryCode(code);
        if (normalized !== null) {
          accepted = await adapter.credentials.consumeRecoveryCode(
            userId,
            await hashRecoveryCode(userId, normalized),
            clock.now(),
          );
        }
      }
    }

    if (!accepted) {
      await throttle.recordWindowFailure(limitKey, config.mfa.rateLimit.windowSec);
      await audit.emit('mfa.failed', { outcome: 'failure', reason: failure, userId, data: { method, purpose } }, ctx);
      throw new MfaError('MFA_CODE_INVALID');
    }

    await audit.emit('mfa.verified', { outcome: 'success', userId, data: { method, purpose } }, ctx);
    if (method === 'recovery_code') {
      const remaining = await adapter.credentials.countRecoveryCodes(userId);
      await audit.emit('mfa.recovery_code.used', { outcome: 'success', userId, data: { remaining } }, ctx);
    }
  }

  // -------------------------------------------------------------------------------------------
  // Enrolment
  // -------------------------------------------------------------------------------------------

  /** Starts TOTP enrolment. Nothing is stored on the account until a first code is confirmed. */
  async beginTotpEnrollment(userId: string): Promise<TotpEnrollment> {
    const { config, adapter, protector } = this.options;
    const user = await adapter.users.findById(userId);
    if (!user) throw new AccountError('USER_NOT_FOUND');
    if (await adapter.credentials.getTotp(userId)) throw new MfaError('MFA_ALREADY_ENROLLED');

    const secret = generateTotpSecret(config.mfa.totp.algorithm);
    const enrollmentId = randomToken(16);
    await adapter.ephemeral.set(
      this.enrollmentKey(enrollmentId),
      { userId, encryptedSecret: await protector.encrypt(toBase64Url(secret)) },
      config.mfa.enrollmentTtlSec,
    );
    return {
      enrollmentId,
      secret: toBase32(secret),
      otpauthUri: otpauthUri({
        issuer: config.mfa.totp.issuer,
        account: user.identifier,
        secret,
        algorithm: config.mfa.totp.algorithm,
        digits: config.mfa.totp.digits,
        period: config.mfa.totp.period,
      }),
    };
  }

  /**
   * Activates TOTP once the user proves the authenticator app works, and returns the recovery
   * codes. This is the only time the codes are available in plain text.
   */
  async confirmTotpEnrollment(
    userId: string,
    input: { enrollmentId: string; code: string },
    ctx: RequestContext = {},
  ): Promise<{ recoveryCodes: string[] }> {
    const { config, adapter, clock, audit, protector } = this.options;
    if (typeof input.enrollmentId !== 'string' || input.enrollmentId.length === 0 || input.enrollmentId.length > MAX_TICKET_LENGTH) {
      throw new MfaError('MFA_TICKET_INVALID');
    }
    const key = this.enrollmentKey(input.enrollmentId);
    const pending = (await adapter.ephemeral.get(key)) as { userId: string; encryptedSecret: string } | null;
    if (!pending || pending.userId !== userId) throw new MfaError('MFA_TICKET_INVALID');

    const attempts = await adapter.ephemeral.increment(`${key}:attempts`, config.mfa.enrollmentTtlSec);
    if (attempts > config.mfa.ticketMaxAttempts) {
      await adapter.ephemeral.take(key);
      throw new MfaError('MFA_TICKET_INVALID');
    }

    const secret = fromBase64Url(await protector.decrypt(pending.encryptedSecret));
    const step =
      typeof input.code === 'string' && input.code.length <= MAX_CODE_LENGTH
        ? await matchTotp(secret, input.code.trim(), {
            nowSec: clock.nowSec(),
            period: config.mfa.totp.period,
            digits: config.mfa.totp.digits,
            window: config.mfa.totp.window,
            algorithm: config.mfa.totp.algorithm,
          })
        : null;
    if (step === null) {
      await audit.emit('mfa.failed', { outcome: 'failure', reason: 'invalid', userId, data: { method: 'totp', purpose: 'enrolment' } }, ctx);
      throw new MfaError('MFA_CODE_INVALID');
    }

    if ((await adapter.ephemeral.take(key)) === null) throw new MfaError('MFA_TICKET_INVALID');
    if (await adapter.credentials.getTotp(userId)) throw new MfaError('MFA_ALREADY_ENROLLED');

    await adapter.credentials.saveTotp({
      userId,
      encryptedSecret: pending.encryptedSecret,
      algorithm: config.mfa.totp.algorithm,
      digits: config.mfa.totp.digits,
      period: config.mfa.totp.period,
      // The confirming code counts as used, so it cannot be replayed at the next login.
      lastUsedStep: step,
      createdAt: clock.now(),
    });
    await audit.emit('mfa.totp.enrolled', { outcome: 'success', userId, data: {} }, ctx);
    return { recoveryCodes: await this.writeRecoveryCodes(userId, ctx) };
  }

  /** Removes TOTP and every recovery code. */
  async removeTotp(userId: string, ctx: RequestContext = {}): Promise<void> {
    const { adapter, clock, audit } = this.options;
    if (!(await adapter.credentials.deleteTotp(userId))) throw new MfaError('MFA_NOT_ENROLLED');
    await adapter.credentials.replaceRecoveryCodes(userId, [], clock.now());
    await audit.emit('mfa.totp.removed', { outcome: 'success', userId, data: {} }, ctx);
  }

  /** Replaces all recovery codes. The old ones stop working. */
  async regenerateRecoveryCodes(userId: string, ctx: RequestContext = {}): Promise<string[]> {
    if (!(await this.options.adapter.credentials.getTotp(userId))) throw new MfaError('MFA_NOT_ENROLLED');
    return this.writeRecoveryCodes(userId, ctx);
  }

  private async writeRecoveryCodes(userId: string, ctx: RequestContext): Promise<string[]> {
    const { config, adapter, clock, audit } = this.options;
    const codes = Array.from({ length: config.mfa.recoveryCodes.count }, () => generateRecoveryCode());
    const hashes = await Promise.all(
      codes.map((code) => hashRecoveryCode(userId, normalizeRecoveryCode(code) as string)),
    );
    await adapter.credentials.replaceRecoveryCodes(userId, hashes, clock.now());
    await audit.emit('mfa.recovery_codes.generated', { outcome: 'success', userId, data: { count: codes.length } }, ctx);
    return codes;
  }

  private async ticketKey(ticket: string): Promise<string> {
    return `mfa:ticket:${await sha256Base64Url(ticket)}`;
  }

  private enrollmentKey(enrollmentId: string): string {
    return `mfa:enroll:${enrollmentId}`;
  }
}
