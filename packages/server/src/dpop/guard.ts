import { DpopError, isAuthError } from '@acme/auth-core';
import type { AuditEmitter } from '../audit/emitter.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { Clock } from '../util/clock.js';
import { validateDpopProof, type ReplayStore } from './proof.js';

type Stage = 'login' | 'mfa' | 'refresh' | 'request';

export interface DpopGuardOptions {
  config: ResolvedConfig['dpop'];
  clock: Clock;
  replayStore: ReplayStore;
  audit: AuditEmitter;
}

/** Applies the configured DPoP mode to the requests that do not carry an access token. */
export class DpopGuard {
  constructor(private readonly options: DpopGuardOptions) {}

  /**
   * For a login request: validates the proof and returns the thumbprint of the key to bind the
   * session to. Returns null when binding is off, or optional and no proof was sent.
   */
  async bindingKey(ctx: RequestContext, stage: Stage): Promise<string | null> {
    const { config } = this.options;
    if (config.mode === 'off') return null;
    if (!ctx.dpop?.proof) {
      if (config.mode === 'optional') return null;
      await this.reject(new DpopError('DPOP_PROOF_REQUIRED'), stage, ctx, {});
    }
    return this.validate(ctx, stage, undefined, {});
  }

  /** For a request that must come from the key a session or ticket is already bound to. */
  async requireKey(
    ctx: RequestContext,
    expectedJkt: string,
    stage: Stage,
    ids: { userId?: string; sessionId?: string } = {},
  ): Promise<void> {
    await this.validate(ctx, stage, expectedJkt, ids);
  }

  private async validate(
    ctx: RequestContext,
    stage: Stage,
    expectedJkt: string | undefined,
    ids: { userId?: string; sessionId?: string },
  ): Promise<string> {
    const { config, clock, replayStore } = this.options;
    try {
      const { jkt } = await validateDpopProof(
        {
          proof: ctx.dpop?.proof,
          method: ctx.dpop?.method ?? '',
          url: ctx.dpop?.url ?? '',
          ...(expectedJkt !== undefined ? { expectedJkt } : {}),
        },
        {
          algorithms: config.algorithms,
          iatToleranceSec: config.iatToleranceSec,
          replayStore,
          now: () => clock.nowMs(),
        },
      );
      return jkt;
    } catch (error) {
      return this.reject(error, stage, ctx, ids);
    }
  }

  private async reject(
    error: unknown,
    stage: Stage,
    ctx: RequestContext,
    ids: { userId?: string; sessionId?: string },
  ): Promise<never> {
    if (isAuthError(error)) {
      await this.options.audit.emit(
        'dpop.rejected',
        { outcome: 'failure', reason: error.code, ...ids, data: { during: stage } },
        ctx,
      );
    }
    throw error;
  }
}
