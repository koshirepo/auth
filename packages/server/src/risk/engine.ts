import type { DeviceStore, User } from '../adapters/types.js';
import type { ResolvedConfig } from '../config.js';
import type { RequestContext } from '../context.js';
import type { Clock } from '../util/clock.js';
import type { GeoLocation, RiskAssessment, RiskInput, RiskSignalResult } from './types.js';

export interface RiskEngineOptions {
  config: ResolvedConfig['risk'];
  devices: DeviceStore;
  clock: Clock;
}

/** Device key recorded for logins that are not bound to a DPoP key, so their network history is still kept. */
const UNBOUND_DEVICE_KEY = 'unbound';

/**
 * Scores a login from the configured signals and turns the score into a decision.
 *
 * A signal or locator that throws is treated as not firing. Risk scoring is a heuristic layered
 * on top of the factors, so a broken GeoIP lookup must not stop every login.
 */
export class RiskEngine {
  constructor(private readonly options: RiskEngineOptions) {}

  async assess(input: {
    user: User;
    ctx: RequestContext;
    deviceKey: string | null;
    failures: { account: number; ip: number };
  }): Promise<RiskAssessment> {
    const { config, devices, clock } = this.options;

    let location: GeoLocation | null = null;
    const locate = config.signals.find((signal) => typeof signal.locate === 'function')?.locate;
    if (locate && input.ctx.ip) {
      try {
        location = (await locate(input.ctx.ip)) ?? null;
      } catch {
        location = null;
      }
    }

    const known = await devices.listByUser(input.user.id);
    const riskInput: RiskInput = {
      user: input.user,
      ip: input.ctx.ip,
      userAgent: input.ctx.userAgent,
      deviceKey: input.deviceKey ?? undefined,
      location,
      now: clock.now(),
      devices: known,
      failures: input.failures,
    };

    const signals: RiskSignalResult[] = [];
    for (const signal of config.signals) {
      try {
        const result = await signal(riskInput);
        if (result && typeof result.score === 'number' && Number.isFinite(result.score) && result.score > 0) {
          signals.push({ name: String(result.name), score: result.score });
        }
      } catch {
        // See the class comment.
      }
    }

    const score = Math.min(100, Math.round(signals.reduce((sum, signal) => sum + signal.score, 0)));
    const decision = score >= config.denyAt ? 'deny' : score >= config.stepUpAt ? 'step_up' : 'allow';
    return { score, decision, signals, location };
  }

  /** Records a completed login, so the next one is compared against it. */
  async remember(input: { user: User; ctx: RequestContext; deviceKey: string | null; location: GeoLocation | null }): Promise<void> {
    await this.options.devices.upsert({
      userId: input.user.id,
      deviceKey: input.deviceKey ?? UNBOUND_DEVICE_KEY,
      ip: input.ctx.ip ?? null,
      country: input.location?.country ?? null,
      latitude: input.location?.latitude ?? null,
      longitude: input.location?.longitude ?? null,
      now: this.options.clock.now(),
    });
  }
}
