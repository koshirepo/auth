import { InternalError, type AuditEvent, type AuditEventData, type AuditEventType } from '@koshirepo/auth-core';
import type { RequestContext } from '../context.js';
import type { Clock } from '../util/clock.js';
import { randomId } from '../util/crypto.js';
import type { AuditSink } from './sinks.js';

export interface AuditInput<T extends AuditEventType> {
  outcome: 'success' | 'failure';
  data: AuditEventData[T];
  userId?: string;
  sessionId?: string;
  /** An error code or a fixed enum value. Never text taken from a request. */
  reason?: string;
}

export interface AuditEmitterOptions {
  sinks: readonly AuditSink[];
  /** When true, a sink failure fails the operation that produced the event. */
  failClosed: boolean;
  onError: (error: unknown, event: AuditEvent) => void;
  clock: Clock;
}

const MAX_USER_AGENT_LENGTH = 256;

/**
 * The only place audit events are built.
 *
 * Callers pass a typed payload whose fields are ids, enum values and numbers. There is no
 * parameter through which a password, token, code or key could be handed in, which is the first
 * line of defence against secrets reaching the log.
 */
export class AuditEmitter {
  constructor(private readonly options: AuditEmitterOptions) {}

  async emit<T extends AuditEventType>(type: T, input: AuditInput<T>, ctx?: RequestContext): Promise<void> {
    const event = {
      id: randomId(),
      type,
      at: this.options.clock.now().toISOString(),
      outcome: input.outcome,
      ...(input.userId !== undefined ? { userId: input.userId } : {}),
      ...(input.sessionId !== undefined ? { sessionId: input.sessionId } : {}),
      ...(ctx?.ip !== undefined ? { ip: ctx.ip } : {}),
      ...(ctx?.userAgent !== undefined ? { userAgent: ctx.userAgent.slice(0, MAX_USER_AGENT_LENGTH) } : {}),
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
      data: input.data,
    } as AuditEvent;

    const results = await Promise.allSettled(
      this.options.sinks.map(async (sink) => {
        await sink.write(event);
      }),
    );
    for (const result of results) {
      if (result.status !== 'rejected') continue;
      if (this.options.failClosed) {
        throw new InternalError('INTERNAL_ERROR', { debug: 'An audit sink failed.', cause: result.reason });
      }
      try {
        this.options.onError(result.reason, event);
      } catch {
        // A broken error hook must not break authentication.
      }
    }
  }
}
