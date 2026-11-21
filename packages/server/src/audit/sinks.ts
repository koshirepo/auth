import type { AuditEvent } from '@acme/auth-core';
import type { AuditStore } from '../adapters/types.js';

/** Receives finished audit events. Events never contain secrets or tokens. */
export interface AuditSink {
  write(event: AuditEvent): void | Promise<void>;
}

/** Writes events to an adapter's audit store. This is the default sink. */
export function storeSink(store: AuditStore): AuditSink {
  return { write: (event) => store.append(event) };
}

/** Writes one JSON object per line. Defaults to standard output. */
export function consoleSink(options: { write?: (line: string) => void } = {}): AuditSink {
  const write = options.write ?? ((line: string) => console.log(line));
  return { write: (event) => write(JSON.stringify(event)) };
}

export interface MemorySink extends AuditSink {
  readonly events: AuditEvent[];
  /** Events of one type, in the order they were written. */
  ofType<T extends AuditEvent['type']>(type: T): Extract<AuditEvent, { type: T }>[];
  clear(): void;
}

/** Collects events in an array. For tests. */
export function memorySink(): MemorySink {
  const events: AuditEvent[] = [];
  return {
    events,
    write(event) {
      events.push(event);
    },
    ofType<T extends AuditEvent['type']>(type: T) {
      return events.filter((event): event is Extract<AuditEvent, { type: T }> => event.type === type);
    },
    clear() {
      events.length = 0;
    },
  };
}
