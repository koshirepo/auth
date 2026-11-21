/** The single source of time for a server instance. Injectable so tests never sleep. */
export interface Clock {
  /** Epoch milliseconds. */
  nowMs(): number;
  /** Epoch seconds, rounded down. */
  nowSec(): number;
  now(): Date;
}

export function createClock(source: () => number = Date.now): Clock {
  return {
    nowMs: source,
    nowSec: () => Math.floor(source() / 1000),
    now: () => new Date(source()),
  };
}

export function toEpochSec(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}
