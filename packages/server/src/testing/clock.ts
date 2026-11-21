export interface FakeClock {
  /** Epoch milliseconds. Pass this function as the `clock` option of `createAuth` and of an adapter. */
  (): number;
  advance(ms: number): void;
  advanceSec(seconds: number): void;
  set(ms: number): void;
}

/** A clock that only moves when told to. Starts at 2026-01-01T00:00:00Z unless given a start. */
export function createFakeClock(startMs: number = Date.UTC(2026, 0, 1)): FakeClock {
  let current = startMs;
  const clock = (() => current) as FakeClock;
  clock.advance = (ms: number) => {
    current += ms;
  };
  clock.advanceSec = (seconds: number) => {
    current += seconds * 1000;
  };
  clock.set = (ms: number) => {
    current = ms;
  };
  return clock;
}
