/** The part of the Web Locks API the client uses. */
export interface LockManagerLike {
  /** Runs `callback` while holding the named lock, and resolves with its result. */
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

const queues = new Map<string, Promise<void>>();

/**
 * A lock that works inside one page only. Used when the Web Locks API is missing. It still
 * serialises several clients in the same page, but not several tabs.
 */
export const inPageLocks: LockManagerLike = {
  request<T>(name: string, callback: () => Promise<T>): Promise<T> {
    const previous = queues.get(name) ?? Promise.resolve();
    const result = previous.then(callback);
    const settled = result.then(
      () => undefined,
      () => undefined,
    );
    queues.set(name, settled);
    void settled.then(() => {
      if (queues.get(name) === settled) queues.delete(name);
    });
    return result;
  },
};

/** The browser's lock manager when there is one, which also coordinates across tabs. */
export function defaultLocks(): LockManagerLike {
  const locks = (globalThis as { navigator?: { locks?: { request?: unknown } } }).navigator?.locks;
  if (locks && typeof locks.request === 'function') {
    const manager = locks as unknown as { request<T>(name: string, callback: () => Promise<T>): Promise<T> };
    return { request: (name, callback) => manager.request(name, callback) };
  }
  return inPageLocks;
}
