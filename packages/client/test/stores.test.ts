import { IDBFactory } from 'fake-indexeddb';
import { decodeProtectedHeader } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DpopSigner,
  broadcastChannel,
  defaultKeyStore,
  defaultLocks,
  inPageLocks,
  indexedDbKeyStore,
  memoryKeyStore,
  type ChannelMessage,
} from '../src/index.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

async function generate(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}

describe('memoryKeyStore', () => {
  it('holds a key pair until cleared', async () => {
    const store = memoryKeyStore();
    expect(await store.load()).toBeNull();
    const pair = await generate();
    await store.save(pair);
    expect(await store.load()).toBe(pair);
    await store.clear();
    expect(await store.load()).toBeNull();
  });
});

describe('indexedDbKeyStore', () => {
  it('stores the key pair as CryptoKey objects, so the private key never becomes readable bytes', async () => {
    vi.stubGlobal('indexedDB', new IDBFactory());
    const store = indexedDbKeyStore();
    expect(await store.load()).toBeNull();

    const pair = await generate();
    await store.save(pair);

    // A second store instance is what a page reload or another tab sees.
    const reloaded = await indexedDbKeyStore().load();
    expect(reloaded).not.toBeNull();
    expect(reloaded!.privateKey.type).toBe('private');
    expect(reloaded!.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', reloaded!.privateKey)).rejects.toThrow();

    // The reloaded key still signs, and the original public key verifies it.
    const data = new TextEncoder().encode('proof');
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, reloaded!.privateKey, data);
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, signature, data)).toBe(true);

    await store.clear();
    expect(await indexedDbKeyStore().load()).toBeNull();
  });

  it('keeps separate databases apart', async () => {
    vi.stubGlobal('indexedDB', new IDBFactory());
    await indexedDbKeyStore({ databaseName: 'app-one' }).save(await generate());
    expect(await indexedDbKeyStore({ databaseName: 'app-one' }).load()).not.toBeNull();
    expect(await indexedDbKeyStore({ databaseName: 'app-two' }).load()).toBeNull();
  });

  it('is the default where IndexedDB exists, and memory is the fallback', async () => {
    vi.stubGlobal('indexedDB', new IDBFactory());
    const persistent = defaultKeyStore();
    await persistent.save(await generate());
    expect(await defaultKeyStore().load()).not.toBeNull();

    vi.stubGlobal('indexedDB', undefined);
    const fallback = defaultKeyStore();
    await fallback.save(await generate());
    expect(await defaultKeyStore().load()).toBeNull();
  });
});

describe('DpopSigner', () => {
  it('creates one key however many proofs are requested at once, and saves it', async () => {
    const store = memoryKeyStore();
    let saves = 0;
    const counting = { ...store, save: async (pair: CryptoKeyPair) => (saves++, store.save(pair)) };
    const signer = new DpopSigner(counting, Date.now, inPageLocks);

    const proofs = await Promise.all(Array.from({ length: 10 }, () => signer.proof('GET', 'https://api.example.com/x')));
    expect(saves).toBe(1);
    const keys = new Set(proofs.map((proof) => JSON.stringify(decodeProtectedHeader(proof).jwk)));
    expect(keys.size).toBe(1);
    expect(new Set(proofs).size).toBe(10);
  });

  it('agrees on one key when two signers start with an empty store', async () => {
    const store = memoryKeyStore();
    const one = new DpopSigner(store, Date.now, inPageLocks);
    const two = new DpopSigner(store, Date.now, inPageLocks);
    const [first, second] = await Promise.all([one.thumbprint(), two.thumbprint()]);
    expect(first).toBe(second);
  });

  it('reuses a stored key, which is what makes the device recognisable after a reload', async () => {
    const store = memoryKeyStore();
    const before = await new DpopSigner(store, Date.now, null).thumbprint();
    const after = await new DpopSigner(store, Date.now, null).thumbprint();
    expect(after).toBe(before);
    expect(before).toMatch(/^[A-Za-z0-9_-]{43}$/);

    await store.clear();
    expect(await new DpopSigner(store, Date.now, null).thumbprint()).not.toBe(before);
  });

  it('recovers when the key store fails once', async () => {
    const store = memoryKeyStore();
    let fail = true;
    const flaky = {
      ...store,
      load: async () => {
        if (fail) {
          fail = false;
          throw new Error('IndexedDB is not available yet');
        }
        return store.load();
      },
    };
    const signer = new DpopSigner(flaky, Date.now, null);
    await expect(signer.proof('GET', 'https://api.example.com/x')).rejects.toThrow(/not available yet/);
    expect((await signer.proof('GET', 'https://api.example.com/x')).split('.')).toHaveLength(3);
  });
});

describe('locks', () => {
  it('runs holders of the same lock one after another, in order', async () => {
    const order: string[] = [];
    const task = (name: string, ms: number) => async () => {
      order.push(`${name} start`);
      await new Promise((resolve) => setTimeout(resolve, ms));
      order.push(`${name} end`);
      return name;
    };
    const results = await Promise.all([
      inPageLocks.request('lock-a', task('one', 15)),
      inPageLocks.request('lock-a', task('two', 1)),
      inPageLocks.request('lock-a', task('three', 5)),
    ]);
    expect(results).toEqual(['one', 'two', 'three']);
    expect(order).toEqual(['one start', 'one end', 'two start', 'two end', 'three start', 'three end']);
  });

  it('does not make different locks wait for each other', async () => {
    const order: string[] = [];
    await Promise.all([
      inPageLocks.request('lock-b', async () => {
        await new Promise((resolve) => setTimeout(resolve, 15));
        order.push('slow');
      }),
      inPageLocks.request('lock-c', async () => {
        order.push('fast');
      }),
    ]);
    expect(order).toEqual(['fast', 'slow']);
  });

  it('releases the lock when the holder fails', async () => {
    const failed = inPageLocks.request('lock-d', async () => {
      throw new Error('holder failed');
    });
    const next = inPageLocks.request('lock-d', async () => 'ran');
    await expect(failed).rejects.toThrow('holder failed');
    expect(await next).toBe('ran');
  });

  it('uses the Web Locks API where it exists', async () => {
    const calls: string[] = [];
    vi.stubGlobal('navigator', {
      locks: {
        request: async <T>(name: string, callback: () => Promise<T>) => {
          calls.push(name);
          return callback();
        },
      },
    });
    expect(await defaultLocks().request('from-web-locks', async () => 42)).toBe(42);
    expect(calls).toEqual(['from-web-locks']);

    vi.stubGlobal('navigator', {});
    expect(defaultLocks()).toBe(inPageLocks);
  });
});

describe('broadcastChannel', () => {
  it('delivers sign-in and sign-out notices to other tabs and ignores anything else', async () => {
    const name = `test-${crypto.randomUUID()}`;
    const one = broadcastChannel(name)!;
    const two = broadcastChannel(name)!;
    const raw = new BroadcastChannel(name);
    const received: ChannelMessage[] = [];
    two.subscribe((message) => received.push(message));

    one.post({ type: 'signed-in' });
    raw.postMessage({ type: 'something-else', accessToken: 'should never be read' });
    raw.postMessage('junk');
    one.post({ type: 'signed-out' });
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(received).toEqual([{ type: 'signed-in' }, { type: 'signed-out' }]);

    one.close();
    two.close();
    raw.close();
  });

  it('is unavailable where the API does not exist', () => {
    vi.stubGlobal('BroadcastChannel', undefined);
    expect(broadcastChannel('nope')).toBeNull();
  });
});
