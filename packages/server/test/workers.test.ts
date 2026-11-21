import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthEnv } from './env.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

async function concurrentKeyLoads() {
  const env = createAuthEnv();
  await env.auth.keys.jwks();
  env.clock.advanceSec(31); // past the key cache
  const list = vi.spyOn(env.adapter.keys, 'list');
  await Promise.all([env.auth.keys.jwks(), env.auth.keys.jwks(), env.auth.keys.jwks()]);
  return list.mock.calls.length;
}

describe('running on Cloudflare Workers', () => {
  it('does not make one request wait on a key load started by another', async () => {
    vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
    expect(await concurrentKeyLoads()).toBe(3);
  });

  it('still shares a concurrent key load on other runtimes', async () => {
    vi.stubGlobal('navigator', { userAgent: 'Node.js/24' });
    expect(await concurrentKeyLoads()).toBe(1);
  });

  it('converges on one signing key when concurrent requests find an empty store', async () => {
    vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' });
    const env = createAuthEnv();
    const documents = await Promise.all(Array.from({ length: 8 }, () => env.auth.keys.jwks()));
    for (const document of documents) expect(document.keys).toHaveLength(1);
    expect(new Set(documents.map((document) => document.keys[0]!.kid)).size).toBe(1);
  });
});
