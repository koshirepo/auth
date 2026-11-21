import { describe, expect, it } from 'vitest';
import { argon2id } from '../src/password/argon2.js';

const weak = { memoryKiB: 64, iterations: 1, unsafeAllowWeakParameters: true } as const;

describe('argon2id hasher', () => {
  it('uses the OWASP minimum parameters by default and produces PHC strings', async () => {
    const hasher = argon2id();
    const hash = await hasher.hash('correct horse battery staple');
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
    expect(await hasher.verify(hash, 'correct horse battery staple')).toBe(true);
    expect(await hasher.verify(hash, 'correct horse battery stapl')).toBe(false);
    expect(hasher.needsRehash(hash)).toBe(false);
  });

  it('salts every hash', async () => {
    const hasher = argon2id(weak);
    const one = await hasher.hash('same password');
    const two = await hasher.hash('same password');
    expect(one).not.toBe(two);
    expect(await hasher.verify(one, 'same password')).toBe(true);
    expect(await hasher.verify(two, 'same password')).toBe(true);
  });

  it('returns false instead of throwing for a malformed hash', async () => {
    const hasher = argon2id(weak);
    for (const hash of ['', 'not-a-hash', '$argon2id$', '$2b$10$abcdefghijklmnopqrstuv', 'stub$password']) {
      expect(await hasher.verify(hash, 'password')).toBe(false);
    }
  });

  it('asks for a rehash when stored parameters are weaker than the current ones', async () => {
    const old = argon2id(weak);
    const current = argon2id({ memoryKiB: 128, iterations: 2, unsafeAllowWeakParameters: true });
    const oldHash = await old.hash('password');
    expect(current.needsRehash(oldHash)).toBe(true);
    expect(current.needsRehash(await current.hash('password'))).toBe(false);
    // Stronger stored parameters are left alone.
    expect(old.needsRehash(await current.hash('password'))).toBe(false);
    // Anything that is not an Argon2id hash needs replacing.
    expect(current.needsRehash('$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')).toBe(true);
    expect(current.needsRehash('$2b$10$abcdefghijklmnopqrstuv')).toBe(true);
  });

  it('mixes in a pepper, so a hash cannot be verified without it', async () => {
    const peppered = argon2id({ ...weak, pepper: 'kept-outside-the-database' });
    const plain = argon2id(weak);
    const other = argon2id({ ...weak, pepper: 'a-different-pepper' });
    const hash = await peppered.hash('password');
    expect(await peppered.verify(hash, 'password')).toBe(true);
    expect(await plain.verify(hash, 'password')).toBe(false);
    expect(await other.verify(hash, 'password')).toBe(false);
  });

  it('refuses unsafe parameters unless explicitly allowed', () => {
    expect(() => argon2id({ memoryKiB: 1024 })).toThrow(/at least 7168/);
    expect(() => argon2id({ memoryKiB: 0, unsafeAllowWeakParameters: true })).toThrow(/positive whole number/);
    expect(() => argon2id({ iterations: 1.5 })).toThrow(/positive whole number/);
    expect(() => argon2id({ parallelism: -1 })).toThrow(/positive whole number/);
    expect(() => argon2id({ memoryKiB: 7168 })).not.toThrow();
  });

  it('handles unicode and long passwords', async () => {
    const hasher = argon2id(weak);
    for (const password of ['pässwörd-ñ-日本語-🔐', 'x'.repeat(1000), ' leading and trailing ']) {
      const hash = await hasher.hash(password);
      expect(await hasher.verify(hash, password)).toBe(true);
      expect(await hasher.verify(hash, password.trim() + '!')).toBe(false);
    }
  });
});
