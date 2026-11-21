import { describe, expect, it } from 'vitest';
import { scrypt } from '../src/password/scrypt.js';

const fast = { logN: 4, r: 8, p: 1, unsafeAllowWeakParameters: true };
const b64 = (bytes: Buffer) => bytes.toString('base64').replace(/=+$/, '');

describe('scrypt password hasher', () => {
  it('verifies the RFC 7914 test vector', async () => {
    const dk =
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162' +
      '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640';
    const hash = `$scrypt$ln=10,r=8,p=16$${b64(Buffer.from('NaCl'))}$${b64(Buffer.from(dk, 'hex'))}`;
    expect(await scrypt().verify(hash, 'password')).toBe(true);
    expect(await scrypt().verify(hash, 'Password')).toBe(false);
  });

  it('hashes to a PHC string with a fresh salt, and verifies only the right password', async () => {
    const hasher = scrypt(fast);
    const [one, two] = [await hasher.hash('correct horse'), await hasher.hash('correct horse')];
    expect(one).toMatch(/^\$scrypt\$ln=4,r=8,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
    expect(one).not.toBe(two);
    expect(await hasher.verify(one, 'correct horse')).toBe(true);
    expect(await hasher.verify(one, 'wrong horse')).toBe(false);
  });

  it('uses the OWASP setting by default', async () => {
    const hash = await scrypt().hash('correct horse');
    expect(hash.startsWith('$scrypt$ln=14,r=8,p=5$')).toBe(true);
    expect(await scrypt().verify(hash, 'correct horse')).toBe(true);
  });

  it('returns false for malformed hashes and for parameters too large to compute', async () => {
    const hasher = scrypt(fast);
    const salt = b64(Buffer.alloc(16, 1));
    const key = b64(Buffer.alloc(32, 2));
    for (const hash of [
      '',
      'not a hash',
      '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
      `$scrypt$ln=99,r=8,p=1$${salt}$${key}`,
      `$scrypt$ln=17,r=32,p=1$${salt}$${key}`,
      `$scrypt$ln=4,r=999,p=1$${salt}$${key}`,
      `$scrypt$ln=0,r=8,p=1$${salt}$${key}`,
      `$scrypt$ln=4,r=8,p=1$${salt}$${b64(Buffer.alloc(4))}`,
    ]) {
      expect(await hasher.verify(hash, 'anything')).toBe(false);
    }
  });

  it('mixes in the pepper', async () => {
    const hash = await scrypt({ ...fast, pepper: 'pepper-one' }).hash('correct horse');
    expect(await scrypt({ ...fast, pepper: 'pepper-one' }).verify(hash, 'correct horse')).toBe(true);
    expect(await scrypt({ ...fast, pepper: 'pepper-two' }).verify(hash, 'correct horse')).toBe(false);
    expect(await scrypt(fast).verify(hash, 'correct horse')).toBe(false);
  });

  it('asks for a rehash when the stored parameters are weaker', async () => {
    const weak = await scrypt(fast).hash('correct horse');
    expect(scrypt().needsRehash(weak)).toBe(true);
    expect(scrypt(fast).needsRehash(weak)).toBe(false);
    expect(scrypt().needsRehash('$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA')).toBe(true);
  });

  it('refuses parameters below the OWASP minimum', () => {
    expect(() => scrypt({ logN: 10 })).toThrow(/OWASP/);
    expect(() => scrypt({ logN: 14, r: 4, p: 10 })).toThrow(/OWASP/);
    expect(() => scrypt({ logN: 30 })).toThrow(/logN/);
    expect(() => scrypt({ logN: 13, r: 8, p: 10 })).not.toThrow();
  });
});
