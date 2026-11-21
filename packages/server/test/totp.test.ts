import { describe, expect, it } from 'vitest';
import { generateRecoveryCode, hashRecoveryCode, normalizeRecoveryCode } from '../src/mfa/recovery-codes.js';
import { generateTotpSecret, hotp, matchTotp, otpauthUri, totpStep, type TotpAlgorithm } from '../src/mfa/totp.js';
import { fromBase32, toBase32 } from '../src/util/encoding.js';

const ascii = (text: string) => new TextEncoder().encode(text);

describe('HOTP (RFC 4226, Appendix D)', () => {
  it('matches the RFC test vectors', async () => {
    const secret = ascii('12345678901234567890');
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    for (const [counter, value] of expected.entries()) {
      expect(await hotp(secret, counter, 6, 'SHA-1')).toBe(value);
    }
  });
});

describe('TOTP (RFC 6238, Appendix B)', () => {
  const secrets: Record<TotpAlgorithm, Uint8Array> = {
    'SHA-1': ascii('12345678901234567890'),
    'SHA-256': ascii('12345678901234567890123456789012'),
    'SHA-512': ascii('1234567890123456789012345678901234567890123456789012345678901234'),
  };
  const vectors: [time: number, sha1: string, sha256: string, sha512: string][] = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];

  it('matches the RFC test vectors for SHA-1, SHA-256 and SHA-512', async () => {
    for (const [time, sha1, sha256, sha512] of vectors) {
      const step = totpStep(time, 30);
      expect(await hotp(secrets['SHA-1'], step, 8, 'SHA-1')).toBe(sha1);
      expect(await hotp(secrets['SHA-256'], step, 8, 'SHA-256')).toBe(sha256);
      expect(await hotp(secrets['SHA-512'], step, 8, 'SHA-512')).toBe(sha512);
    }
  });

  it('computes the time step the RFC lists', () => {
    expect(totpStep(59, 30)).toBe(0x1);
    expect(totpStep(1111111109, 30)).toBe(0x23523ec);
    expect(totpStep(20000000000, 30)).toBe(0x27bc86aa);
  });
});

describe('matchTotp', () => {
  const secret = ascii('12345678901234567890');
  const parameters = { nowSec: 1111111111, period: 30, digits: 8, window: 1, algorithm: 'SHA-1' as const };
  const step = totpStep(1111111111, 30);

  it('returns the step of a code for the current time', async () => {
    expect(await matchTotp(secret, '14050471', parameters)).toBe(step);
  });

  it('accepts one step either side and nothing further', async () => {
    const previous = await hotp(secret, step - 1, 8, 'SHA-1');
    const next = await hotp(secret, step + 1, 8, 'SHA-1');
    const twoBack = await hotp(secret, step - 2, 8, 'SHA-1');
    const twoAhead = await hotp(secret, step + 2, 8, 'SHA-1');
    expect(await matchTotp(secret, previous, parameters)).toBe(step - 1);
    expect(await matchTotp(secret, next, parameters)).toBe(step + 1);
    expect(await matchTotp(secret, twoBack, parameters)).toBeNull();
    expect(await matchTotp(secret, twoAhead, parameters)).toBeNull();
  });

  it('accepts only the current step when the window is 0', async () => {
    const strict = { ...parameters, window: 0 };
    expect(await matchTotp(secret, '14050471', strict)).toBe(step);
    expect(await matchTotp(secret, await hotp(secret, step - 1, 8, 'SHA-1'), strict)).toBeNull();
  });

  it('rejects wrong codes and malformed input', async () => {
    for (const code of ['00000000', '1405047', '140504711', '1405047a', ' 14050471', '', '１４０５０４７１']) {
      expect(await matchTotp(secret, code, parameters)).toBeNull();
    }
    expect(await matchTotp(secret, 14050471 as unknown as string, parameters)).toBeNull();
  });

  it('rejects a code made with another secret', async () => {
    const other = await hotp(ascii('09876543210987654321'), step, 8, 'SHA-1');
    expect(await matchTotp(secret, other, parameters)).toBeNull();
  });
});

describe('TOTP secrets and otpauth URIs', () => {
  it('generates secrets of the recommended length for each hash', () => {
    expect(generateTotpSecret('SHA-1')).toHaveLength(20);
    expect(generateTotpSecret('SHA-256')).toHaveLength(32);
    expect(generateTotpSecret('SHA-512')).toHaveLength(64);
    expect(toBase32(generateTotpSecret('SHA-1'))).not.toBe(toBase32(generateTotpSecret('SHA-1')));
  });

  it('builds an otpauth URI authenticator apps accept', () => {
    const uri = otpauthUri({
      issuer: 'Example & Co',
      account: 'ada+test@example.com',
      secret: ascii('12345678901234567890'),
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
    });
    expect(uri).toBe(
      'otpauth://totp/Example%20%26%20Co:ada%2Btest%40example.com' +
        '?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20%26%20Co&algorithm=SHA1&digits=6&period=30',
    );
  });
});

describe('base32 (RFC 4648)', () => {
  it('matches the RFC test vectors, without padding', () => {
    const vectors: [string, string][] = [
      ['', ''],
      ['f', 'MY'],
      ['fo', 'MZXQ'],
      ['foo', 'MZXW6'],
      ['foob', 'MZXW6YQ'],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI'],
    ];
    for (const [plain, encoded] of vectors) {
      expect(toBase32(ascii(plain))).toBe(encoded);
      expect(new TextDecoder().decode(fromBase32(encoded))).toBe(plain);
    }
  });

  it('decodes lower case, padding, spaces and dashes', () => {
    expect(new TextDecoder().decode(fromBase32('mzxw 6ytb-oi======'))).toBe('foobar');
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => fromBase32('MZXW1')).toThrow(/base32/);
    expect(() => fromBase32('MZ!W6')).toThrow(/base32/);
  });

  it('round-trips random bytes of every length', () => {
    for (let length = 0; length < 40; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect([...fromBase32(toBase32(bytes))]).toEqual([...bytes]);
    }
  });
});

describe('recovery codes', () => {
  it('generates 80-bit codes shown in four groups', () => {
    const codes = new Set(Array.from({ length: 200 }, () => generateRecoveryCode()));
    expect(codes.size).toBe(200);
    for (const code of codes) expect(code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/);
  });

  it('normalises what a person types', () => {
    expect(normalizeRecoveryCode('abcd-efgh-ijkl-mnop')).toBe('ABCDEFGHIJKLMNOP');
    expect(normalizeRecoveryCode(' ABCD EFGH IJKL MNOP ')).toBe('ABCDEFGHIJKLMNOP');
    expect(normalizeRecoveryCode('ABCDEFGHIJKLMNOP')).toBe('ABCDEFGHIJKLMNOP');
    // 0, 1 and 8 are not in the alphabet, so they can only be typos for O, I and B.
    expect(normalizeRecoveryCode('A0C1-EFG8-IJKL-MN2P')).toBe('AOCIEFGBIJKLMN2P');
  });

  it('rejects input that cannot be a code', () => {
    for (const input of ['', 'ABCD', 'ABCD-EFGH-IJKL-MNO', 'ABCD-EFGH-IJKL-MNOPQ', 'ABCD-EFGH-IJKL-MNO9', 'x'.repeat(100)]) {
      expect(normalizeRecoveryCode(input)).toBeNull();
    }
    expect(normalizeRecoveryCode(123456 as unknown)).toBeNull();
    expect(normalizeRecoveryCode(null)).toBeNull();
  });

  it('hashes the same code differently for different users', async () => {
    const one = await hashRecoveryCode('user-1', 'ABCDEFGHIJKLMNOP');
    expect(one).toBe(await hashRecoveryCode('user-1', 'ABCDEFGHIJKLMNOP'));
    expect(one).not.toBe(await hashRecoveryCode('user-2', 'ABCDEFGHIJKLMNOP'));
    expect(one).not.toContain('ABCDEFGHIJKLMNOP');
  });
});
