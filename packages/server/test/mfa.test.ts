import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { fromBase32 } from '../src/util/encoding.js';
import {
  PASSWORD,
  createAuthEnv,
  createDevice,
  createUser,
  enrollTotp,
  loginWithMfa,
  loginWithPassword,
  totpCode,
  type AuthEnv,
  type Device,
} from './env.js';
import { expectAuthError } from './helpers.js';

const LOGIN = '/auth/login/password';
const VERIFY = '/auth/mfa/verify';

async function setup(overrides = {}) {
  const env = createAuthEnv(overrides);
  const user = await createUser(env);
  const device = await createDevice(env.clock);
  return { env, user, device };
}

/** First factor only: returns the ticket of a login that is waiting for its second factor. */
async function firstFactor(env: AuthEnv, device: Device) {
  const result = await env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, await device.ctx('POST', LOGIN));
  if (result.status !== 'mfa_required') throw new Error(`Expected mfa_required, got ${result.status}`);
  return result;
}

/** Moves the clock to the next TOTP time step, so a fresh code is available. */
function nextStep(env: AuthEnv) {
  env.clock.advanceSec(30);
}

describe('TOTP enrolment', () => {
  it('returns a secret and an otpauth URI, and changes nothing until confirmed', async () => {
    const { env, user } = await setup();
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);

    expect(enrollment.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(fromBase32(enrollment.secret)).toHaveLength(20);
    expect(enrollment.otpauthUri).toBe(
      `otpauth://totp/api.example.com:ada%40example.com?secret=${enrollment.secret}&issuer=api.example.com&algorithm=SHA1&digits=6&period=30`,
    );
    expect(await env.auth.mfa.status(user.id)).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });
    // Login is unaffected by an enrolment that was started but not finished.
    await loginWithPassword(env, await createDevice(env.clock));
  });

  it('uses the configured issuer name', async () => {
    const { env, user } = await setup({ mfa: { totp: { issuer: 'Example Corp' } } });
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);
    expect(enrollment.otpauthUri).toContain('otpauth://totp/Example%20Corp:ada%40example.com?');
    expect(enrollment.otpauthUri).toContain('&issuer=Example%20Corp&');
  });

  it('activates on a correct code and returns ten recovery codes once', async () => {
    const { env, user } = await setup();
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);
    const { recoveryCodes } = await env.auth.mfa.confirmTotpEnrollment(user.id, {
      enrollmentId: enrollment.enrollmentId,
      code: await totpCode(env.clock, enrollment.secret),
    });

    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);
    for (const code of recoveryCodes) expect(code).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
    expect(await env.auth.mfa.status(user.id)).toEqual({ totp: true, recoveryCodes: 10, passkeys: 0 });
    expect(env.sink.ofType('mfa.totp.enrolled')[0]!.userId).toBe(user.id);
    expect(env.sink.ofType('mfa.recovery_codes.generated')[0]!.data).toEqual({ count: 10 });
  });

  it('rejects a wrong confirmation code and allows another try', async () => {
    const { env, user } = await setup();
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);
    await expectAuthError(
      env.auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: enrollment.enrollmentId, code: '000000' }),
      'MFA_CODE_INVALID',
    );
    expect(await env.auth.mfa.status(user.id)).toMatchObject({ totp: false });
    await env.auth.mfa.confirmTotpEnrollment(user.id, {
      enrollmentId: enrollment.enrollmentId,
      code: await totpCode(env.clock, enrollment.secret),
    });
  });

  it('gives up on an enrolment after too many wrong codes', async () => {
    const { env, user } = await setup();
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);
    for (let attempt = 0; attempt < 5; attempt++) {
      await expectAuthError(
        env.auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: enrollment.enrollmentId, code: '000000' }),
        'MFA_CODE_INVALID',
      );
    }
    await expectAuthError(
      env.auth.mfa.confirmTotpEnrollment(user.id, {
        enrollmentId: enrollment.enrollmentId,
        code: await totpCode(env.clock, enrollment.secret),
      }),
      'MFA_TICKET_INVALID',
    );
  });

  it('rejects an enrolment id that is unknown, expired, used or belongs to someone else', async () => {
    const { env, user } = await setup();
    const other = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    const enrollment = await env.auth.mfa.beginTotpEnrollment(user.id);
    const code = () => totpCode(env.clock, enrollment.secret);

    await expectAuthError(env.auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: 'nope', code: await code() }), 'MFA_TICKET_INVALID');
    await expectAuthError(
      env.auth.mfa.confirmTotpEnrollment(other.id, { enrollmentId: enrollment.enrollmentId, code: await code() }),
      'MFA_TICKET_INVALID',
    );
    await env.auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: enrollment.enrollmentId, code: await code() });
    await expectAuthError(
      env.auth.mfa.confirmTotpEnrollment(user.id, { enrollmentId: enrollment.enrollmentId, code: await code() }),
      'MFA_TICKET_INVALID',
    );

    const late = await env.auth.mfa.beginTotpEnrollment(other.id);
    env.clock.advanceSec(601);
    await expectAuthError(
      env.auth.mfa.confirmTotpEnrollment(other.id, { enrollmentId: late.enrollmentId, code: await totpCode(env.clock, late.secret) }),
      'MFA_TICKET_INVALID',
    );
  });

  it('refuses a second enrolment while one is active', async () => {
    const { env, user } = await setup();
    await enrollTotp(env, user.id);
    await expectAuthError(env.auth.mfa.beginTotpEnrollment(user.id), 'MFA_ALREADY_ENROLLED');
    await expectAuthError(env.auth.mfa.beginTotpEnrollment('missing-user'), 'USER_NOT_FOUND');
  });

  it('stores the seed encrypted and the recovery codes hashed', async () => {
    const { env, user } = await setup();
    const { secret, recoveryCodes } = await enrollTotp(env, user.id);
    const stored = await env.adapter.credentials.getTotp(user.id);

    expect(stored!.encryptedSecret.split('.')).toHaveLength(5);
    const dump = JSON.stringify(stored);
    expect(dump).not.toContain(secret);
    expect(dump).not.toContain(Buffer.from(fromBase32(secret)).toString('base64url'));

    for (const code of recoveryCodes) {
      expect(await env.adapter.credentials.consumeRecoveryCode(user.id, code, new Date())).toBe(false);
      expect(await env.adapter.credentials.consumeRecoveryCode(user.id, code.replace(/-/g, ''), new Date())).toBe(false);
    }
    expect(await env.adapter.credentials.countRecoveryCodes(user.id)).toBe(10);
  });
});

describe('login with TOTP', () => {
  it('asks for a second factor and completes at aal2', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);

    const first = await firstFactor(env, device);
    expect(first).toMatchObject({ status: 'mfa_required', methods: ['totp', 'recovery_code'], reason: 'enrolled' });
    expect(first.expiresAt).toBe(Math.floor(env.clock() / 1000) + 300);
    expect(first).not.toHaveProperty('accessToken');
    expect(first).not.toHaveProperty('refreshToken');

    const done = await env.auth.mfa.verify(
      { ticket: first.ticket, method: 'totp', code: await totpCode(env.clock, secret) },
      await device.ctx('POST', VERIFY),
    );
    expect(done.session).toMatchObject({ methods: ['pwd', 'otp'], assurance: 'aal2', deviceBound: true });
    expect(decodeJwt(done.accessToken)).toMatchObject({ sub: user.id, amr: ['pwd', 'otp'], acr: 'aal2' });
    expect(env.sink.ofType('mfa.challenged')[0]!.data).toEqual({ reason: 'enrolled', methods: ['totp', 'recovery_code'] });
    expect(env.sink.ofType('login.succeeded')[0]!.data).toMatchObject({ method: 'pwd', mfa: true });
  });

  it('creates no session until the second factor is verified', async () => {
    const { env, user, device } = await setup();
    await enrollTotp(env, user.id);
    nextStep(env);
    await firstFactor(env, device);
    expect(await env.auth.sessions.list(user.id)).toEqual([]);
    expect(env.sink.ofType('session.created')).toHaveLength(0);
  });

  it('rejects the code that confirmed enrolment when it is replayed at login', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);

    // The code that confirmed enrolment belongs to the current time step and is already spent.
    const spent = await totpCode(env.clock, secret);
    const first = await firstFactor(env, device);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: spent }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
    expect(env.sink.ofType('mfa.failed').at(-1)).toMatchObject({ reason: 'replayed', data: { method: 'totp', purpose: 'login' } });

    // A code from the next step is accepted.
    nextStep(env);
    const fresh = await totpCode(env.clock, secret);
    await env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: fresh }, await device.ctx('POST', VERIFY));
  });

  it('rejects a replayed code from the same device with the generic error', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const code = await totpCode(env.clock, secret);
    await loginWithMfa(env, device, code);

    const again = await firstFactor(env, device);
    const error = await expectAuthError(
      env.auth.mfa.verify({ ticket: again.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
    // The caller cannot tell a replay from a typo. The audit log can.
    expect(error.toJSON()).toEqual({ code: 'MFA_CODE_INVALID', message: 'The code is not valid.' });
    expect(env.sink.ofType('mfa.failed').at(-1)!.reason).toBe('replayed');
  });

  it('does not accept an older code once a newer one has been used', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const older = await totpCode(env.clock, secret);
    nextStep(env);
    const newer = await totpCode(env.clock, secret);
    await loginWithMfa(env, device, newer);

    const again = await firstFactor(env, device);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: again.ticket, method: 'totp', code: older }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
  });

  it('accepts codes one step either side of the clock, and no further', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    env.clock.advanceSec(300);

    const tooOld = await totpCode(env.clock, secret, -2);
    const tooNew = await totpCode(env.clock, secret, 2);
    const first = await firstFactor(env, device);
    for (const code of [tooOld, tooNew]) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
    expect(env.sink.ofType('mfa.failed').at(-1)!.reason).toBe('invalid');

    // A phone whose clock runs 30 seconds slow still works.
    const slow = await totpCode(env.clock, secret, -1);
    await env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: slow }, await device.ctx('POST', VERIFY));
  });

  it('rejects wrong and malformed codes', async () => {
    const { env, user, device } = await setup();
    await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    for (const code of ['000000', '12345', '1234567', 'abcdef', '']) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
  });

  it('removes the requirement when TOTP is removed', async () => {
    const { env, user, device } = await setup();
    await enrollTotp(env, user.id);
    await env.auth.mfa.removeTotp(user.id);
    expect(await env.auth.mfa.status(user.id)).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });
    expect(await env.adapter.credentials.countRecoveryCodes(user.id)).toBe(0);
    const result = await loginWithPassword(env, device);
    expect(result.session.assurance).toBe('aal1');
    await expectAuthError(env.auth.mfa.removeTotp(user.id), 'MFA_NOT_ENROLLED');
  });
});

describe('MFA rate limiting', () => {
  it('blocks a user after five wrong codes, even for the right code', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);

    // Two tickets, so the per-ticket limit does not get in the way of the per-user one.
    const one = await firstFactor(env, device);
    for (let attempt = 0; attempt < 3; attempt++) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: one.ticket, method: 'totp', code: '000000' }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
    const two = await firstFactor(env, device);
    for (let attempt = 0; attempt < 2; attempt++) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: two.ticket, method: 'totp', code: '000000' }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }

    const blocked = await expectAuthError(
      env.auth.mfa.verify({ ticket: two.ticket, method: 'totp', code: await totpCode(env.clock, secret) }, await device.ctx('POST', VERIFY)),
      'RATE_LIMITED',
    );
    expect(blocked.status).toBe(429);
    expect(blocked.details).toEqual({ retryAfterSec: 900 });
    expect(env.sink.ofType('rate_limit.exceeded').at(-1)).toMatchObject({ userId: user.id, data: { scope: 'mfa' } });

    // Recovery codes are covered by the same limit.
    await expectAuthError(
      env.auth.mfa.verify({ ticket: two.ticket, method: 'recovery_code', code: 'AAAA-AAAA-AAAA-AAAA' }, await device.ctx('POST', VERIFY)),
      'RATE_LIMITED',
    );
  });

  it('lifts the block when the window ends', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    for (let attempt = 0; attempt < 5; attempt++) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: '000000' }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
    env.clock.advanceSec(901);
    await loginWithMfa(env, device, await totpCode(env.clock, secret));
  });

  it('does not let one user’s failures block another user', async () => {
    const { env, user, device } = await setup();
    const bob = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    await enrollTotp(env, user.id);
    const bobTotp = await enrollTotp(env, bob.id);
    nextStep(env);

    const first = await firstFactor(env, device);
    for (let attempt = 0; attempt < 5; attempt++) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: '000000' }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
    const bobDevice = await createDevice(env.clock);
    await loginWithMfa(env, bobDevice, await totpCode(env.clock, bobTotp.secret), 'totp', 'bob@example.com');
  });
});

describe('MFA tickets', () => {
  it('works once', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    await env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: await totpCode(env.clock, secret) }, await device.ctx('POST', VERIFY));

    nextStep(env);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: await totpCode(env.clock, secret) }, await device.ctx('POST', VERIFY)),
      'MFA_TICKET_INVALID',
    );
  });

  it('expires after five minutes', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    env.clock.advanceSec(301);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: await totpCode(env.clock, secret) }, await device.ctx('POST', VERIFY)),
      'MFA_TICKET_INVALID',
    );
  });

  it('is destroyed after five wrong codes', async () => {
    const { env, user, device } = await setup({ mfa: { rateLimit: { maxFailures: 50 } } });
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    for (let attempt = 0; attempt < 5; attempt++) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: '000000' }, await device.ctx('POST', VERIFY)),
        'MFA_CODE_INVALID',
      );
    }
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code: await totpCode(env.clock, secret) }, await device.ctx('POST', VERIFY)),
      'MFA_TICKET_INVALID',
    );
  });

  it('must be redeemed by the device that passed the first factor', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    const code = await totpCode(env.clock, secret);

    // An attacker who intercepts the ticket and the code still lacks the device key.
    const attacker = await createDevice(env.clock, { ip: '198.51.100.9' });
    await expectAuthError(env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await attacker.ctx('POST', VERIFY)), 'DPOP_KEY_MISMATCH');
    await expectAuthError(env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, attacker.bare()), 'DPOP_PROOF_REQUIRED');
    expect(env.sink.ofType('dpop.rejected').map((event) => event.data.during)).toEqual(['mfa', 'mfa']);

    // Those attempts did not spend the code or the ticket.
    const done = await env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY));
    expect(done.session.deviceBound).toBe(true);
    expect(decodeJwt(done.accessToken).cnf).toEqual({ jkt: device.key.jkt });
  });

  it('yields one session when two requests race with the same ticket and code', async () => {
    const { env, user, device } = await setup();
    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    const code = await totpCode(env.clock, secret);

    const results = await Promise.allSettled([
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
      env.auth.mfa.verify({ ticket: first.ticket, method: 'totp', code }, await device.ctx('POST', VERIFY)),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(await env.auth.sessions.list(user.id)).toHaveLength(1);
  });

  it('rejects junk tickets and unknown methods', async () => {
    const { env, user, device } = await setup();
    await enrollTotp(env, user.id);
    nextStep(env);
    const first = await firstFactor(env, device);
    for (const ticket of ['', 'nope', 'x'.repeat(1000), undefined]) {
      await expectAuthError(
        env.auth.mfa.verify({ ticket: ticket as string, method: 'totp', code: '123456' }, await device.ctx('POST', VERIFY)),
        'MFA_TICKET_INVALID',
      );
    }
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'sms' as never, code: '123456' }, await device.ctx('POST', VERIFY)),
      'REQUEST_INVALID',
    );
  });
});

describe('recovery codes', () => {
  it('completes a login and works once', async () => {
    const { env, user, device } = await setup();
    const { recoveryCodes } = await enrollTotp(env, user.id);
    const done = await loginWithMfa(env, device, recoveryCodes[0]!, 'recovery_code');
    expect(done.session).toMatchObject({ methods: ['pwd', 'recovery'], assurance: 'aal2' });
    expect(env.sink.ofType('mfa.recovery_code.used')[0]!.data).toEqual({ remaining: 9 });
    expect(await env.auth.mfa.status(user.id)).toMatchObject({ recoveryCodes: 9 });

    const again = await firstFactor(env, device);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: again.ticket, method: 'recovery_code', code: recoveryCodes[0]! }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
  });

  it('accepts a code typed in lower case, without dashes, or with look-alike digits', async () => {
    const { env, user, device } = await setup();
    const { recoveryCodes } = await enrollTotp(env, user.id);
    await loginWithMfa(env, device, recoveryCodes[0]!.toLowerCase(), 'recovery_code');
    await loginWithMfa(env, device, recoveryCodes[1]!.replace(/-/g, ''), 'recovery_code');
    await loginWithMfa(env, device, ` ${recoveryCodes[2]!.replace(/-/g, ' ')} `, 'recovery_code');
    const withTypos = recoveryCodes[3]!.replace(/O/g, '0').replace(/I/g, '1').replace(/B/g, '8');
    await loginWithMfa(env, device, withTypos, 'recovery_code');
  });

  it('rejects a recovery code that belongs to another user', async () => {
    const { env, user, device } = await setup();
    const bob = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    await enrollTotp(env, user.id);
    const bobCodes = await enrollTotp(env, bob.id);
    const first = await firstFactor(env, device);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'recovery_code', code: bobCodes.recoveryCodes[0]! }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
    expect(await env.auth.mfa.status(bob.id)).toMatchObject({ recoveryCodes: 10 });
  });

  it('lets a code be used for only one of two simultaneous logins', async () => {
    const { env, user } = await setup();
    const { recoveryCodes } = await enrollTotp(env, user.id);
    const laptop = await createDevice(env.clock);
    const phone = await createDevice(env.clock);
    const one = await firstFactor(env, laptop);
    const two = await firstFactor(env, phone);

    const results = await Promise.allSettled([
      env.auth.mfa.verify({ ticket: one.ticket, method: 'recovery_code', code: recoveryCodes[0]! }, await laptop.ctx('POST', VERIFY)),
      env.auth.mfa.verify({ ticket: two.ticket, method: 'recovery_code', code: recoveryCodes[0]! }, await phone.ctx('POST', VERIFY)),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(await env.auth.mfa.status(user.id)).toMatchObject({ recoveryCodes: 9 });
  });

  it('replaces all codes on regeneration', async () => {
    const { env, user, device } = await setup();
    const { recoveryCodes: old } = await enrollTotp(env, user.id);
    const fresh = await env.auth.mfa.regenerateRecoveryCodes(user.id);
    expect(fresh).toHaveLength(10);
    expect(fresh.some((code) => old.includes(code))).toBe(false);

    const first = await firstFactor(env, device);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: first.ticket, method: 'recovery_code', code: old[0]! }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
    await env.auth.mfa.verify({ ticket: first.ticket, method: 'recovery_code', code: fresh[0]! }, await device.ctx('POST', VERIFY));
  });

  it('cannot be generated without TOTP', async () => {
    const { env, user } = await setup();
    await expectAuthError(env.auth.mfa.regenerateRecoveryCodes(user.id), 'MFA_NOT_ENROLLED');
  });

  it('stops being offered when none are left', async () => {
    const { env, user, device } = await setup({ mfa: { recoveryCodes: { count: 1 } } });
    const { recoveryCodes } = await enrollTotp(env, user.id);
    await loginWithMfa(env, device, recoveryCodes[0]!, 'recovery_code');
    const next = await firstFactor(env, device);
    expect(next.methods).toEqual(['totp']);
    await expectAuthError(
      env.auth.mfa.verify({ ticket: next.ticket, method: 'recovery_code', code: recoveryCodes[0]! }, await device.ctx('POST', VERIFY)),
      'MFA_CODE_INVALID',
    );
  });
});

describe('step-up with a second factor', () => {
  it('raises an existing session to aal2', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const device = await createDevice(env.clock);
    const login = await loginWithPassword(env, device);
    expect(login.session.assurance).toBe('aal1');

    const { secret } = await enrollTotp(env, user.id);
    nextStep(env);
    const grant = await env.auth.sessions.reauthenticate(login.session.id, { method: 'totp', code: await totpCode(env.clock, secret) });
    expect(grant.session).toMatchObject({ assurance: 'aal2', methods: ['pwd', 'otp'] });
    expect(decodeJwt(grant.accessToken)).toMatchObject({ acr: 'aal2', amr: ['pwd', 'otp'] });
    expect(env.sink.ofType('mfa.verified').at(-1)!.data).toEqual({ method: 'totp', purpose: 'reauthentication' });

    // The session stays at aal2 through later refreshes.
    const refreshed = await env.auth.sessions.refresh(login.refreshToken, await device.ctx('POST', '/auth/refresh'));
    expect(refreshed.session.assurance).toBe('aal2');
  });

  it('rejects a wrong code and a replayed one', async () => {
    const env = createAuthEnv();
    const user = await createUser(env);
    const login = await loginWithPassword(env, await createDevice(env.clock));
    const { secret } = await enrollTotp(env, user.id);
    await expectAuthError(env.auth.sessions.reauthenticate(login.session.id, { method: 'totp', code: '000000' }), 'MFA_CODE_INVALID');
    nextStep(env);
    const code = await totpCode(env.clock, secret);
    await env.auth.sessions.reauthenticate(login.session.id, { method: 'totp', code });
    await expectAuthError(env.auth.sessions.reauthenticate(login.session.id, { method: 'totp', code }), 'MFA_CODE_INVALID');
  });
});
