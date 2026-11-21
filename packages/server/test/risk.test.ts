import { describe, expect, it } from 'vitest';
import type { DeviceRecord, User } from '../src/adapters/types.js';
import { failedAttempts, haversineKm, networkPrefix, newDevice, newLocation, newNetwork } from '../src/risk/signals.js';
import type { GeoLocation, RiskInput, RiskSignal } from '../src/risk/types.js';
import { SoftwareAuthenticator } from './authenticator.js';
import {
  APP_ORIGIN,
  PASSWORD,
  createAuthEnv,
  createDevice,
  createUser,
  enrollTotp,
  loginWithPassword,
  totpCode,
  type AuthEnv,
  type Device,
} from './env.js';
import { expectAuthError } from './helpers.js';

const LOGIN = '/auth/login/password';
const NOW = new Date(Date.UTC(2026, 0, 15, 12));
const HOUR = 3_600_000;
const DAY = 86_400_000;

const user: User = { id: 'u1', identifier: 'ada@example.com', roles: [], status: 'active', attributes: {}, createdAt: NOW };

function device(overrides: Partial<DeviceRecord> = {}): DeviceRecord {
  return {
    userId: 'u1',
    deviceKey: 'known-key',
    firstSeenAt: new Date(NOW.getTime() - 10 * DAY),
    lastSeenAt: new Date(NOW.getTime() - DAY),
    lastIp: '203.0.113.10',
    lastCountry: 'DE',
    lastLatitude: 52.52,
    lastLongitude: 13.4,
    ...overrides,
  };
}

function input(overrides: Partial<RiskInput> = {}): RiskInput {
  return {
    user,
    ip: '203.0.113.10',
    userAgent: 'test',
    deviceKey: 'known-key',
    location: null,
    now: NOW,
    devices: [device()],
    failures: { account: 0, ip: 0 },
    ...overrides,
  };
}

describe('newDevice', () => {
  const signal = newDevice();
  it('fires for a key the user has not signed in with', async () => {
    expect(await signal(input({ deviceKey: 'other-key' }))).toEqual({ name: 'new_device', score: 30 });
  });
  it('stays quiet for a known key, on a first login, and without a device key', async () => {
    expect(await signal(input())).toBeNull();
    expect(await signal(input({ deviceKey: 'other-key', devices: [] }))).toBeNull();
    expect(await signal(input({ deviceKey: undefined }))).toBeNull();
  });
  it('uses the configured score', async () => {
    expect(await newDevice({ score: 55 })(input({ deviceKey: 'x' }))).toEqual({ name: 'new_device', score: 55 });
  });
});

describe('newNetwork', () => {
  const signal = newNetwork();
  it('fires for an address outside the networks the user signed in from', async () => {
    expect(await signal(input({ ip: '198.51.100.7' }))).toEqual({ name: 'new_network', score: 15 });
  });
  it('treats addresses in the same /24 as the same network', async () => {
    expect(await signal(input({ ip: '203.0.113.200' }))).toBeNull();
    expect(await signal(input({ ip: '203.0.114.10' }))).not.toBeNull();
  });
  it('treats IPv6 addresses in the same /48 as the same network', async () => {
    const known = [device({ lastIp: '2001:db8:1234:5678::1' })];
    expect(await signal(input({ ip: '2001:db8:1234:9999::42', devices: known }))).toBeNull();
    expect(await signal(input({ ip: '2001:db8:1235::1', devices: known }))).not.toBeNull();
  });
  it('stays quiet without an address or without history', async () => {
    expect(await signal(input({ ip: undefined }))).toBeNull();
    expect(await signal(input({ ip: '198.51.100.7', devices: [] }))).toBeNull();
    expect(await signal(input({ ip: '198.51.100.7', devices: [device({ lastIp: null })] }))).toBeNull();
  });
  it('ignores sightings older than the look-back period', async () => {
    const old = [device({ lastSeenAt: new Date(NOW.getTime() - 100 * DAY) })];
    expect(await signal(input({ ip: '198.51.100.7', devices: old }))).toBeNull();
    expect(await newNetwork({ withinDays: 365 })(input({ ip: '198.51.100.7', devices: old }))).not.toBeNull();
  });
});

describe('newLocation', () => {
  const berlin: GeoLocation = { country: 'DE', latitude: 52.52, longitude: 13.4 };
  const munich: GeoLocation = { country: 'DE', latitude: 48.14, longitude: 11.58 };
  const newYork: GeoLocation = { country: 'US', latitude: 40.71, longitude: -74.01 };
  const signal = newLocation({ locate: () => berlin });

  it('fires when the country differs from recent logins', async () => {
    expect(await signal(input({ location: newYork }))).toEqual({ name: 'new_location', score: 25 });
  });
  it('stays quiet in a known country at a plausible distance', async () => {
    expect(await signal(input({ location: berlin }))).toBeNull();
    expect(await signal(input({ location: munich }))).toBeNull();
  });
  it('fires on travel faster than a plane within the same country', async () => {
    // Berlin to Munich is about 500 km. Twenty minutes is not enough.
    const recent = [device({ lastSeenAt: new Date(NOW.getTime() - HOUR / 3) })];
    expect(await signal(input({ location: munich, devices: recent }))).toEqual({ name: 'new_location', score: 25 });
    // Three hours is.
    const earlier = [device({ lastSeenAt: new Date(NOW.getTime() - 3 * HOUR) })];
    expect(await signal(input({ location: munich, devices: earlier }))).toBeNull();
  });
  it('ignores small distances, which are within the error of IP geolocation', async () => {
    const nearby: GeoLocation = { country: 'DE', latitude: 52.4, longitude: 13.1 };
    const justNow = [device({ lastSeenAt: new Date(NOW.getTime() - 60_000) })];
    expect(await signal(input({ location: nearby, devices: justNow }))).toBeNull();
  });
  it('stays quiet without a location or without history', async () => {
    expect(await signal(input({ location: null }))).toBeNull();
    expect(await signal(input({ location: newYork, devices: [] }))).toBeNull();
  });
  it('carries its locator for the engine to call', () => {
    expect(typeof signal.locate).toBe('function');
    expect(newDevice().locate).toBeUndefined();
  });
});

describe('failedAttempts', () => {
  const signal = failedAttempts();
  it('scores ten per failure up to forty, using the higher of account and address', async () => {
    expect(await signal(input())).toBeNull();
    expect(await signal(input({ failures: { account: 1, ip: 0 } }))).toEqual({ name: 'failed_attempts', score: 10 });
    expect(await signal(input({ failures: { account: 1, ip: 3 } }))).toEqual({ name: 'failed_attempts', score: 30 });
    expect(await signal(input({ failures: { account: 9, ip: 0 } }))).toEqual({ name: 'failed_attempts', score: 40 });
  });
});

describe('helpers', () => {
  it('reduces addresses to their network', () => {
    expect(networkPrefix('203.0.113.10')).toBe('203.0.113');
    expect(networkPrefix('::ffff:203.0.113.10')).toBe('203.0.113');
    expect(networkPrefix('2001:0db8:1234:5678::1')).toBe('2001:db8:1234');
    expect(networkPrefix('2001:db8::1')).toBe('2001:db8:0');
    expect(networkPrefix('::1')).toBe('0:0:0');
    expect(networkPrefix('fe80::1%eth0')).toBe('fe80:0:0');
    expect(networkPrefix('not-an-ip')).toBe('not-an-ip');
  });
  it('computes great-circle distances', () => {
    expect(haversineKm(52.52, 13.4, 48.14, 11.58)).toBeGreaterThan(480);
    expect(haversineKm(52.52, 13.4, 48.14, 11.58)).toBeLessThan(520);
    expect(haversineKm(52.52, 13.4, 40.71, -74.01)).toBeGreaterThan(6300);
    expect(haversineKm(10, 20, 10, 20)).toBe(0);
  });
});

// ---------------------------------------------------------------------------------------------
// Through the login flow
// ---------------------------------------------------------------------------------------------

const fixed = (name: string, score: number): RiskSignal => () => ({ name, score });

async function attempt(env: AuthEnv, from: Device, password = PASSWORD) {
  return env.auth.login.withPassword({ identifier: 'ada@example.com', password }, await from.ctx('POST', LOGIN));
}

describe('risk-based login decisions', () => {
  it('lets a low score through and records the assessment', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 10), fixed('b', 25)] } });
    const created = await createUser(env);
    const result = await attempt(env, await createDevice(env.clock));
    expect(result.status).toBe('authenticated');

    const [assessment] = env.sink.ofType('risk.evaluated');
    expect(assessment).toMatchObject({
      outcome: 'success',
      userId: created.id,
      data: { score: 35, decision: 'allow', signals: [{ name: 'a', score: 10 }, { name: 'b', score: 25 }] },
    });
    expect(env.sink.ofType('login.succeeded')[0]!.data.riskScore).toBe(35);
  });

  it('requires MFA from the step-up threshold, with the reason given as risk', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 40)] } });
    const created = await createUser(env);
    const { secret } = await enrollTotp(env, created.id);
    env.clock.advanceSec(30);
    const from = await createDevice(env.clock);

    const result = await attempt(env, from);
    expect(result).toMatchObject({ status: 'mfa_required', reason: 'risk' });
    expect(env.sink.ofType('risk.evaluated')[0]!.data.decision).toBe('step_up');

    if (result.status !== 'mfa_required') throw new Error('unreachable');
    const done = await env.auth.mfa.verify(
      { ticket: result.ticket, method: 'totp', code: await totpCode(env.clock, secret) },
      await from.ctx('POST', '/auth/mfa/verify'),
    );
    expect(done.session.assurance).toBe('aal2');
    expect(env.sink.ofType('login.succeeded')[0]!.data).toMatchObject({ riskScore: 40, mfa: true });
  });

  it('lets a step-up through for a user with no second factor, and records that it was called for', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 45)] } });
    const created = await createUser(env);
    const result = await attempt(env, await createDevice(env.clock));
    expect(result.status === 'authenticated' && result.session.assurance).toBe('aal1');
    // Nothing could be asked of the user, but the log shows the login was risky.
    expect(env.sink.ofType('risk.evaluated')[0]).toMatchObject({ userId: created.id, data: { score: 45, decision: 'step_up' } });
    expect(env.sink.ofType('login.succeeded')[0]!.data).toMatchObject({ riskScore: 45, mfa: false });
  });

  it('refuses that login instead when configured to deny', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 45)], whenStepUpUnavailable: 'deny' } });
    const created = await createUser(env);
    const error = await expectAuthError(attempt(env, await createDevice(env.clock)), 'RISK_DENIED');
    expect(error.status).toBe(403);
    expect(error.toJSON()).toEqual({ code: 'RISK_DENIED', message: 'This sign-in was blocked.' });
    expect(env.sink.ofType('login.failed')[0]).toMatchObject({ reason: 'RISK_DENIED', userId: created.id });
    expect(await env.auth.sessions.list(created.id)).toEqual([]);
  });

  it('denies from the deny threshold even when a second factor is enrolled', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 60), fixed('b', 30)] } });
    const created = await createUser(env);
    await enrollTotp(env, created.id);
    await expectAuthError(attempt(env, await createDevice(env.clock)), 'RISK_DENIED');
    const [assessment] = env.sink.ofType('risk.evaluated');
    expect(assessment).toMatchObject({ outcome: 'failure', data: { score: 90, decision: 'deny' } });
    expect(env.sink.ofType('mfa.challenged')).toHaveLength(0);
  });

  it('caps the score at 100', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 80), fixed('b', 80)], denyAt: 100 } });
    await createUser(env);
    await expectAuthError(attempt(env, await createDevice(env.clock)), 'RISK_DENIED');
    expect(env.sink.ofType('risk.evaluated')[0]!.data.score).toBe(100);
  });

  it('honours configured thresholds', async () => {
    const strict = createAuthEnv({ risk: { signals: [fixed('a', 20)], stepUpAt: 10, denyAt: 20 } });
    await createUser(strict);
    await expectAuthError(attempt(strict, await createDevice(strict.clock)), 'RISK_DENIED');

    const lenient = createAuthEnv({ risk: { signals: [fixed('a', 95)], stepUpAt: 100, denyAt: 1000 } });
    await createUser(lenient);
    expect((await attempt(lenient, await createDevice(lenient.clock))).status).toBe('authenticated');
  });

  it('does not evaluate risk for a wrong password, so an attacker learns nothing from it', async () => {
    let calls = 0;
    const spy: RiskSignal = () => {
      calls++;
      return { name: 'spy', score: 95 };
    };
    const env = createAuthEnv({ risk: { signals: [spy] } });
    await createUser(env);
    await expectAuthError(attempt(env, await createDevice(env.clock), 'the wrong password'), 'INVALID_CREDENTIALS');
    expect(calls).toBe(0);
    expect(env.sink.ofType('risk.evaluated')).toHaveLength(0);

    await expectAuthError(attempt(env, await createDevice(env.clock)), 'RISK_DENIED');
    expect(calls).toBe(1);
  });

  it('ignores a signal or locator that throws, and a signal that returns nonsense', async () => {
    const broken: RiskSignal = () => {
      throw new Error('GeoIP service is down');
    };
    const brokenLocator = newLocation({
      locate: () => {
        throw new Error('lookup failed');
      },
    });
    const nonsense = (() => ({ name: 'nan', score: Number.NaN })) as RiskSignal;
    const negative = fixed('negative', -50);
    const env = createAuthEnv({ risk: { signals: [broken, brokenLocator, nonsense, negative, fixed('ok', 5)] } });
    await createUser(env);
    expect((await attempt(env, await createDevice(env.clock))).status).toBe('authenticated');
    expect(env.sink.ofType('risk.evaluated')[0]!.data).toEqual({ score: 5, decision: 'allow', signals: [{ name: 'ok', score: 5 }] });
  });

  it('passes a custom signal everything it needs', async () => {
    let seen: RiskInput | undefined;
    const capture: RiskSignal = (riskInput) => {
      seen = riskInput;
      return null;
    };
    const env = createAuthEnv({ risk: { signals: [capture] } });
    const created = await createUser(env);
    const from = await createDevice(env.clock, { ip: '203.0.113.77', userAgent: 'custom-agent' });
    await attempt(env, from);
    expect(seen).toMatchObject({
      user: { id: created.id },
      ip: '203.0.113.77',
      userAgent: 'custom-agent',
      deviceKey: from.key.jkt,
      location: null,
      devices: [],
      failures: { account: 0, ip: 0 },
    });
  });
});

describe('default signals through the login flow', () => {
  it('lets a first login through and remembers the device', async () => {
    const env = createAuthEnv();
    const created = await createUser(env);
    const laptop = await createDevice(env.clock);
    await loginWithPassword(env, laptop);
    expect(env.sink.ofType('risk.evaluated')[0]!.data).toEqual({ score: 0, decision: 'allow', signals: [] });
    expect(await env.adapter.devices.listByUser(created.id)).toMatchObject([{ deviceKey: laptop.key.jkt, lastIp: laptop.ip }]);
  });

  it('allows a new device alone and a new network alone', async () => {
    const env = createAuthEnv();
    await createUser(env);
    const laptop = await createDevice(env.clock, { ip: '203.0.113.10' });
    await loginWithPassword(env, laptop);

    // Same network, new browser.
    await loginWithPassword(env, await createDevice(env.clock, { ip: '203.0.113.99' }));
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toEqual({ score: 30, decision: 'allow', signals: [{ name: 'new_device', score: 30 }] });

    // Same browser, new network.
    const moved = await env.auth.login.withPassword(
      { identifier: 'ada@example.com', password: PASSWORD },
      { ...(await laptop.ctx('POST', LOGIN)), ip: '198.51.100.5' },
    );
    expect(moved.status).toBe('authenticated');
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toEqual({ score: 15, decision: 'allow', signals: [{ name: 'new_network', score: 15 }] });
  });

  it('requires MFA for a new device on a new network', async () => {
    const env = createAuthEnv();
    const created = await createUser(env);
    await loginWithPassword(env, await createDevice(env.clock, { ip: '203.0.113.10' }));
    await enrollTotp(env, created.id);

    const result = await attempt(env, await createDevice(env.clock, { ip: '198.51.100.5' }));
    expect(result).toMatchObject({ status: 'mfa_required', reason: 'risk' });
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toMatchObject({ score: 45, decision: 'step_up' });
  });

  // The next three tests cover the interaction between throttling and risk scoring. Four failed
  // attempts score 40, which is the step-up threshold.

  it('with the defaults, a user without a second factor still gets in after several wrong passwords', async () => {
    const env = createAuthEnv();
    await createUser(env);
    const laptop = await createDevice(env.clock);
    await loginWithPassword(env, laptop);

    for (let index = 0; index < 4; index++) {
      await expectAuthError(attempt(env, laptop, 'a wrong password'), 'INVALID_CREDENTIALS');
    }
    // There is no factor to step up to, so the login goes through, and the assessment is on record.
    expect((await attempt(env, laptop)).status).toBe('authenticated');
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toMatchObject({
      score: 40,
      decision: 'step_up',
      signals: [{ name: 'failed_attempts', score: 40 }],
    });
  });

  it('with the defaults, a user who has a second factor is asked for it after several wrong passwords', async () => {
    const env = createAuthEnv();
    const created = await createUser(env);
    const laptop = await createDevice(env.clock);
    await loginWithPassword(env, laptop);
    await enrollTotp(env, created.id);

    for (let index = 0; index < 4; index++) {
      await expectAuthError(attempt(env, laptop, 'a wrong password'), 'INVALID_CREDENTIALS');
    }
    expect(await attempt(env, laptop)).toMatchObject({ status: 'mfa_required', reason: 'risk' });
  });

  it('with deny configured, a user without a second factor is refused until the failures age out', async () => {
    const env = createAuthEnv({ risk: { whenStepUpUnavailable: 'deny' } });
    await createUser(env);
    const laptop = await createDevice(env.clock);
    await loginWithPassword(env, laptop);

    for (let index = 0; index < 4; index++) {
      await expectAuthError(attempt(env, laptop, 'a wrong password'), 'INVALID_CREDENTIALS');
    }
    await expectAuthError(attempt(env, laptop), 'RISK_DENIED');

    // The failures are forgotten after the throttle window, and the user can sign in again.
    env.clock.advanceSec(901);
    await loginWithPassword(env, laptop);
  });

  it('with the defaults, one wrong password on a new device does not lock out a user without a second factor', async () => {
    const env = createAuthEnv();
    await createUser(env);
    await loginWithPassword(env, await createDevice(env.clock));

    const newLaptop = await createDevice(env.clock);
    await expectAuthError(attempt(env, newLaptop, 'a typo in the password'), 'INVALID_CREDENTIALS');
    expect((await attempt(env, newLaptop)).status).toBe('authenticated');
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toMatchObject({ score: 40, decision: 'step_up' });
  });

  it('denies a new device in a new country after repeated failures', async () => {
    const locations: Record<string, GeoLocation> = {
      '203.0.113.10': { country: 'DE', latitude: 52.52, longitude: 13.4 },
      '198.51.100.5': { country: 'BR', latitude: -23.55, longitude: -46.63 },
    };
    const env = createAuthEnv({
      risk: { signals: [newDevice(), newNetwork(), newLocation({ locate: (ip) => locations[ip] ?? null }), failedAttempts()] },
    });
    const created = await createUser(env);

    // The user's own laptop, signing in from Germany. The device and its location are remembered.
    await loginWithPassword(env, await createDevice(env.clock, { ip: '203.0.113.10' }));
    expect(await env.adapter.devices.listByUser(created.id)).toMatchObject([{ lastCountry: 'DE', lastLatitude: 52.52 }]);
    env.clock.advanceSec(3600);

    // Someone in Brazil, on a device never seen before, gets the password right on the third try.
    const stranger = await createDevice(env.clock, { ip: '198.51.100.5' });
    for (let index = 0; index < 2; index++) {
      await expectAuthError(attempt(env, stranger, 'guessing the password'), 'INVALID_CREDENTIALS');
    }
    await expectAuthError(attempt(env, stranger), 'RISK_DENIED');
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data).toEqual({
      score: 90,
      decision: 'deny',
      signals: [
        { name: 'new_device', score: 30 },
        { name: 'new_network', score: 15 },
        { name: 'new_location', score: 25 },
        { name: 'failed_attempts', score: 20 },
      ],
    });
  });

  it('does not ask a passkey with user verification for more', async () => {
    const env = createAuthEnv({ risk: { signals: [fixed('a', 50)] } });
    const created = await createUser(env);
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const registration = await env.auth.passkeys.registrationOptions(created.id);
    await env.auth.passkeys.register(created.id, { challengeId: registration.challengeId, response: authenticator.create(registration.options) });

    const from = await createDevice(env.clock);
    const { challengeId, options } = await env.auth.login.passkeyOptions();
    const result = await env.auth.login.withPasskey(
      { challengeId, response: authenticator.get(options) },
      await from.ctx('POST', '/auth/login/passkey'),
    );
    expect(result.status === 'authenticated' && result.session.assurance).toBe('aal2');
    expect(env.sink.ofType('risk.evaluated')[0]!.data.decision).toBe('step_up');
  });

  it('keeps network history when sessions are not device bound', async () => {
    const env = createAuthEnv({ dpop: { mode: 'off' } });
    const created = await createUser(env);
    await env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, { ip: '203.0.113.10' });
    expect(await env.adapter.devices.listByUser(created.id)).toMatchObject([{ deviceKey: 'unbound', lastIp: '203.0.113.10' }]);

    await env.auth.login.withPassword({ identifier: 'ada@example.com', password: PASSWORD }, { ip: '198.51.100.5' });
    expect(env.sink.ofType('risk.evaluated').at(-1)!.data.signals).toEqual([{ name: 'new_network', score: 15 }]);
  });
});
