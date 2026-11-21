import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { SoftwareAuthenticator } from './authenticator.js';
import {
  APP_ORIGIN,
  PASSWORD,
  createAuthEnv,
  createDevice,
  createUser,
  enrollTotp,
  loginWithPassword,
  type AuthEnv,
  type Device,
} from './env.js';
import { expectAuthError } from './helpers.js';

const PASSKEY_LOGIN = '/auth/login/passkey';

async function setup(overrides = {}) {
  const env = createAuthEnv(overrides);
  const user = await createUser(env);
  const device = await createDevice(env.clock);
  const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
  return { env, user, device, authenticator };
}

async function registerPasskey(env: AuthEnv, userId: string, authenticator: SoftwareAuthenticator, name?: string) {
  const { challengeId, options } = await env.auth.passkeys.registrationOptions(userId);
  return env.auth.passkeys.register(userId, {
    challengeId,
    response: authenticator.create(options),
    ...(name !== undefined ? { name } : {}),
  });
}

async function passkeyLogin(env: AuthEnv, device: Device, authenticator: SoftwareAuthenticator, identifier?: string) {
  const { challengeId, options } = await env.auth.login.passkeyOptions(identifier === undefined ? {} : { identifier });
  return env.auth.login.withPasskey({ challengeId, response: authenticator.get(options) }, await device.ctx('POST', PASSKEY_LOGIN));
}

describe('passkey registration', () => {
  it('issues options for the configured relying party', async () => {
    const { env, user } = await setup();
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    expect(challengeId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(options.rp).toEqual({ id: 'example.com', name: 'Example' });
    expect(options.user.name).toBe('ada@example.com');
    expect(options.attestation).toBe('none');
    expect(options.authenticatorSelection).toMatchObject({ residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
    expect(options.pubKeyCredParams.map((param) => param.alg)).toContain(-7);
    expect(options.challenge.length).toBeGreaterThan(20);
  });

  it('registers a passkey and lists it', async () => {
    const { env, user, authenticator } = await setup();
    const passkey = await registerPasskey(env, user.id, authenticator, 'Work laptop');
    expect(passkey).toMatchObject({ name: 'Work laptop', deviceType: 'multiDevice', backedUp: true, transports: ['internal'], lastUsedAt: null });
    expect(await env.auth.passkeys.list(user.id)).toEqual([passkey]);
    expect(await env.auth.mfa.status(user.id)).toMatchObject({ passkeys: 1 });
    expect(env.sink.ofType('passkey.registered')[0]).toMatchObject({
      userId: user.id,
      data: { passkeyId: passkey.id, deviceType: 'multiDevice', backedUp: true },
    });
    // The public listing does not expose the credential id or key.
    expect(passkey).not.toHaveProperty('credentialId');
    expect(passkey).not.toHaveProperty('publicKey');
  });

  it('excludes credentials the user already has, so one authenticator is not registered twice', async () => {
    const { env, user, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const { options } = await env.auth.passkeys.registrationOptions(user.id);
    expect(options.excludeCredentials?.map((credential) => credential.id)).toEqual([...authenticator.credentials.keys()]);
  });

  it('uses a challenge only once', async () => {
    const { env, user, authenticator } = await setup();
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    const response = authenticator.create(options);
    await env.auth.passkeys.register(user.id, { challengeId, response });
    await expectAuthError(env.auth.passkeys.register(user.id, { challengeId, response }), 'PASSKEY_CHALLENGE_INVALID');
  });

  it('consumes the challenge even when verification fails', async () => {
    const { env, user, authenticator } = await setup();
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId, response: authenticator.create(options, { origin: 'https://evil.example' }) }),
      'PASSKEY_VERIFICATION_FAILED',
    );
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId, response: authenticator.create(options) }),
      'PASSKEY_CHALLENGE_INVALID',
    );
  });

  it('rejects an expired or unknown challenge, and a challenge issued to another user', async () => {
    const { env, user, authenticator } = await setup();
    const bob = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });

    const stale = await env.auth.passkeys.registrationOptions(user.id);
    env.clock.advanceSec(301);
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId: stale.challengeId, response: authenticator.create(stale.options) }),
      'PASSKEY_CHALLENGE_INVALID',
    );

    const fresh = await env.auth.passkeys.registrationOptions(user.id);
    await expectAuthError(
      env.auth.passkeys.register(bob.id, { challengeId: fresh.challengeId, response: authenticator.create(fresh.options) }),
      'PASSKEY_CHALLENGE_INVALID',
    );
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId: 'unknown', response: authenticator.create(fresh.options) }),
      'PASSKEY_CHALLENGE_INVALID',
    );
  });

  it('rejects a response signed over a different challenge', async () => {
    const { env, user, authenticator } = await setup();
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId, response: authenticator.create(options, { challenge: 'YXR0YWNrZXItY2hhbGxlbmdl' }) }),
      'PASSKEY_VERIFICATION_FAILED',
    );
  });

  it('rejects a response from another origin or for another relying party', async () => {
    const { env, user, authenticator } = await setup();
    for (const overrides of [{ origin: 'https://app.example.com.evil.example' }, { origin: 'http://app.example.com' }, { rpId: 'evil.example' }]) {
      const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
      await expectAuthError(
        env.auth.passkeys.register(user.id, { challengeId, response: authenticator.create(options, overrides) }),
        'PASSKEY_VERIFICATION_FAILED',
      );
    }
    expect(await env.auth.passkeys.list(user.id)).toEqual([]);
  });

  it('requires user verification by default', async () => {
    const { env, user } = await setup();
    const noPin = new SoftwareAuthenticator({ origin: APP_ORIGIN, userVerification: false });
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId, response: noPin.create(options) }),
      'PASSKEY_VERIFICATION_FAILED',
    );
  });

  it('refuses a credential id that is already registered to someone', async () => {
    const { env, user, authenticator } = await setup();
    const bob = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    const first = await env.auth.passkeys.registrationOptions(user.id);
    const response = authenticator.create(first.options);
    await env.auth.passkeys.register(user.id, { challengeId: first.challengeId, response });

    // Bob replays Ada's attestation against his own challenge: the challenge check stops it.
    const second = await env.auth.passkeys.registrationOptions(bob.id);
    await expectAuthError(
      env.auth.passkeys.register(bob.id, { challengeId: second.challengeId, response }),
      'PASSKEY_VERIFICATION_FAILED',
    );
    expect(await env.auth.passkeys.list(bob.id)).toEqual([]);
  });

  it('validates the name', async () => {
    const { env, user, authenticator } = await setup();
    const { challengeId, options } = await env.auth.passkeys.registrationOptions(user.id);
    await expectAuthError(
      env.auth.passkeys.register(user.id, { challengeId, response: authenticator.create(options), name: 'x'.repeat(101) }),
      'REQUEST_INVALID',
    );
  });

  it('is refused when passkeys are not configured', async () => {
    const env = createAuthEnv({ passkeys: undefined });
    const user = await createUser(env);
    const error = await expectAuthError(env.auth.passkeys.registrationOptions(user.id), 'REQUEST_INVALID');
    expect(error.details).toEqual({ reason: 'passkeys_disabled' });
    expect(await env.auth.passkeys.list(user.id)).toEqual([]);
    await expectAuthError(env.auth.login.passkeyOptions(), 'REQUEST_INVALID');
  });
});

describe('passkey sign-in', () => {
  it('signs in without an identifier and counts as two factors', async () => {
    const { env, user, device, authenticator } = await setup();
    const passkey = await registerPasskey(env, user.id, authenticator);
    env.clock.advanceSec(60);

    const result = await passkeyLogin(env, device, authenticator);
    if (result.status !== 'authenticated') throw new Error('expected a completed login');
    expect(result.user.id).toBe(user.id);
    expect(result.session).toMatchObject({ methods: ['passkey'], assurance: 'aal2', deviceBound: true });
    expect(decodeJwt(result.accessToken)).toMatchObject({ amr: ['passkey'], acr: 'aal2', cnf: { jkt: device.key.jkt } });
    expect(env.sink.ofType('login.succeeded').at(-1)!.data).toMatchObject({ method: 'passkey', mfa: false });

    const [listed] = await env.auth.passkeys.list(user.id);
    expect(listed!.id).toBe(passkey.id);
    expect(listed!.lastUsedAt).toBe(Math.floor(env.clock() / 1000));
  });

  it('does not ask for TOTP after a passkey with user verification', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    await enrollTotp(env, user.id);
    const result = await passkeyLogin(env, device, authenticator);
    expect(result.status).toBe('authenticated');
  });

  it('asks for TOTP when the passkey did not verify the user', async () => {
    const { env, user, device } = await setup({
      passkeys: { rpId: 'example.com', rpName: 'Example', origins: [APP_ORIGIN], userVerification: 'preferred' },
    });
    const noPin = new SoftwareAuthenticator({ origin: APP_ORIGIN, userVerification: false });
    await registerPasskey(env, user.id, noPin);

    const withoutMfa = await passkeyLogin(env, device, noPin);
    expect(withoutMfa.status === 'authenticated' && withoutMfa.session.assurance).toBe('aal1');

    await enrollTotp(env, user.id);
    const withMfa = await passkeyLogin(env, device, noPin);
    expect(withMfa.status).toBe('mfa_required');
  });

  it('ignores the identifier by default, so the options say nothing about any account', async () => {
    const { env, user, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const anonymous = (await env.auth.login.passkeyOptions()).options;
    const known = (await env.auth.login.passkeyOptions({ identifier: 'ada@example.com' })).options;
    const unknown = (await env.auth.login.passkeyOptions({ identifier: 'nobody@example.com' })).options;
    for (const options of [anonymous, known, unknown]) {
      expect(options.allowCredentials).toBeUndefined();
      expect(Object.keys(options).sort()).toEqual(Object.keys(anonymous).sort());
      expect(options.rpId).toBe('example.com');
      expect(options.userVerification).toBe('required');
    }
  });

  it('still signs the user in when an identifier is sent, through the discoverable credential', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const result = await passkeyLogin(env, device, authenticator, 'ada@example.com');
    expect(result.status === 'authenticated' && result.user.id).toBe(user.id);
  });

  it('lists the credentials of an account only when identifier hints are switched on', async () => {
    const hinted = { rpId: 'example.com', rpName: 'Example', origins: [APP_ORIGIN], identifierHints: true, residentKey: 'preferred' as const };
    const { env, user, authenticator } = await setup({ passkeys: hinted });
    await registerPasskey(env, user.id, authenticator);

    const known = (await env.auth.login.passkeyOptions({ identifier: 'ADA@example.com' })).options;
    expect(known.allowCredentials?.map((credential) => credential.id)).toEqual([...authenticator.credentials.keys()]);
    // This is the trade-off the option documents: a known account with passkeys is distinguishable.
    expect((await env.auth.login.passkeyOptions({ identifier: 'nobody@example.com' })).options.allowCredentials).toBeUndefined();
    expect((await env.auth.login.passkeyOptions()).options.allowCredentials).toBeUndefined();

    const registration = await env.auth.passkeys.registrationOptions(user.id);
    expect(registration.options.authenticatorSelection).toMatchObject({ residentKey: 'preferred' });
  });

  it('uses a challenge only once, so a captured response cannot be replayed', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const { challengeId, options } = await env.auth.login.passkeyOptions();
    const response = authenticator.get(options);
    await env.auth.login.withPasskey({ challengeId, response }, await device.ctx('POST', PASSKEY_LOGIN));
    await expectAuthError(
      env.auth.login.withPasskey({ challengeId, response }, await device.ctx('POST', PASSKEY_LOGIN)),
      'PASSKEY_CHALLENGE_INVALID',
    );
  });

  it('rejects a response to an older challenge presented with a newer challenge id', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const first = await env.auth.login.passkeyOptions();
    const captured = authenticator.get(first.options);
    const second = await env.auth.login.passkeyOptions();
    await expectAuthError(
      env.auth.login.withPasskey({ challengeId: second.challengeId, response: captured }, await device.ctx('POST', PASSKEY_LOGIN)),
      'PASSKEY_VERIFICATION_FAILED',
    );
  });

  it('rejects an expired challenge', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const { challengeId, options } = await env.auth.login.passkeyOptions();
    env.clock.advanceSec(301);
    await expectAuthError(
      env.auth.login.withPasskey({ challengeId, response: authenticator.get(options) }, await device.ctx('POST', PASSKEY_LOGIN)),
      'PASSKEY_CHALLENGE_INVALID',
    );
  });

  it('rejects a bad signature, a wrong origin and a wrong relying party', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    for (const overrides of [{ tamperSignature: true }, { origin: 'https://evil.example' }, { rpId: 'evil.example' }, { userVerified: false }]) {
      const { challengeId, options } = await env.auth.login.passkeyOptions();
      await expectAuthError(
        env.auth.login.withPasskey({ challengeId, response: authenticator.get(options, overrides) }, await device.ctx('POST', PASSKEY_LOGIN)),
        'PASSKEY_VERIFICATION_FAILED',
      );
    }
    expect(env.sink.ofType('login.failed').every((event) => event.data.method === 'passkey')).toBe(true);
    expect(await env.auth.sessions.list(user.id)).toEqual([]);
  });

  it('rejects a credential the server does not know', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const stranger = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const other = createAuthEnv();
    const otherUser = await createUser(other);
    await registerPasskey(other, otherUser.id, stranger);

    const { challengeId, options } = await env.auth.login.passkeyOptions();
    await expectAuthError(
      env.auth.login.withPasskey({ challengeId, response: stranger.get(options) }, await device.ctx('POST', PASSKEY_LOGIN)),
      'PASSKEY_VERIFICATION_FAILED',
    );
    for (const response of [{}, { id: '' }, { id: 'x'.repeat(2000) }, null]) {
      const next = await env.auth.login.passkeyOptions();
      await expectAuthError(
        env.auth.login.withPasskey({ challengeId: next.challengeId, response: response as never }, await device.ctx('POST', PASSKEY_LOGIN)),
        'PASSKEY_VERIFICATION_FAILED',
      );
    }
  });

  it('rejects a signature counter that goes backwards, which indicates a cloned authenticator', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);

    const first = await env.auth.login.passkeyOptions();
    await env.auth.login.withPasskey(
      { challengeId: first.challengeId, response: authenticator.get(first.options, { counter: 10 }) },
      await device.ctx('POST', PASSKEY_LOGIN),
    );

    const second = await env.auth.login.passkeyOptions();
    await expectAuthError(
      env.auth.login.withPasskey(
        { challengeId: second.challengeId, response: authenticator.get(second.options, { counter: 4 }) },
        await device.ctx('POST', PASSKEY_LOGIN),
      ),
      'PASSKEY_VERIFICATION_FAILED',
    );
    expect(env.sink.ofType('login.failed').at(-1)).toMatchObject({ reason: 'counter_regression', data: { method: 'passkey' } });

    const third = await env.auth.login.passkeyOptions();
    const ok = await env.auth.login.withPasskey(
      { challengeId: third.challengeId, response: authenticator.get(third.options, { counter: 11 }) },
      await device.ctx('POST', PASSKEY_LOGIN),
    );
    expect(ok.status).toBe('authenticated');
  });

  it('refuses a disabled user', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    await env.auth.users.disable(user.id);
    await expectAuthError(passkeyLogin(env, device, authenticator), 'ACCOUNT_DISABLED');
  });

  it('requires a DPoP proof like any other login', async () => {
    const { env, user, device, authenticator } = await setup();
    await registerPasskey(env, user.id, authenticator);
    const { challengeId, options } = await env.auth.login.passkeyOptions();
    await expectAuthError(env.auth.login.withPasskey({ challengeId, response: authenticator.get(options) }, device.bare()), 'DPOP_PROOF_REQUIRED');
  });

  it('works for an account that has no password', async () => {
    const env = createAuthEnv({ password: undefined });
    const user = await env.auth.users.create({ identifier: 'keys@example.com' });
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    await registerPasskey(env, user.id, authenticator);
    const result = await passkeyLogin(env, await createDevice(env.clock), authenticator, 'keys@example.com');
    expect(result.status === 'authenticated' && result.user.identifier).toBe('keys@example.com');
  });
});

describe('passkey removal', () => {
  it('removes a passkey, after which it no longer signs in', async () => {
    const { env, user, device, authenticator } = await setup();
    const passkey = await registerPasskey(env, user.id, authenticator);
    await env.auth.passkeys.remove(user.id, passkey.id);
    expect(await env.auth.passkeys.list(user.id)).toEqual([]);
    expect(env.sink.ofType('passkey.removed')[0]!.data).toEqual({ passkeyId: passkey.id });
    await expectAuthError(passkeyLogin(env, device, authenticator), 'PASSKEY_VERIFICATION_FAILED');
  });

  it('cannot remove another user’s passkey', async () => {
    const { env, user, authenticator } = await setup();
    const bob = await env.auth.users.create({ identifier: 'bob@example.com', password: PASSWORD });
    const passkey = await registerPasskey(env, user.id, authenticator);
    await expectAuthError(env.auth.passkeys.remove(bob.id, passkey.id), 'PASSKEY_NOT_FOUND');
    await expectAuthError(env.auth.passkeys.remove(user.id, 'missing'), 'PASSKEY_NOT_FOUND');
    expect(await env.auth.passkeys.list(user.id)).toHaveLength(1);
  });

  it('refuses to remove the last way to sign in', async () => {
    const env = createAuthEnv();
    const user = await env.auth.users.create({ identifier: 'keys@example.com' });
    const one = await registerPasskey(env, user.id, new SoftwareAuthenticator({ origin: APP_ORIGIN }));
    const two = await registerPasskey(env, user.id, new SoftwareAuthenticator({ origin: APP_ORIGIN }));

    await env.auth.passkeys.remove(user.id, one.id);
    const error = await expectAuthError(env.auth.passkeys.remove(user.id, two.id), 'REQUEST_INVALID');
    expect(error.details).toEqual({ reason: 'last_credential' });
    expect(await env.auth.passkeys.list(user.id)).toHaveLength(1);
  });
});

describe('step-up with a passkey', () => {
  it('raises a password session to aal2', async () => {
    const { env, user, device, authenticator } = await setup();
    const login = await loginWithPassword(env, device);
    await registerPasskey(env, user.id, authenticator);
    env.clock.advanceSec(120);

    const { challengeId, options } = await env.auth.login.passkeyOptions({ identifier: 'ada@example.com' });
    const grant = await env.auth.sessions.reauthenticate(login.session.id, {
      method: 'passkey',
      challengeId,
      response: authenticator.get(options),
    });
    expect(grant.session).toMatchObject({ assurance: 'aal2', methods: ['pwd', 'passkey'] });
    expect(grant.session.authenticatedAt).toBe(login.session.authenticatedAt + 120);
  });

  it('rejects a passkey that belongs to a different user', async () => {
    const { env, user, device, authenticator } = await setup();
    const login = await loginWithPassword(env, device);
    void user;
    const mallory = await env.auth.users.create({ identifier: 'mallory@example.com', password: PASSWORD });
    await registerPasskey(env, mallory.id, authenticator);

    const { challengeId, options } = await env.auth.login.passkeyOptions();
    await expectAuthError(
      env.auth.sessions.reauthenticate(login.session.id, { method: 'passkey', challengeId, response: authenticator.get(options) }),
      'PASSKEY_VERIFICATION_FAILED',
    );
    expect((await env.auth.sessions.get(login.session.id))!.assurance).toBe('aal1');
  });
});
