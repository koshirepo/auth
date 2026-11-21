import { isAuthError, type AuthError } from '@koshirepo/auth-core';
import { afterEach, describe, expect, it } from 'vitest';
import { SoftwareAuthenticator } from '../../server/test/authenticator.js';
import type { AuthClient, WebAuthnBrowser } from '../src/index.js';
import { APP_ORIGIN, BrowserProfile, PASSWORD, setup, signedInTab, totpCode } from './harness.js';

const tabs: AuthClient[] = [];

afterEach(() => {
  for (const tab of tabs.splice(0)) tab.dispose();
});

async function login(profile: BrowserProfile, options: Parameters<BrowserProfile['openTab']>[0] = {}) {
  const tab = await signedInTab(profile, options);
  tabs.push(tab);
  return tab;
}

async function rejection(promise: Promise<unknown>): Promise<AuthError> {
  try {
    await promise;
  } catch (error) {
    if (!isAuthError(error)) throw error;
    return error;
  }
  throw new Error('Expected the call to be rejected');
}

/** Connects the software authenticator the way `@simplewebauthn/browser` connects a real one. */
function webauthnFor(authenticator: SoftwareAuthenticator): WebAuthnBrowser {
  return {
    startRegistration: async ({ optionsJSON }) => authenticator.create(optionsJSON),
    startAuthentication: async ({ optionsJSON }) => authenticator.get(optionsJSON),
  };
}

describe('second factor management through the client', () => {
  it('enrols TOTP, reports the status and regenerates recovery codes', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    expect(await tab.mfa.status()).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });

    const enrollment = await tab.mfa.beginTotpEnrollment();
    expect(enrollment.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(enrollment.otpauthUri).toContain(`secret=${enrollment.secret}`);

    const wrong = await rejection(tab.mfa.confirmTotpEnrollment({ enrollmentId: enrollment.enrollmentId, code: '000000' }));
    expect(wrong.code).toBe('MFA_CODE_INVALID');

    const { recoveryCodes } = await tab.mfa.confirmTotpEnrollment({
      enrollmentId: enrollment.enrollmentId,
      code: await totpCode(server.clock, enrollment.secret),
    });
    expect(recoveryCodes).toHaveLength(10);
    expect(await tab.mfa.status()).toEqual({ totp: true, recoveryCodes: 10, passkeys: 0 });

    const fresh = await tab.mfa.regenerateRecoveryCodes();
    expect(fresh).toHaveLength(10);
    expect(fresh).not.toEqual(recoveryCodes);

    await tab.mfa.removeTotp();
    expect(await tab.mfa.status()).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });
  });

  it('raises the session to aal2 by re-authenticating with a code', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const enrollment = await tab.mfa.beginTotpEnrollment();
    await tab.mfa.confirmTotpEnrollment({ enrollmentId: enrollment.enrollmentId, code: await totpCode(server.clock, enrollment.secret) });
    server.clock.advanceSec(30);

    const state = await tab.reauthenticate({ method: 'totp', code: await totpCode(server.clock, enrollment.secret) });
    expect(state).toMatchObject({ status: 'authenticated', session: { assurance: 'aal2', methods: ['pwd', 'otp'] } });
    expect(tab.check({ assurance: 'aal2' })).toEqual({ status: 'allow' });
  });

  it('surfaces a step-up demand as a typed error, and re-authenticating satisfies it', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    server.clock.advanceSec(601);

    const error = await rejection(tab.mfa.beginTotpEnrollment());
    expect(error.code).toBe('STEP_UP_REQUIRED');
    expect(error.status).toBe(403);
    expect(error.details).toEqual({ required: 'recent_authentication', maxAuthAgeSec: 600 });
    // A step-up demand is not the end of the session.
    expect(tab.getState().status).toBe('authenticated');

    const before = tab.getState();
    const state = await tab.reauthenticate({ method: 'password', password: PASSWORD });
    if (state.status !== 'authenticated' || before.status !== 'authenticated') throw new Error('expected an authenticated state');
    expect(state.session.authenticatedAt).toBe(before.session.authenticatedAt + 601);
    expect((await tab.mfa.beginTotpEnrollment()).enrollmentId).toBeTruthy();
  });

  it('rejects a wrong password on re-authentication without ending the session', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    const error = await rejection(tab.reauthenticate({ method: 'password', password: 'not my password' }));
    expect(error.code).toBe('INVALID_CREDENTIALS');
    expect(tab.getState().status).toBe('authenticated');
  });
});

describe('sessions and password through the client', () => {
  it('lists sessions and marks the current one', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const other = await login(new BrowserProfile(server));
    const sessions = await tab.sessions.list();
    expect(sessions).toHaveLength(2);
    expect(sessions.filter((session) => session.current)).toHaveLength(1);

    const otherState = other.getState();
    if (otherState.status !== 'authenticated') throw new Error('expected an authenticated state');
    await tab.sessions.revoke(otherState.session.id);
    expect(await tab.sessions.list()).toHaveLength(1);
    expect(tab.getState().status).toBe('authenticated');
    expect(await other.getAccessToken({ forceRefresh: true })).toBeNull();
  });

  it('signs this tab out when it revokes its own session', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    const state = tab.getState();
    if (state.status !== 'authenticated') throw new Error('expected an authenticated state');
    await tab.sessions.revoke(state.session.id);
    expect(tab.getState()).toEqual({ status: 'unauthenticated' });
    expect(profile.broadcasts.at(-1)).toEqual({ type: 'signed-out' });
  });

  it('changes the password', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    expect((await rejection(tab.changePassword({ currentPassword: 'wrong wrong wrong', newPassword: 'a brand new password' }))).code).toBe(
      'INVALID_CREDENTIALS',
    );
    expect((await rejection(tab.changePassword({ currentPassword: PASSWORD, newPassword: 'short' }))).details).toEqual({ reason: 'too_short' });
    await tab.changePassword({ currentPassword: PASSWORD, newPassword: 'a brand new password' });
    expect(tab.getState().status).toBe('authenticated');

    expect((await rejection(tab.changePassword({} as never))).code).toBe('REQUEST_INVALID');

    // Signing in again from the same browser: the old password is gone and the new one works.
    await tab.logout();
    expect((await rejection(tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD }))).code).toBe('INVALID_CREDENTIALS');
    expect((await tab.loginWithPassword({ identifier: 'ada@example.com', password: 'a brand new password' })).status).toBe('authenticated');
  });

  it('refreshes and retries once when an account call meets an expired token', async () => {
    const { profile, server } = await setup();
    const tab = await login(profile);
    const refreshes = profile.requestsTo('/auth/refresh').length;
    server.failNext('/auth/session', 401);
    expect(await tab.mfa.status()).toEqual({ totp: false, recoveryCodes: 0, passkeys: 0 });
    expect(profile.requestsTo('/auth/session')).toHaveLength(2);
    expect(profile.requestsTo('/auth/refresh')).toHaveLength(refreshes + 1);
  });

  it('refuses account calls when signed out, without sending anything', async () => {
    const { profile } = await setup();
    const tab = profile.openTab();
    tabs.push(tab);
    await tab.ready();
    const before = profile.sent.length;
    expect((await rejection(tab.sessions.list())).code).toBe('TOKEN_MISSING');
    expect((await rejection(tab.mfa.status())).code).toBe('TOKEN_MISSING');
    expect(profile.sent.length).toBe(before);
  });

  it('sends account calls with the access token and without the refresh cookie', async () => {
    const { profile } = await setup();
    const tab = await login(profile);
    await tab.sessions.list();
    const [request] = profile.requestsTo('/auth/sessions');
    expect(request!.headers.get('authorization')).toMatch(/^DPoP /);
    expect(request!.credentials).toBe('omit');
  });
});

describe('passkeys through the client', () => {
  it('registers a passkey, signs in with it on another browser, and removes it', async () => {
    const { profile, server, user } = await setup();
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const webauthn = webauthnFor(authenticator);
    const tab = await login(profile, { webauthn });

    const passkey = await tab.passkeys.register({ name: 'Laptop' });
    expect(passkey).toMatchObject({ name: 'Laptop', deviceType: 'multiDevice', backedUp: true });
    expect((await tab.passkeys.list()).map((entry) => entry.id)).toEqual([passkey.id]);
    expect(await tab.mfa.status()).toMatchObject({ passkeys: 1 });

    // A different browser profile, signing in with nothing but the passkey.
    const fresh = new BrowserProfile(server).openTab({ webauthn });
    tabs.push(fresh);
    const state = await fresh.loginWithPasskey();
    expect(state).toMatchObject({ status: 'authenticated', user: { id: user.id }, session: { assurance: 'aal2', methods: ['passkey'] } });
    expect(typeof (await fresh.getAccessToken())).toBe('string');

    await tab.passkeys.remove(passkey.id);
    expect(await tab.passkeys.list()).toEqual([]);
    expect((await rejection(tab.passkeys.remove(passkey.id))).code).toBe('PASSKEY_NOT_FOUND');
  });

  it('passes an identifier along when one is given', async () => {
    const { profile, server } = await setup();
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const webauthn = webauthnFor(authenticator);
    const tab = await login(profile, { webauthn });
    await tab.passkeys.register();

    const fresh = new BrowserProfile(server);
    const freshTab = fresh.openTab({ webauthn });
    tabs.push(freshTab);
    const state = await freshTab.loginWithPasskey({ identifier: 'ada@example.com' });
    expect(state.status).toBe('authenticated');
    expect(JSON.parse(fresh.requestsTo('/auth/login/passkey/options')[0]!.body!)).toEqual({ identifier: 'ada@example.com' });
  });

  it('re-authenticates with a passkey to reach aal2', async () => {
    const { profile } = await setup();
    const authenticator = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const tab = await login(profile, { webauthn: webauthnFor(authenticator) });
    await tab.passkeys.register();
    const state = await tab.reauthenticate({ method: 'passkey' });
    expect(state).toMatchObject({ status: 'authenticated', session: { assurance: 'aal2', methods: ['pwd', 'passkey'] } });
  });

  it('reports a ceremony the user cancels', async () => {
    const { profile } = await setup();
    const cancelled: WebAuthnBrowser = {
      startRegistration: async () => {
        throw new Error('The operation either timed out or was not allowed.');
      },
      startAuthentication: async () => {
        throw new Error('The operation either timed out or was not allowed.');
      },
    };
    const tab = await login(profile, { webauthn: cancelled });
    await expect(tab.passkeys.register()).rejects.toThrow(/timed out or was not allowed/);
    await expect(tab.loginWithPasskey()).rejects.toThrow(/timed out or was not allowed/);
    expect(tab.getState().status).toBe('authenticated');
  });

  it('rejects a response produced on a look-alike site', async () => {
    const { profile, server } = await setup();
    const real = new SoftwareAuthenticator({ origin: APP_ORIGIN });
    const tab = await login(profile, { webauthn: webauthnFor(real) });
    await tab.passkeys.register();

    // The same credentials, but the ceremony ran on another origin, as it would on a phishing page.
    const phishing = new SoftwareAuthenticator({ origin: 'https://app.example.com.evil.example' });
    for (const [id, credential] of real.credentials) phishing.credentials.set(id, credential);
    const victim = new BrowserProfile(server).openTab({ webauthn: webauthnFor(phishing) });
    tabs.push(victim);
    expect((await rejection(victim.loginWithPasskey())).code).toBe('PASSKEY_VERIFICATION_FAILED');
    expect(victim.getState()).toEqual({ status: 'unauthenticated' });
  });
});
