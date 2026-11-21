import type { PublicUser, SessionInfo } from '@koshi-repo/auth-core';
import { afterEach, describe, expect, it } from 'vitest';
import { evaluateGuard, type AuthClient, type AuthState } from '../src/index.js';
import { PASSWORD, createUser, rbac, setup, signedInTab } from './harness.js';

const NOW = 10_000;

const user = (roles: string[]): PublicUser => ({ id: 'u1', identifier: 'ada@example.com', roles });
const session = (overrides: Partial<SessionInfo> = {}): SessionInfo => ({
  id: 's1',
  createdAt: NOW - 100,
  lastUsedAt: NOW - 100,
  expiresAt: NOW + 10_000,
  authenticatedAt: NOW - 100,
  methods: ['pwd'],
  assurance: 'aal1',
  deviceBound: true,
  ...overrides,
});
const signedIn = (roles: string[], overrides: Partial<SessionInfo> = {}): AuthState => ({
  status: 'authenticated',
  user: user(roles),
  session: session(overrides),
});
const options = { rbac, nowSec: NOW };

describe('evaluateGuard', () => {
  it('is pending while the session is being restored', () => {
    expect(evaluateGuard({ status: 'loading' }, {}, options)).toEqual({ status: 'pending' });
    expect(evaluateGuard({ status: 'loading' }, { roles: ['admin'] }, options)).toEqual({ status: 'pending' });
  });

  it('sends a signed-out visitor to login and a half-signed-in one to the second factor', () => {
    expect(evaluateGuard({ status: 'unauthenticated' }, {}, options)).toEqual({ status: 'deny', action: 'login', reason: 'not signed in' });
    expect(
      evaluateGuard({ status: 'mfa_required', methods: ['totp'], reason: 'enrolled', expiresAt: NOW + 300 }, {}, options),
    ).toEqual({ status: 'deny', action: 'mfa', reason: 'a second factor is required' });
  });

  it('allows any signed-in user when nothing more is required', () => {
    expect(evaluateGuard(signedIn([]), {}, options)).toEqual({ status: 'allow' });
    expect(evaluateGuard(signedIn([]), undefined, options)).toEqual({ status: 'allow' });
  });

  it('requires one of the listed roles', () => {
    expect(evaluateGuard(signedIn(['editor']), { roles: ['admin', 'editor'] }, options)).toEqual({ status: 'allow' });
    expect(evaluateGuard(signedIn(['viewer']), { roles: ['admin', 'editor'] }, options)).toEqual({
      status: 'deny',
      action: 'forbidden',
      reason: 'requires one of the roles: admin, editor',
    });
    expect(evaluateGuard(signedIn(['viewer']), { roles: [] }, options)).toEqual({ status: 'allow' });
  });

  it('requires every listed permission, resolved through the role map', () => {
    expect(evaluateGuard(signedIn(['editor']), { permissions: ['invoice:read', 'invoice:write'] }, options)).toEqual({ status: 'allow' });
    expect(evaluateGuard(signedIn(['viewer']), { permissions: ['invoice:read', 'invoice:write'] }, options)).toEqual({
      status: 'deny',
      action: 'forbidden',
      reason: 'missing permission: invoice:write',
    });
    expect(evaluateGuard(signedIn(['editor']), { permissions: ['invoice:delete'] }, options).status).toBe('deny');
  });

  it('denies permission checks when no role map was given, instead of guessing', () => {
    expect(evaluateGuard(signedIn(['editor']), { permissions: ['invoice:read'] }, { nowSec: NOW })).toEqual({
      status: 'deny',
      action: 'forbidden',
      reason: 'no role map is configured to resolve permissions',
    });
  });

  it('asks for step-up when two factors are required', () => {
    expect(evaluateGuard(signedIn(['editor']), { assurance: 'aal2' }, options)).toEqual({
      status: 'deny',
      action: 'step_up',
      reason: 'requires a second factor',
    });
    expect(evaluateGuard(signedIn(['editor'], { assurance: 'aal2', methods: ['pwd', 'otp'] }), { assurance: 'aal2' }, options)).toEqual({
      status: 'allow',
    });
  });

  it('asks for step-up when the last sign-in is too old', () => {
    const old = signedIn(['editor'], { authenticatedAt: NOW - 301 });
    expect(evaluateGuard(old, { maxAuthAgeSec: 300 }, options)).toEqual({ status: 'deny', action: 'step_up', reason: 'requires a recent sign-in' });
    expect(evaluateGuard(signedIn(['editor'], { authenticatedAt: NOW - 300 }), { maxAuthAgeSec: 300 }, options)).toEqual({ status: 'allow' });
  });

  it('reports a missing permission before asking for step-up, which would not help', () => {
    expect(evaluateGuard(signedIn(['viewer']), { permissions: ['invoice:write'], assurance: 'aal2' }, options)).toMatchObject({
      status: 'deny',
      action: 'forbidden',
    });
  });
});

describe('guards and permission checks on a live client', () => {
  const tabs: AuthClient[] = [];
  afterEach(() => {
    for (const tab of tabs.splice(0)) tab.dispose();
  });

  it('follows the session through its states', async () => {
    const { profile } = await setup();
    const tab = profile.openTab();
    tabs.push(tab);
    expect(tab.check()).toEqual({ status: 'pending' });
    expect(tab.can('invoice:read')).toBe(false);

    await tab.ready();
    expect(tab.check({ permissions: ['invoice:read'] })).toMatchObject({ status: 'deny', action: 'login' });

    await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
    expect(tab.check({ permissions: ['invoice:write'] })).toEqual({ status: 'allow' });
    expect(tab.check({ permissions: ['invoice:delete'] })).toMatchObject({ status: 'deny', action: 'forbidden' });
    expect(tab.check({ assurance: 'aal2' })).toMatchObject({ status: 'deny', action: 'step_up' });

    await tab.logout();
    expect(tab.check()).toMatchObject({ status: 'deny', action: 'login' });
  });

  it('asks for step-up once the sign-in has aged', async () => {
    const { profile, server } = await setup();
    const tab = await signedInTab(profile);
    tabs.push(tab);
    expect(tab.check({ maxAuthAgeSec: 300 })).toEqual({ status: 'allow' });
    server.clock.advanceSec(301);
    expect(tab.check({ maxAuthAgeSec: 300 })).toMatchObject({ status: 'deny', action: 'step_up' });
  });

  it('evaluates roles and policies with the same rules as the server', async () => {
    const { profile, server, user: ada } = await setup();
    await createUser(server, 'vera@example.com', ['viewer']);
    const tab = await signedInTab(profile);
    tabs.push(tab);

    expect(tab.can('invoice:read')).toBe(true);
    expect(tab.can('invoice:write')).toBe(true);
    expect(tab.can('invoice:delete')).toBe(false);
    // The policy looks at the resource: an editor may change only their own invoices.
    expect(tab.can('invoice:write', { ownerId: ada.id })).toBe(true);
    expect(tab.can('invoice:write', { ownerId: 'someone-else' })).toBe(false);
  });

  it('answers no to everything without a role map', async () => {
    const { profile } = await setup();
    const tab = await signedInTab(profile, { access: {} });
    tabs.push(tab);
    expect(tab.can('invoice:read')).toBe(false);
    expect(tab.check({ permissions: ['invoice:read'] })).toMatchObject({ status: 'deny', action: 'forbidden' });
    expect(tab.check({ roles: ['editor'] })).toEqual({ status: 'allow' });
  });
});
