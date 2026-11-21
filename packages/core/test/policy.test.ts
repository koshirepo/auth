import { describe, expect, it } from 'vitest';
import {
  AuthorizationError,
  allow,
  createAuthorizer,
  defineRbac,
  definePolicy,
  deny,
  isAuthError,
  type AuthContext,
  type Subject,
} from '../src/index.js';

interface Invoice {
  id: string;
  ownerId: string;
}

const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete', 'user:manage'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
    support: { grants: [] },
    admin: { grants: ['invoice:*', 'user:manage'] },
  },
});

const changeOwnInvoiceOnly = definePolicy('change-own-invoice-only', (subject, action, resource: Invoice) => {
  if (action !== 'invoice:write' && action !== 'invoice:delete') return;
  if (resource.ownerId !== subject.id && !subject.roles.includes('admin')) {
    return deny('invoice belongs to another user');
  }
});

const supportReadsDuringIncident = definePolicy('support-incident-read', (subject, action, _resource, ctx) => {
  if (action === 'invoice:read' && subject.roles.includes('support') && ctx.incidentOpen === true) {
    return allow('support may read invoices during an open incident');
  }
});

const recentMfaForDelete = definePolicy('recent-mfa-for-delete', (_subject, action, _resource, ctx) => {
  if (action !== 'invoice:delete') return;
  const auth = ctx.auth;
  if (!auth || auth.assurance !== 'aal2' || (ctx.now ?? 0) - auth.authenticatedAt > 300) {
    return deny('requires MFA within the last 5 minutes');
  }
});

const authorizer = createAuthorizer({
  rbac,
  policies: [changeOwnInvoiceOnly, supportReadsDuringIncident, recentMfaForDelete],
});

const alice: Subject = { id: 'alice', roles: ['editor'] };
const sam: Subject = { id: 'sam', roles: ['support'] };
const root: Subject = { id: 'root', roles: ['admin'] };
const own: Invoice = { id: 'i1', ownerId: 'alice' };
const other: Invoice = { id: 'i2', ownerId: 'bob' };

const auth = (overrides: Partial<AuthContext> = {}): AuthContext => ({
  sessionId: 's1',
  methods: ['pwd', 'otp'],
  assurance: 'aal2',
  authenticatedAt: 1000,
  deviceBound: true,
  ...overrides,
});

describe('createAuthorizer', () => {
  it('allows what a role grants and names the source as rbac', () => {
    expect(authorizer.evaluate(alice, 'invoice:read', own)).toEqual({
      effect: 'allow',
      reason: 'a role grants "invoice:read"',
      policy: 'rbac',
    });
  });

  it('denies by default when no role or policy allows, with a reason', () => {
    expect(authorizer.evaluate(alice, 'user:manage')).toEqual({
      effect: 'deny',
      reason: 'no role or policy allows "user:manage"',
      policy: 'default',
    });
    expect(authorizer.evaluate(sam, 'invoice:read', other, { incidentOpen: false }).effect).toBe('deny');
  });

  it('lets a policy deny what a role grants', () => {
    expect(authorizer.evaluate(alice, 'invoice:write', own).effect).toBe('allow');
    expect(authorizer.evaluate(alice, 'invoice:write', other)).toEqual({
      effect: 'deny',
      reason: 'invoice belongs to another user',
      policy: 'change-own-invoice-only',
    });
  });

  it('lets a policy allow what no role grants', () => {
    expect(authorizer.evaluate(sam, 'invoice:read', other, { incidentOpen: true })).toEqual({
      effect: 'allow',
      reason: 'support may read invoices during an open incident',
      policy: 'support-incident-read',
    });
  });

  it('makes deny win over allow regardless of policy order', () => {
    const allowAll = definePolicy('allow-all', () => allow('everything goes'));
    const denyAll = definePolicy('deny-all', () => deny('nothing goes'));
    for (const policies of [
      [allowAll, denyAll],
      [denyAll, allowAll],
    ]) {
      const decision = createAuthorizer({ rbac, policies }).evaluate(root, 'invoice:read');
      expect(decision).toEqual({ effect: 'deny', reason: 'nothing goes', policy: 'deny-all' });
    }
  });

  it('reports the first denying policy in list order', () => {
    const first = definePolicy('first', () => deny('first says no'));
    const second = definePolicy('second', () => deny('second says no'));
    expect(createAuthorizer({ policies: [first, second] }).evaluate(root, 'x:y').policy).toBe('first');
    expect(createAuthorizer({ policies: [second, first] }).evaluate(root, 'x:y').policy).toBe('second');
  });

  it('passes the authentication context so policies can demand recent MFA', () => {
    const fresh = { auth: auth({ authenticatedAt: 1000 }), now: 1200 };
    const stale = { auth: auth({ authenticatedAt: 1000 }), now: 2000 };
    const weak = { auth: auth({ assurance: 'aal1', methods: ['pwd'] }), now: 1200 };

    expect(authorizer.evaluate(root, 'invoice:delete', own, fresh).effect).toBe('allow');
    expect(authorizer.evaluate(root, 'invoice:delete', own, stale)).toEqual({
      effect: 'deny',
      reason: 'requires MFA within the last 5 minutes',
      policy: 'recent-mfa-for-delete',
    });
    expect(authorizer.evaluate(root, 'invoice:delete', own, weak).effect).toBe('deny');
    expect(authorizer.evaluate(root, 'invoice:delete', own).effect).toBe('deny');
  });

  it('treats a policy that throws as a deny', () => {
    const broken = definePolicy('broken', (_subject, _action, resource: Invoice) => {
      if (resource.ownerId.length > 0) return allow('fine');
    });
    const decision = createAuthorizer({ rbac, policies: [broken] }).evaluate(root, 'invoice:read', undefined);
    expect(decision).toEqual({ effect: 'deny', reason: 'policy "broken" failed', policy: 'broken' });
  });

  it('treats an asynchronous policy as a deny instead of ignoring it', () => {
    const lazy = definePolicy('lazy', (async () => allow('eventually')) as never);
    const decision = createAuthorizer({ rbac, policies: [lazy] }).evaluate(root, 'invoice:read');
    expect(decision).toEqual({ effect: 'deny', reason: 'policy "lazy" is asynchronous', policy: 'lazy' });
  });

  it('treats an unknown effect as a deny', () => {
    const odd = definePolicy('odd', (() => ({ effect: 'maybe', reason: 'hmm' })) as never);
    expect(createAuthorizer({ rbac, policies: [odd] }).evaluate(root, 'invoice:read').effect).toBe('deny');
  });

  it('works with policies alone and with nothing at all', () => {
    const onlyPolicies = createAuthorizer({ policies: [definePolicy('yes', () => allow('ok'))] });
    expect(onlyPolicies.can({ id: 'u', roles: [] }, 'anything:goes')).toBe(true);
    expect(createAuthorizer().evaluate({ id: 'u', roles: ['admin'] }, 'anything:goes')).toEqual({
      effect: 'deny',
      reason: 'no role or policy allows "anything:goes"',
      policy: 'default',
    });
  });

  it('can() returns the effect as a boolean', () => {
    expect(authorizer.can(alice, 'invoice:write', own)).toBe(true);
    expect(authorizer.can(alice, 'invoice:write', other)).toBe(false);
  });

  it('assert() throws FORBIDDEN carrying the reason, policy and action', () => {
    expect(() => authorizer.assert(alice, 'invoice:write', own)).not.toThrow();
    try {
      authorizer.assert(alice, 'invoice:write', other);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(AuthorizationError);
      expect(isAuthError(error) && error.code).toBe('FORBIDDEN');
      expect((error as AuthorizationError).details).toEqual({
        reason: 'invoice belongs to another user',
        policy: 'change-own-invoice-only',
        action: 'invoice:write',
      });
    }
  });

  it('checks actions against the declared permissions at compile time', () => {
    // @ts-expect-error 'invoice:fly' is not a declared permission
    expect(authorizer.can(root, 'invoice:fly')).toBe(false);
  });

  it('does not evaluate later policies after a deny', () => {
    let called = false;
    const stop = definePolicy('stop', () => deny('stop'));
    const spy = definePolicy('spy', () => {
      called = true;
    });
    createAuthorizer({ policies: [stop, spy] }).evaluate(root, 'a:b');
    expect(called).toBe(false);
  });
});

describe('definePolicy', () => {
  it('rejects empty and reserved names', () => {
    expect(() => definePolicy('', () => undefined)).toThrow(/needs a name/);
    expect(() => definePolicy('rbac', () => undefined)).toThrow(/reserved/);
    expect(() => definePolicy('default', () => undefined)).toThrow(/reserved/);
  });

  it('rejects two policies with the same name in one authorizer', () => {
    const one = definePolicy('same', () => undefined);
    const two = definePolicy('same', () => undefined);
    expect(() => createAuthorizer({ policies: [one, two] })).toThrow(/Two policies are named "same"/);
  });
});
