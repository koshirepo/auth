import { describe, expect, it } from 'vitest';
import { ConfigurationError, defineRbac } from '../src/index.js';

const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete', 'user:manage', 'report:view'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
    manager: { inherits: ['editor'], grants: ['report:view'] },
    support: { grants: [] },
    billing: { grants: ['invoice:*'] },
    admin: { grants: ['*'] },
  },
});

describe('defineRbac', () => {
  it('lists the declared permissions and roles', () => {
    expect(rbac.permissions).toEqual(['invoice:read', 'invoice:write', 'invoice:delete', 'user:manage', 'report:view']);
    expect(rbac.roles).toEqual(['viewer', 'editor', 'manager', 'support', 'billing', 'admin']);
  });

  it('grants direct permissions', () => {
    expect([...rbac.permissionsFor(['viewer'])]).toEqual(['invoice:read']);
    expect(rbac.grants(['viewer'], 'invoice:read')).toBe(true);
    expect(rbac.grants(['viewer'], 'invoice:write')).toBe(false);
  });

  it('follows inheritance through several levels', () => {
    expect(new Set(rbac.permissionsFor(['manager']))).toEqual(new Set(['invoice:read', 'invoice:write', 'report:view']));
    expect(rbac.grants(['manager'], 'invoice:read')).toBe(true);
    expect(rbac.grants(['manager'], 'invoice:delete')).toBe(false);
  });

  it('expands resource wildcards against the declared list only', () => {
    expect(new Set(rbac.permissionsFor(['billing']))).toEqual(new Set(['invoice:read', 'invoice:write', 'invoice:delete']));
    expect(rbac.grants(['billing'], 'user:manage')).toBe(false);
  });

  it('expands the global wildcard to every declared permission', () => {
    expect(new Set(rbac.permissionsFor(['admin']))).toEqual(new Set(rbac.permissions));
  });

  it('unions the permissions of several roles', () => {
    expect(new Set(rbac.permissionsFor(['viewer', 'support', 'manager']))).toEqual(
      new Set(['invoice:read', 'invoice:write', 'report:view']),
    );
  });

  it('grants nothing to a role with no grants, to unknown roles, or to no roles', () => {
    expect(rbac.permissionsFor(['support']).size).toBe(0);
    expect(rbac.permissionsFor(['ghost']).size).toBe(0);
    expect(rbac.permissionsFor([]).size).toBe(0);
    expect(rbac.grants(['ghost', 'toString', '__proto__'], 'invoice:read')).toBe(false);
  });

  it('narrows strings to declared names', () => {
    expect(rbac.isPermission('invoice:read')).toBe(true);
    expect(rbac.isPermission('invoice:*')).toBe(false);
    expect(rbac.isPermission('invoice:fly')).toBe(false);
    expect(rbac.isRole('admin')).toBe(true);
    expect(rbac.isRole('root')).toBe(false);
  });

  it('rejects a misspelt permission at compile time and at run time', () => {
    expect(() =>
      defineRbac({
        permissions: ['invoice:read'],
        // @ts-expect-error 'invoice:raed' is not a declared permission
        roles: { viewer: { grants: ['invoice:raed'] } },
      }),
    ).toThrow(ConfigurationError);
  });

  it('rejects a wildcard for an undeclared resource at compile time and at run time', () => {
    expect(() =>
      defineRbac({
        permissions: ['invoice:read'],
        // @ts-expect-error there is no 'user' resource
        roles: { viewer: { grants: ['user:*'] } },
      }),
    ).toThrow(/matches no declared permission/);
  });

  it('rejects an unknown parent role at compile time and at run time', () => {
    expect(() =>
      defineRbac({
        permissions: ['invoice:read'],
        // @ts-expect-error 'viewr' is not a role
        roles: { editor: { inherits: ['viewr'], grants: [] } },
      }),
    ).toThrow(/unknown role "viewr"/);
  });

  it('rejects a misspelt permission in a check at compile time', () => {
    // @ts-expect-error 'invoice:fly' is not a declared permission
    expect(rbac.grants(['admin'], 'invoice:fly')).toBe(false);
  });

  it('rejects inheritance cycles', () => {
    expect(() =>
      defineRbac({
        permissions: ['a:read'],
        roles: {
          one: { inherits: ['two'], grants: [] },
          two: { inherits: ['three'], grants: [] },
          three: { inherits: ['one'], grants: ['a:read'] },
        },
      }),
    ).toThrow(/cycle: one -> two -> three -> one/);
  });

  it('rejects a role that inherits from itself', () => {
    expect(() =>
      defineRbac({ permissions: ['a:read'], roles: { loop: { inherits: ['loop'], grants: [] } } }),
    ).toThrow(/cycle/);
  });

  it('allows diamond inheritance, which is not a cycle', () => {
    const diamond = defineRbac({
      permissions: ['a:read', 'a:write'],
      roles: {
        base: { grants: ['a:read'] },
        left: { inherits: ['base'], grants: [] },
        right: { inherits: ['base'], grants: ['a:write'] },
        top: { inherits: ['left', 'right'], grants: [] },
      },
    });
    expect(new Set(diamond.permissionsFor(['top']))).toEqual(new Set(['a:read', 'a:write']));
  });

  it('rejects malformed, wildcard and duplicate permission declarations', () => {
    expect(() => defineRbac({ permissions: ['invoiceread'], roles: {} })).toThrow(/resource:action/);
    expect(() => defineRbac({ permissions: ['invoice:*'], roles: {} })).toThrow(/resource:action/);
    expect(() => defineRbac({ permissions: ['a:read', 'a:read'], roles: {} })).toThrow(/unique/);
  });

  it('does not treat inherited object properties as roles', () => {
    expect(() =>
      defineRbac({
        permissions: ['a:read'],
        // @ts-expect-error 'constructor' is not a role
        roles: { one: { inherits: ['constructor'], grants: [] } },
      }),
    ).toThrow(/unknown role "constructor"/);
  });

  it('returns frozen structures', () => {
    expect(Object.isFrozen(rbac)).toBe(true);
    expect(Object.isFrozen(rbac.permissions)).toBe(true);
    expect(Object.isFrozen(rbac.roles)).toBe(true);
  });
});
