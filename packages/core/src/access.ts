import { AuthorizationError, ConfigurationError } from './errors.js';
import type { AuthContext, Subject } from './types.js';

// ---------------------------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------------------------

type ResourceOf<P extends string> = P extends `${infer Resource}:${string}` ? Resource : never;

/** What a role may list: a declared permission, every permission of one resource, or everything. */
export type GrantOf<P extends string> = P | `${ResourceOf<P>}:*` | '*';

export interface RoleDefinition<P extends string, R extends string> {
  /** Permissions this role grants directly. `resource:*` and `*` expand against the declared list. */
  readonly grants: readonly GrantOf<P>[];
  /** Roles whose permissions this role also has. */
  readonly inherits?: readonly R[];
}

export interface RbacDefinition<P extends string, R extends string> {
  /** Every permission that exists, as `resource:action`. */
  readonly permissions: readonly P[];
  readonly roles: { readonly [K in R]: RoleDefinition<NoInfer<P>, NoInfer<R>> };
}

export interface Rbac<P extends string = string, R extends string = string> {
  readonly permissions: readonly P[];
  readonly roles: readonly R[];
  /** The union of permissions held by `roles`. Role names that are not in the map are ignored. */
  permissionsFor(roles: readonly string[]): ReadonlySet<P>;
  /** True when at least one of `roles` grants `permission`. */
  grants(roles: readonly string[], permission: P): boolean;
  isPermission(value: string): value is P;
  isRole(value: string): value is R;
}

function invalid(message: string): never {
  throw new ConfigurationError('CONFIGURATION_INVALID', { debug: message });
}

/**
 * Declares the permission vocabulary and the roles that grant it.
 *
 * Role and permission names are inferred as literal types, so a misspelt name is a compile error.
 * The definition is also checked at run time: unknown permissions, unknown parent roles and
 * inheritance cycles throw a `ConfigurationError`.
 */
export function defineRbac<const P extends string, const R extends string>(
  definition: RbacDefinition<P, R>,
): Rbac<P, R> {
  const permissions = [...definition.permissions];
  const permissionSet = new Set<string>(permissions);
  if (permissionSet.size !== permissions.length) invalid('RBAC permissions must be unique.');
  for (const permission of permissions) {
    if (!/^[^:*\s]+:[^*\s]+$/.test(permission)) {
      invalid(`RBAC permission "${permission}" must look like "resource:action" and contain no "*".`);
    }
  }

  const roleNames = Object.keys(definition.roles) as R[];
  const roleMap = definition.roles as Record<string, RoleDefinition<string, string>>;

  const expand = (role: string, grant: string): string[] => {
    if (grant === '*') return permissions;
    if (grant.endsWith(':*')) {
      const prefix = grant.slice(0, -1);
      const matches = permissions.filter((permission) => permission.startsWith(prefix));
      if (matches.length === 0) invalid(`Role "${role}" grants "${grant}", which matches no declared permission.`);
      return matches;
    }
    if (!permissionSet.has(grant)) invalid(`Role "${role}" grants "${grant}", which is not a declared permission.`);
    return [grant];
  };

  const resolved = new Map<string, ReadonlySet<P>>();
  const resolving = new Set<string>();

  const resolve = (role: string, path: readonly string[]): ReadonlySet<P> => {
    const done = resolved.get(role);
    if (done) return done;
    if (resolving.has(role)) invalid(`RBAC role inheritance has a cycle: ${[...path, role].join(' -> ')}.`);
    const roleDefinition = roleMap[role];
    if (!roleDefinition || !Object.hasOwn(roleMap, role)) {
      invalid(`Role "${path[path.length - 1] ?? role}" inherits from unknown role "${role}".`);
    }
    resolving.add(role);
    const result = new Set<P>();
    for (const grant of roleDefinition.grants) {
      for (const permission of expand(role, grant)) result.add(permission as P);
    }
    for (const parent of roleDefinition.inherits ?? []) {
      for (const permission of resolve(parent, [...path, role])) result.add(permission);
    }
    resolving.delete(role);
    resolved.set(role, result);
    return result;
  };

  for (const role of roleNames) resolve(role, []);

  const permissionsFor = (roles: readonly string[]): ReadonlySet<P> => {
    const result = new Set<P>();
    for (const role of roles) {
      const granted = resolved.get(role);
      if (granted) for (const permission of granted) result.add(permission);
    }
    return result;
  };

  return Object.freeze({
    permissions: Object.freeze(permissions),
    roles: Object.freeze(roleNames),
    permissionsFor,
    grants: (roles: readonly string[], permission: P) =>
      roles.some((role) => resolved.get(role)?.has(permission) === true),
    isPermission: (value: string): value is P => permissionSet.has(value),
    isRole: (value: string): value is R => resolved.has(value),
  });
}

// ---------------------------------------------------------------------------------------------
// ABAC
// ---------------------------------------------------------------------------------------------

/** What a single policy returns when it applies. */
export interface PolicyVerdict {
  effect: 'allow' | 'deny';
  reason: string;
}

/** The outcome of evaluating every policy: always allow or deny, with the reason and its source. */
export interface Decision extends PolicyVerdict {
  /** The policy that decided, `"rbac"` for a role grant, or `"default"` when nothing allowed. */
  policy: string;
}

/** Context handed to policies. Add your own fields alongside the standard ones. */
export interface PolicyContext {
  /** How the subject authenticated. */
  auth?: AuthContext;
  /** Current time in epoch seconds. */
  now?: number;
  ip?: string;
  [key: string]: unknown;
}

/**
 * A policy is a pure, synchronous function. Return `allow(...)` or `deny(...)` when the policy
 * applies and nothing when it does not.
 */
export type PolicyFn<S extends Subject = Subject, A extends string = string, R = unknown, C = PolicyContext> = (
  subject: S,
  action: A,
  resource: R,
  context: C,
) => PolicyVerdict | undefined | void;

export interface Policy<S extends Subject = Subject, A extends string = string, R = unknown, C = PolicyContext> {
  readonly name: string;
  readonly evaluate: PolicyFn<S, A, R, C>;
}

export function allow(reason: string): PolicyVerdict {
  return { effect: 'allow', reason };
}

export function deny(reason: string): PolicyVerdict {
  return { effect: 'deny', reason };
}

/** Names a policy function. The name appears in decisions and audit events. */
export function definePolicy<
  S extends Subject = Subject,
  A extends string = string,
  // `any` lets the policy annotate the resource type it expects.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  R = any,
  C = PolicyContext,
>(name: string, evaluate: PolicyFn<S, A, R, C>): Policy<S, A, R, C> {
  if (name.length === 0) invalid('A policy needs a name.');
  if (name === 'rbac' || name === 'default') invalid(`The policy name "${name}" is reserved.`);
  return Object.freeze({ name, evaluate });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyPolicy = Policy<any, any, any, any>;

export interface AuthorizerOptions<P extends string = string> {
  rbac?: Rbac<P, string>;
  policies?: readonly AnyPolicy[];
}

export interface Authorizer<P extends string = string> {
  /**
   * Combines the role map and every policy into one decision:
   *
   * 1. If any policy denies, the decision is deny. The first denying policy supplies the reason.
   * 2. Otherwise, if a role grants the permission or any policy allows, the decision is allow.
   * 3. Otherwise the decision is deny.
   *
   * A policy that throws, or returns a promise, counts as a deny.
   */
  evaluate(subject: Subject, action: P, resource?: unknown, context?: PolicyContext): Decision;
  can(subject: Subject, action: P, resource?: unknown, context?: PolicyContext): boolean;
  /** Throws `AuthorizationError` (`FORBIDDEN`) carrying the reason and policy when the decision is deny. */
  assert(subject: Subject, action: P, resource?: unknown, context?: PolicyContext): void;
}

function isThenable(value: unknown): boolean {
  return typeof value === 'object' && value !== null && typeof (value as { then?: unknown }).then === 'function';
}

export function createAuthorizer<P extends string = string>(options: AuthorizerOptions<P> = {}): Authorizer<P> {
  const rbac = options.rbac;
  const policies = [...(options.policies ?? [])];
  const names = new Set<string>();
  for (const policy of policies) {
    if (names.has(policy.name)) invalid(`Two policies are named "${policy.name}".`);
    names.add(policy.name);
  }

  const evaluate = (subject: Subject, action: P, resource?: unknown, context: PolicyContext = {}): Decision => {
    let firstAllow: Decision | undefined;
    for (const policy of policies) {
      let verdict: PolicyVerdict | undefined | void;
      try {
        verdict = policy.evaluate(subject, action, resource, context);
      } catch {
        return { effect: 'deny', reason: `policy "${policy.name}" failed`, policy: policy.name };
      }
      if (verdict === undefined || verdict === null) continue;
      if (isThenable(verdict)) {
        return { effect: 'deny', reason: `policy "${policy.name}" is asynchronous`, policy: policy.name };
      }
      if (verdict.effect === 'deny') {
        return { effect: 'deny', reason: verdict.reason, policy: policy.name };
      }
      if (verdict.effect === 'allow') {
        firstAllow ??= { effect: 'allow', reason: verdict.reason, policy: policy.name };
        continue;
      }
      return { effect: 'deny', reason: `policy "${policy.name}" returned an unknown effect`, policy: policy.name };
    }
    if (rbac?.grants(subject.roles, action)) {
      return { effect: 'allow', reason: `a role grants "${action}"`, policy: 'rbac' };
    }
    if (firstAllow) return firstAllow;
    return { effect: 'deny', reason: `no role or policy allows "${action}"`, policy: 'default' };
  };

  return Object.freeze({
    evaluate,
    can: (subject: Subject, action: P, resource?: unknown, context?: PolicyContext) =>
      evaluate(subject, action, resource, context).effect === 'allow',
    assert: (subject: Subject, action: P, resource?: unknown, context?: PolicyContext) => {
      const decision = evaluate(subject, action, resource, context);
      if (decision.effect === 'deny') {
        throw new AuthorizationError('FORBIDDEN', {
          details: { reason: decision.reason, policy: decision.policy, action },
        });
      }
    },
  });
}
