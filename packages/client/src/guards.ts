import type { Rbac } from '@koshirepo/auth-core';
import type { AuthState } from './types.js';

/** What a route or a piece of interface needs. Every field given must hold. */
export interface GuardRequirement {
  /** The user needs at least one of these roles. */
  roles?: readonly string[];
  /** The user needs all of these permissions, resolved through the role map. */
  permissions?: readonly string[];
  /** Two factors, or a passkey with user verification. */
  assurance?: 'aal2';
  /** The last interactive authentication must be at most this old. */
  maxAuthAgeSec?: number;
}

export type GuardResult =
  | { status: 'allow' }
  /** The session is still being restored. Render nothing or a placeholder. */
  | { status: 'pending' }
  | {
      status: 'deny';
      /**
       * What would help: `login` and `mfa` continue the sign-in, `step_up` means re-authenticate,
       * `forbidden` means nothing will.
       */
      action: 'login' | 'mfa' | 'step_up' | 'forbidden';
      reason: string;
    };

/**
 * Decides what to show for a state and a requirement. It performs no navigation: your router
 * decides what each `action` means.
 *
 * This is an interface convenience. A user can change anything in their own browser, so access
 * is always enforced again by the server.
 */
export function evaluateGuard(
  state: AuthState,
  requirement: GuardRequirement = {},
  options: { rbac?: Rbac<string, string> | undefined; nowSec: number },
): GuardResult {
  if (state.status === 'loading') return { status: 'pending' };
  if (state.status === 'unauthenticated') return { status: 'deny', action: 'login', reason: 'not signed in' };
  if (state.status === 'mfa_required') return { status: 'deny', action: 'mfa', reason: 'a second factor is required' };

  const { user, session } = state;
  if (requirement.roles && requirement.roles.length > 0 && !requirement.roles.some((role) => user.roles.includes(role))) {
    return { status: 'deny', action: 'forbidden', reason: `requires one of the roles: ${requirement.roles.join(', ')}` };
  }
  if (requirement.permissions && requirement.permissions.length > 0) {
    if (!options.rbac) {
      return { status: 'deny', action: 'forbidden', reason: 'no role map is configured to resolve permissions' };
    }
    const granted = options.rbac.permissionsFor(user.roles) as ReadonlySet<string>;
    const missing = requirement.permissions.filter((permission) => !granted.has(permission));
    if (missing.length > 0) {
      return { status: 'deny', action: 'forbidden', reason: `missing permission: ${missing.join(', ')}` };
    }
  }
  // Step-up comes last: there is no point asking for it if the user lacks the permission anyway.
  if (requirement.assurance === 'aal2' && session.assurance !== 'aal2') {
    return { status: 'deny', action: 'step_up', reason: 'requires a second factor' };
  }
  if (requirement.maxAuthAgeSec !== undefined && options.nowSec - session.authenticatedAt > requirement.maxAuthAgeSec) {
    return { status: 'deny', action: 'step_up', reason: 'requires a recent sign-in' };
  }
  return { status: 'allow' };
}
