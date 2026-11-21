/**
 * React bindings. Everything here is headless: there is no markup, class name or style.
 * `AuthProvider` and `AuthGuard` render only what you pass them.
 */
import type { AuthError, MfaMethod, PublicUser, SessionInfo } from '@koshi-repo/auth-core';
import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactElement,
  type ReactNode,
} from 'react';
import type { GuardRequirement, GuardResult } from '../guards.js';
import type { AuthClient, AuthState } from '../types.js';

const AuthClientContext = createContext<AuthClient | null>(null);

/** Makes a client available to the hooks below. */
export function AuthProvider(props: { client: AuthClient; children?: ReactNode }): ReactElement {
  return createElement(AuthClientContext.Provider, { value: props.client }, props.children);
}

/** The client given to the nearest `AuthProvider`. */
export function useAuthClient(): AuthClient {
  const client = useContext(AuthClientContext);
  if (!client) throw new Error('useAuthClient must be used inside an <AuthProvider>.');
  return client;
}

/** The current auth state. The component re-renders whenever it changes. */
export function useAuthState(): AuthState {
  const client = useAuthClient();
  return useSyncExternalStore(client.subscribe, client.getState, client.getState);
}

export interface UseAuthResult {
  state: AuthState;
  /** True while the session is being restored on page load. */
  isLoading: boolean;
  isAuthenticated: boolean;
  user: PublicUser | null;
  session: SessionInfo | null;
  logout: AuthClient['logout'];
  client: AuthClient;
}

/** State plus the most common derived values. */
export function useAuth(): UseAuthResult {
  const client = useAuthClient();
  const state = useAuthState();
  return useMemo(
    () => ({
      state,
      isLoading: state.status === 'loading',
      isAuthenticated: state.status === 'authenticated',
      user: state.status === 'authenticated' ? state.user : null,
      session: state.status === 'authenticated' ? state.session : null,
      logout: client.logout,
      client,
    }),
    [client, state],
  );
}

export interface UseLoginResult {
  state: AuthState;
  loginWithPassword(input: { identifier: string; password: string }): Promise<AuthState | undefined>;
  loginWithPasskey(input?: { identifier?: string }): Promise<AuthState | undefined>;
  submitMfa(input: { method: MfaMethod; code: string }): Promise<AuthState | undefined>;
  cancelMfa(): void;
  /** True while a request is in flight. */
  pending: boolean;
  /** The error of the last attempt, or null. Show `error.message`, which is always safe to display. */
  error: AuthError | Error | null;
  reset(): void;
}

/**
 * Sign-in actions with `pending` and `error` tracked for you. The actions resolve with the new
 * state, or with `undefined` after a failure, which is reported through `error` instead of thrown.
 */
export function useLogin(): UseLoginResult {
  const client = useAuthClient();
  const state = useAuthState();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<AuthError | Error | null>(null);

  const run = useCallback(async (action: () => Promise<AuthState>): Promise<AuthState | undefined> => {
    setPending(true);
    setError(null);
    try {
      return await action();
    } catch (caught) {
      setError(caught instanceof Error ? caught : new Error(String(caught)));
      return undefined;
    } finally {
      setPending(false);
    }
  }, []);

  return useMemo(
    () => ({
      state,
      loginWithPassword: (input: { identifier: string; password: string }) => run(() => client.loginWithPassword(input)),
      loginWithPasskey: (input?: { identifier?: string }) => run(() => client.loginWithPasskey(input)),
      submitMfa: (input: { method: MfaMethod; code: string }) => run(() => client.submitMfa(input)),
      cancelMfa: () => {
        setError(null);
        client.cancelMfa();
      },
      pending,
      error,
      reset: () => setError(null),
    }),
    [client, state, run, pending, error],
  );
}

/** The guard decision for a requirement, re-evaluated whenever the auth state changes. */
export function useGuard(requirement?: GuardRequirement): GuardResult {
  const client = useAuthClient();
  useAuthState();
  return client.check(requirement);
}

/** Whether the signed-in user may do `action`, according to the roles and policies given to the client. */
export function useCan(action: string, resource?: unknown, context?: Record<string, unknown>): boolean {
  const client = useAuthClient();
  useAuthState();
  return client.can(action, resource, context);
}

export interface AuthGuardProps {
  require?: GuardRequirement;
  /** Rendered when access is denied. Receives the decision, so it can redirect to login or step-up. */
  fallback?: ReactNode | ((result: Extract<GuardResult, { status: 'deny' }>) => ReactNode);
  /** Rendered while the session is being restored. Default: nothing. */
  pending?: ReactNode;
  children?: ReactNode;
}

/**
 * Renders its children when the requirement is met, `pending` while the session is loading, and
 * `fallback` otherwise. It hides interface. It does not protect data: the server does that.
 */
export function AuthGuard(props: AuthGuardProps): ReactNode {
  const result = useGuard(props.require);
  if (result.status === 'allow') return props.children ?? null;
  if (result.status === 'pending') return props.pending ?? null;
  return typeof props.fallback === 'function' ? props.fallback(result) : (props.fallback ?? null);
}
