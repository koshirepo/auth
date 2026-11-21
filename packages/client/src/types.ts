import type { AccountSecurity, MfaMethod, PasskeyInfo, Policy, PublicUser, Rbac, SessionInfo } from '@koshirepo/auth-core';
import type { ChannelLike } from './channel.js';
import type { DpopKeyStore } from './dpop.js';
import type { GuardRequirement, GuardResult } from './guards.js';
import type { LockManagerLike } from './locks.js';

/** Everything the interface needs to know about who is signed in. */
export type AuthState =
  /** The client is restoring a session from the cookie. Render nothing or a placeholder. */
  | { status: 'loading' }
  | { status: 'unauthenticated' }
  /** The first factor succeeded. Call `submitMfa` with a code. */
  | { status: 'mfa_required'; methods: MfaMethod[]; reason: 'enrolled' | 'risk'; expiresAt: number }
  | { status: 'authenticated'; user: PublicUser; session: SessionInfo };

/** The browser half of the WebAuthn ceremonies. `@simplewebauthn/browser` has exactly this shape. */
export interface WebAuthnBrowser {
  startRegistration(input: { optionsJSON: never }): Promise<unknown>;
  startAuthentication(input: { optionsJSON: never }): Promise<unknown>;
}

/** A factor presented to re-authenticate inside the current session. */
export type ReauthFactor =
  | { method: 'password'; password: string }
  | { method: MfaMethod; code: string }
  /** Runs the passkey ceremony in the browser. */
  | { method: 'passkey' };

export interface AuthClientOptions {
  /**
   * Where the auth endpoints live, for example `https://api.example.com/auth`. A path such as
   * `/auth` is resolved against the page's origin.
   */
  baseUrl: string;
  /** Default: the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Device binding. Default `true`: an ES256 key is created with WebCrypto, marked non-extractable
   * and kept in IndexedDB, and every request carries a DPoP proof signed by it. Pass
   * `{ keyStore }` to control where the key lives, or `false` if the server has binding off.
   */
  dpop?: boolean | { keyStore?: DpopKeyStore };
  /** The role map and policies the server uses, for `check()`, `can()` and the React guards. */
  access?: {
    rbac?: Rbac<string, string>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    policies?: readonly Policy<any, any, any, any>[];
  };
  /** Refresh this many seconds before the access token expires. Default 30. */
  refreshSkewSec?: number;
  /** Try to restore the session from the cookie as soon as the client is created. Default true. */
  restoreOnStart?: boolean;
  /**
   * Serialises refreshes across tabs. Default: the Web Locks API, falling back to a lock inside
   * this page. Pass `null` to disable, which makes two tabs refreshing at once trip reuse detection.
   */
  locks?: LockManagerLike | null;
  /** Tells other tabs about sign-in and sign-out. Default: a `BroadcastChannel`. Pass `null` to disable. */
  channel?: ChannelLike | null;
  /** Default: `@simplewebauthn/browser`, loaded on first use. */
  webauthn?: WebAuthnBrowser;
  /** Epoch milliseconds. Default `Date.now`. */
  now?: () => number;
}

export interface AuthClient {
  // State
  getState(): AuthState;
  /** Calls `listener` on every state change. Returns a function that unsubscribes. */
  subscribe(listener: (state: AuthState) => void): () => void;
  /** Settles once the initial session restore has finished. Never rejects. */
  ready(): Promise<AuthState>;

  // Sign-in and sign-out. Each resolves with the new state and rejects with an `AuthError`.
  loginWithPassword(input: { identifier: string; password: string }): Promise<AuthState>;
  loginWithPasskey(input?: { identifier?: string }): Promise<AuthState>;
  submitMfa(input: { method: MfaMethod; code: string }): Promise<AuthState>;
  /** Abandons a login that is waiting for its second factor. */
  cancelMfa(): void;
  reauthenticate(factor: ReauthFactor): Promise<AuthState>;
  logout(options?: { allSessions?: boolean }): Promise<void>;

  // Tokens
  /**
   * The current access token, refreshed first if it is about to expire. Null when signed out.
   * Concurrent callers share one refresh request.
   */
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
  /**
   * `fetch` with the access token and a DPoP proof attached. On a 401 it refreshes once and
   * retries once.
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;

  // Account security
  mfa: {
    status(): Promise<AccountSecurity>;
    beginTotpEnrollment(): Promise<{ enrollmentId: string; secret: string; otpauthUri: string }>;
    confirmTotpEnrollment(input: { enrollmentId: string; code: string }): Promise<{ recoveryCodes: string[] }>;
    removeTotp(): Promise<void>;
    regenerateRecoveryCodes(): Promise<string[]>;
  };
  passkeys: {
    register(input?: { name?: string }): Promise<PasskeyInfo>;
    list(): Promise<PasskeyInfo[]>;
    remove(id: string): Promise<void>;
  };
  sessions: {
    list(): Promise<SessionInfo[]>;
    revoke(id: string): Promise<void>;
  };
  changePassword(input: { currentPassword: string; newPassword: string }): Promise<void>;

  // Guards. These decide what to show. The server decides what is allowed.
  check(requirement?: GuardRequirement): GuardResult;
  can(action: string, resource?: unknown, context?: Record<string, unknown>): boolean;

  /** Stops listening to other tabs. Call it when the client is thrown away, for example in tests. */
  dispose(): void;
}
