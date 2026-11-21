import {
  ConfigurationError,
  MfaError,
  NetworkError,
  RequestError,
  createAuthorizer,
  errorFromBody,
  isAuthError,
  type AccessGrantResponse,
  type AccountSecurity,
  type AuthContext,
  type LoginResponse,
  type PasskeyInfo,
  type PasskeyListResponse,
  type PasskeyOptionsResponse,
  type RecoveryCodesResponse,
  type SessionInfo,
  type SessionListResponse,
  type SessionResponse,
  type TotpEnrollmentResponse,
} from '@koshi-repo/auth-core';
import { broadcastChannel } from './channel.js';
import { DpopSigner, defaultKeyStore } from './dpop.js';
import { evaluateGuard, type GuardRequirement, type GuardResult } from './guards.js';
import { defaultLocks } from './locks.js';
import type { AuthClient, AuthClientOptions, AuthState, ReauthFactor, WebAuthnBrowser } from './types.js';

interface SendOptions {
  body?: unknown;
  /** Attach this access token. */
  token?: string;
  /** Send and accept the refresh cookie. */
  withCookie?: boolean;
}

function resolveBaseUrl(value: string): string {
  const page = (globalThis as { location?: { href?: string } }).location?.href;
  let url: URL;
  try {
    url = page ? new URL(value, page) : new URL(value);
  } catch {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: `baseUrl "${value}" is not an absolute URL, and there is no page URL to resolve it against.`,
    });
  }
  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
}

/**
 * Creates the browser client.
 *
 * The access token lives in a variable inside this function. It is not a property of the returned
 * object, is never written to `localStorage`, `sessionStorage`, IndexedDB or a cookie, and is not
 * sent to other tabs. The refresh token never reaches script at all: it stays in its `HttpOnly`
 * cookie.
 */
export function createAuthClient(options: AuthClientOptions): AuthClient {
  const baseUrl = resolveBaseUrl(options.baseUrl);
  const localNow = options.now ?? Date.now;
  const skewMs = (options.refreshSkewSec ?? 30) * 1000;
  const fetchImpl: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const locks = options.locks === null ? null : (options.locks ?? defaultLocks());
  const channel = options.channel === null ? null : (options.channel ?? broadcastChannel(`koshi-auth:${baseUrl}`));
  const rbac = options.access?.rbac;
  const authorizer = createAuthorizer({
    ...(rbac ? { rbac } : {}),
    ...(options.access?.policies ? { policies: options.access.policies } : {}),
  });

  // The difference between the server's clock and this device's, learned when the server rejects a
  // proof for its timestamp. DPoP proofs are only valid for about a minute either side of server time.
  let clockOffsetMs = 0;
  const now = () => localNow() + clockOffsetMs;

  const dpop =
    options.dpop === false
      ? null
      : new DpopSigner(typeof options.dpop === 'object' && options.dpop.keyStore ? options.dpop.keyStore : defaultKeyStore(), now, locks);

  // ---- private state -------------------------------------------------------------------------
  let accessToken: { value: string; expiresAtMs: number } | null = null;
  let mfaTicket: string | null = null;
  let state: AuthState = options.restoreOnStart === false ? { status: 'unauthenticated' } : { status: 'loading' };
  let refreshing: Promise<void> | null = null;
  let disposed = false;
  const listeners = new Set<(state: AuthState) => void>();

  const setState = (next: AuthState): AuthState => {
    state = next;
    for (const listener of [...listeners]) {
      try {
        listener(state);
      } catch {
        // One broken subscriber must not stop the others or the login that triggered the change.
      }
    }
    return state;
  };

  const signedOut = (): AuthState => {
    accessToken = null;
    mfaTicket = null;
    return state.status === 'unauthenticated' ? state : setState({ status: 'unauthenticated' });
  };

  const applyGrant = (grant: AccessGrantResponse): AuthState => {
    accessToken = { value: grant.accessToken, expiresAtMs: grant.accessTokenExpiresAt * 1000 };
    mfaTicket = null;
    return setState({ status: 'authenticated', user: grant.user, session: grant.session });
  };

  // ---- transport -----------------------------------------------------------------------------

  /** Builds one request, with a fresh proof, and sends it. */
  const dispatch = async (method: string, url: string, send: SendOptions): Promise<Response> => {
    const headers = new Headers({ accept: 'application/json' });
    let body: string | undefined;
    if (send.body !== undefined) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(send.body);
    }
    if (send.token !== undefined) headers.set('authorization', `${dpop ? 'DPoP' : 'Bearer'} ${send.token}`);
    if (dpop) headers.set('dpop', await dpop.proof(method, url, send.token));
    try {
      return await fetchImpl(url, {
        method,
        headers,
        ...(body !== undefined ? { body } : {}),
        credentials: send.withCookie ? 'include' : 'omit',
      });
    } catch (cause) {
      throw new NetworkError('NETWORK_ERROR', { cause });
    }
  };

  /**
   * If the server rejected a proof because this device's clock is off, remembers the difference.
   * Returns true when a retry with a corrected timestamp is worthwhile.
   */
  const learnClockOffset = (error: unknown): boolean => {
    if (!isAuthError(error) || error.code !== 'DPOP_PROOF_INVALID') return false;
    const serverTime = error.details?.serverTime;
    if (typeof serverTime !== 'number') return false;
    clockOffsetMs = serverTime * 1000 - localNow();
    return true;
  };

  const readError = async (response: Response): Promise<Error> => {
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }
    return errorFromBody(payload);
  };

  /** Sends a request to an auth endpoint and returns the parsed body, or throws an `AuthError`. */
  const call = async <T>(method: string, path: string, send: SendOptions = {}): Promise<T> => {
    const url = `${baseUrl}${path}`;
    let response = await dispatch(method, url, send);
    if (!response.ok) {
      let error = await readError(response);
      if (learnClockOffset(error)) {
        response = await dispatch(method, url, send);
        if (response.ok) return (response.status === 204 ? undefined : await response.json()) as T;
        error = await readError(response);
      }
      throw error;
    }
    return (response.status === 204 ? undefined : await response.json()) as T;
  };

  // ---- refresh -------------------------------------------------------------------------------

  const doRefresh = async (): Promise<void> => {
    if (disposed) return;
    try {
      applyGrant(await call<AccessGrantResponse>('POST', '/refresh', { withCookie: true }));
    } catch (error) {
      // 401 and 403 mean the session is over. Anything else (offline, server error, throttling)
      // says nothing about the session, so the state is kept and the caller sees the error.
      if (isAuthError(error) && (error.status === 401 || error.status === 403)) {
        signedOut();
        return;
      }
      throw error;
    }
  };

  /**
   * One refresh at a time. Callers inside this page share the request in flight. Across tabs the
   * lock makes refreshes take turns, so two tabs never present the same refresh token, which the
   * server would treat as reuse and answer by revoking the session.
   */
  const refresh = (): Promise<void> => {
    refreshing ??= (locks ? locks.request(`koshi-auth:refresh:${baseUrl}`, doRefresh) : doRefresh()).finally(() => {
      refreshing = null;
    });
    return refreshing;
  };

  const initial: Promise<AuthState> =
    state.status === 'loading'
      ? refresh().then(
          () => (state.status === 'loading' ? signedOut() : state),
          () => signedOut(),
        )
      : Promise.resolve(state);

  const getAccessToken = async (tokenOptions: { forceRefresh?: boolean } = {}): Promise<string | null> => {
    await initial;
    if (state.status !== 'authenticated') return null;
    if (!tokenOptions.forceRefresh && accessToken && accessToken.expiresAtMs - skewMs > now()) return accessToken.value;
    await refresh();
    return accessToken?.value ?? null;
  };

  /** A call to an auth endpoint that needs the access token. Refreshes and retries once on a 401. */
  const authed = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
    const token = await getAccessToken();
    if (token === null) throw errorFromBody({ code: 'TOKEN_MISSING' });
    const send = (value: string) => call<T>(method, path, { token: value, ...(body !== undefined ? { body } : {}) });
    try {
      return await send(token);
    } catch (error) {
      if (!isAuthError(error) || error.status !== 401 || error.kind !== 'token') throw error;
      const fresh = await getAccessToken({ forceRefresh: true });
      if (fresh === null) throw error;
      return send(fresh);
    }
  };

  // ---- passkeys ------------------------------------------------------------------------------

  const webauthn = async (): Promise<WebAuthnBrowser> => {
    if (options.webauthn) return options.webauthn;
    try {
      return (await import('@simplewebauthn/browser')) as unknown as WebAuthnBrowser;
    } catch (cause) {
      throw new ConfigurationError('CONFIGURATION_INVALID', {
        debug: 'Passkeys need the "@simplewebauthn/browser" package to be installed.',
        cause,
      });
    }
  };

  const completeLogin = (response: LoginResponse): AuthState => {
    if (response.status === 'authenticated') {
      const next = applyGrant(response);
      channel?.post({ type: 'signed-in' });
      return next;
    }
    accessToken = null;
    mfaTicket = response.ticket;
    return setState({
      status: 'mfa_required',
      methods: response.methods,
      reason: response.reason,
      expiresAt: response.expiresAt,
    });
  };

  // ---- other tabs ----------------------------------------------------------------------------

  channel?.subscribe((message) => {
    if (disposed) return;
    if (message.type === 'signed-out') signedOut();
    // Another tab signed in: pick the session up through the cookie it set.
    else if (state.status !== 'authenticated') void refresh().catch(() => undefined);
  });

  const authContext = (session: SessionInfo): AuthContext => ({
    sessionId: session.id,
    methods: session.methods,
    assurance: session.assurance,
    authenticatedAt: session.authenticatedAt,
    deviceBound: session.deviceBound,
  });

  const client: AuthClient = {
    getState: () => state,

    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    ready: () => initial,

    async loginWithPassword(input) {
      await initial;
      return completeLogin(await call<LoginResponse>('POST', '/login/password', { body: input, withCookie: true }));
    },

    async loginWithPasskey(input = {}) {
      await initial;
      const { challengeId, options: ceremony } = await call<PasskeyOptionsResponse>('POST', '/login/passkey/options', {
        body: input.identifier === undefined ? {} : { identifier: input.identifier },
      });
      const response = await (await webauthn()).startAuthentication({ optionsJSON: ceremony as never });
      return completeLogin(await call<LoginResponse>('POST', '/login/passkey', { body: { challengeId, response }, withCookie: true }));
    },

    async submitMfa(input) {
      if (mfaTicket === null) throw new MfaError('MFA_TICKET_INVALID');
      try {
        return completeLogin(
          await call<LoginResponse>('POST', '/mfa/verify', {
            body: { ticket: mfaTicket, method: input.method, code: input.code },
            withCookie: true,
          }),
        );
      } catch (error) {
        // The ticket is spent or expired: the login has to start again.
        if (isAuthError(error) && error.code === 'MFA_TICKET_INVALID') signedOut();
        throw error;
      }
    },

    cancelMfa() {
      if (state.status === 'mfa_required') signedOut();
    },

    async reauthenticate(factor: ReauthFactor) {
      let body: unknown;
      if (factor.method === 'passkey') {
        const identifier = state.status === 'authenticated' ? state.user.identifier : undefined;
        const { challengeId, options: ceremony } = await call<PasskeyOptionsResponse>('POST', '/login/passkey/options', {
          body: identifier === undefined ? {} : { identifier },
        });
        const response = await (await webauthn()).startAuthentication({ optionsJSON: ceremony as never });
        body = { method: 'passkey', challengeId, response };
      } else {
        body = factor;
      }
      return applyGrant(await authed<AccessGrantResponse>('POST', '/reauthenticate', body));
    },

    async logout(logoutOptions = {}) {
      await initial;
      try {
        await call<void>('POST', logoutOptions.allSessions ? '/logout/all' : '/logout', { withCookie: true });
      } finally {
        // This tab is signed out whatever the server said, and so are the others.
        signedOut();
        channel?.post({ type: 'signed-out' });
      }
    },

    getAccessToken,

    async fetch(input, init) {
      // A template is cloned per attempt, so a request with a body can be sent again after a refresh.
      const template = new Request(input, init);
      const attempt = async (token: string | null): Promise<Response> => {
        const request = template.clone();
        if (token !== null) {
          request.headers.set('authorization', `${dpop ? 'DPoP' : 'Bearer'} ${token}`);
          if (dpop) request.headers.set('dpop', await dpop.proof(request.method, request.url, token));
        }
        return fetchImpl(request);
      };

      const token = await getAccessToken();
      const response = await attempt(token);
      if (response.status !== 401 || token === null) return response;

      // The token may have expired or been replaced, or this device's clock may be off.
      learnClockOffset(await readError(response.clone()));
      let fresh: string | null;
      try {
        fresh = await getAccessToken({ forceRefresh: true });
      } catch {
        return response;
      }
      return fresh === null ? response : attempt(fresh);
    },

    mfa: {
      async status(): Promise<AccountSecurity> {
        return (await authed<SessionResponse>('GET', '/session')).security;
      },
      beginTotpEnrollment: () => authed<TotpEnrollmentResponse>('POST', '/mfa/totp/enroll'),
      confirmTotpEnrollment: (input) => authed<RecoveryCodesResponse>('POST', '/mfa/totp/confirm', input),
      removeTotp: () => authed<void>('DELETE', '/mfa/totp'),
      regenerateRecoveryCodes: async () => (await authed<RecoveryCodesResponse>('POST', '/mfa/recovery-codes')).recoveryCodes,
    },

    passkeys: {
      async register(input = {}) {
        const { challengeId, options: ceremony } = await authed<PasskeyOptionsResponse>('POST', '/passkeys/options');
        const response = await (await webauthn()).startRegistration({ optionsJSON: ceremony as never });
        return authed<PasskeyInfo>('POST', '/passkeys', {
          challengeId,
          response,
          ...(input.name !== undefined ? { name: input.name } : {}),
        });
      },
      list: async () => (await authed<PasskeyListResponse>('GET', '/passkeys')).passkeys,
      remove: (id) => authed<void>('DELETE', `/passkeys/${encodeURIComponent(id)}`),
    },

    sessions: {
      list: async () => (await authed<SessionListResponse>('GET', '/sessions')).sessions,
      async revoke(id) {
        await authed<void>('DELETE', `/sessions/${encodeURIComponent(id)}`);
        if (state.status === 'authenticated' && state.session.id === id) {
          signedOut();
          channel?.post({ type: 'signed-out' });
        }
      },
    },

    changePassword(input) {
      if (typeof input?.currentPassword !== 'string' || typeof input.newPassword !== 'string') {
        return Promise.reject(new RequestError('REQUEST_INVALID'));
      }
      return authed<void>('POST', '/password', input);
    },

    check(requirement: GuardRequirement = {}): GuardResult {
      return evaluateGuard(state, requirement, { rbac, nowSec: Math.floor(now() / 1000) });
    },

    can(action, resource, context = {}) {
      if (state.status !== 'authenticated') return false;
      return authorizer.can({ id: state.user.id, roles: state.user.roles }, action, resource, {
        ...context,
        auth: authContext(state.session),
        now: Math.floor(now() / 1000),
      });
    },

    dispose() {
      disposed = true;
      listeners.clear();
      channel?.close();
    },
  };

  return client;
}
