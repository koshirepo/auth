import {
  ConfigurationError,
  InternalError,
  MfaError,
  RequestError,
  SessionError,
  TokenError,
  isAuthError,
  type AccessGrantResponse,
  type AuthError,
  type ErrorResponse,
  type LoginResponse,
  type MfaMethod,
  type PasskeyListResponse,
  type RecoveryCodesResponse,
  type SessionListResponse,
  type SessionResponse,
} from '@acme/auth-core';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { Auth, ReauthFactor } from '../auth.js';
import type { RequestContext } from '../context.js';
import type { LoginResult } from '../login/login-service.js';
import type { AccessGrant, Authenticated } from '../sessions/session-service.js';
import { toPublicUser } from '../sessions/views.js';
import type { VerifiedToken } from '../tokens/token-service.js';
import { clearedRefreshCookie, readCookie, refreshCookie } from './cookies.js';

export const JWKS_PATH = '/.well-known/jwks.json';

export interface AuthHandlerOptions {
  /** Path the auth endpoints live under. Default `/auth`. */
  basePath?: string;
  /**
   * The origin browsers use to reach this server, for example `https://api.example.com`. DPoP
   * proofs are checked against it, so it must be exactly what the browser sees, not an internal
   * address behind a proxy.
   */
  publicOrigin: string;
  /**
   * Origins of the web pages allowed to call these endpoints. Used for CORS and to reject
   * cross-site requests. Default: `[publicOrigin]`, which suits an app served from the same origin.
   */
  allowedOrigins?: readonly string[];
  /**
   * Returns the client's IP address for risk scoring and throttling. Read it from whatever your
   * trusted proxy sets. The library never looks at `X-Forwarded-For` itself, because that header
   * can be forged by the client.
   */
  clientIp?: (request: Request) => string | undefined;
  /** Largest request body accepted. Default 65536 bytes. */
  maxBodyBytes?: number;
  /** Called with errors that are not `AuthError`s, before a generic 500 is returned. Log them here. */
  onError?: (error: unknown, request: Request) => void;
}

export type AuthHandler = (request: Request) => Promise<Response>;

export interface RequireAuthOptions {
  /** Require two factors, or a passkey with user verification. */
  assurance?: 'aal2';
  /** Require an interactive authentication at most this many seconds ago. */
  maxAuthAgeSec?: number;
  /** Also reject tokens whose session was revoked. Costs one store read. */
  checkSession?: boolean;
}

export interface HttpAuthContext {
  /** Builds the request context services expect, including the DPoP proof and the URL it must match. */
  requestContext(request: Request): RequestContext;
  /**
   * Verifies the access token and DPoP proof of a request to one of your own endpoints. Throws
   * `STEP_UP_REQUIRED` if the session does not meet the requirements.
   */
  authenticate(request: Request, requirements?: RequireAuthOptions): Promise<VerifiedToken>;
  /** Turns any error into the JSON response this library sends for it. */
  errorResponse(error: unknown, request: Request): Response;
}

interface ResolvedOptions {
  basePath: string;
  publicOrigin: string;
  allowedOrigins: ReadonlySet<string>;
  clientIp: (request: Request) => string | undefined;
  maxBodyBytes: number;
  onError: (error: unknown, request: Request) => void;
}

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

function bareOrigin(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigurationError('CONFIGURATION_INVALID', { debug: `${name} "${value}" is not a URL.` });
  }
  if (url.origin !== value) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: `${name} must be a bare origin such as "${url.origin}", without a path or trailing slash.`,
    });
  }
  return value;
}

function resolveOptions(options: AuthHandlerOptions): ResolvedOptions {
  const publicOrigin = bareOrigin('publicOrigin', options.publicOrigin);
  const basePath = options.basePath ?? '/auth';
  if (!/^\/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$/.test(basePath)) {
    throw new ConfigurationError('CONFIGURATION_INVALID', {
      debug: 'basePath must start with "/" and must not end with one, for example "/auth".',
    });
  }
  const allowedOrigins = new Set((options.allowedOrigins ?? [publicOrigin]).map((origin) => bareOrigin('allowedOrigins', origin)));
  return {
    basePath,
    publicOrigin,
    allowedOrigins,
    clientIp: options.clientIp ?? (() => undefined),
    maxBodyBytes: options.maxBodyBytes ?? 65_536,
    onError: options.onError ?? (() => undefined),
  };
}

/** The pieces of the HTTP layer that framework adapters reuse for protecting your own routes. */
export function createHttpAuthContext(auth: Auth, handlerOptions: AuthHandlerOptions): HttpAuthContext {
  const options = resolveOptions(handlerOptions);
  return buildContext(auth, options);
}

function buildContext(auth: Auth, options: ResolvedOptions): HttpAuthContext {
  const requestContext = (request: Request): RequestContext => {
    const ctx: RequestContext = {};
    const ip = options.clientIp(request);
    if (typeof ip === 'string' && ip.length > 0) ctx.ip = ip;
    const userAgent = request.headers.get('user-agent');
    if (userAgent) ctx.userAgent = userAgent;
    // Two DPoP headers arrive joined by a comma, which is not a valid proof and is rejected as such.
    const proof = request.headers.get('dpop');
    if (proof) {
      ctx.dpop = { proof, method: request.method, url: `${options.publicOrigin}${new URL(request.url).pathname}` };
    }
    return ctx;
  };

  const authenticate = async (request: Request, requirements: RequireAuthOptions = {}): Promise<VerifiedToken> => {
    const header = request.headers.get('authorization');
    const match = header === null ? null : /^(DPoP|Bearer) +([^ ]+)$/i.exec(header.trim());
    if (!match) throw new TokenError('TOKEN_MISSING');
    const verified = await auth.tokens.verify(match[2] as string, requestContext(request), {
      checkSession: requirements.checkSession ?? false,
    });
    if (requirements.assurance === 'aal2' && verified.context.assurance !== 'aal2') {
      throw new MfaError('STEP_UP_REQUIRED', { details: { required: 'aal2' } });
    }
    if (
      requirements.maxAuthAgeSec !== undefined &&
      auth.clock.nowSec() - verified.context.authenticatedAt > requirements.maxAuthAgeSec
    ) {
      throw new MfaError('STEP_UP_REQUIRED', { details: { required: 'recent_authentication', maxAuthAgeSec: requirements.maxAuthAgeSec } });
    }
    return verified;
  };

  const errorResponse = (error: unknown, request: Request): Response => {
    let authError: AuthError;
    if (isAuthError(error) && error.kind !== 'internal' && error.kind !== 'configuration' && error.kind !== 'network') {
      authError = error;
    } else {
      // Unexpected failures are reported to the application and never described to the caller.
      options.onError(error, request);
      authError = new InternalError('INTERNAL_ERROR');
    }
    const headers = new Headers(JSON_HEADERS);
    const retryAfter = authError.details?.retryAfterSec;
    if (authError.code === 'RATE_LIMITED' && typeof retryAfter === 'number') headers.set('retry-after', String(retryAfter));
    if (authError.status === 401 && (authError.kind === 'token' || authError.kind === 'dpop')) {
      const reason = authError.kind === 'dpop' ? 'invalid_dpop_proof' : 'invalid_token';
      headers.set('www-authenticate', `DPoP error="${reason}", algs="${auth.config.dpop.algorithms.join(' ')}"`);
    }
    const body: ErrorResponse = { error: authError.toJSON() };
    return new Response(JSON.stringify(body), { status: authError.status, headers });
  };

  return { requestContext, authenticate, errorResponse };
}

interface RouteResult {
  status?: number;
  body?: unknown;
  /** `Set-Cookie` values. */
  cookies?: string[];
  headers?: Record<string, string>;
}

interface RouteInput {
  request: Request;
  ctx: RequestContext;
  body: Record<string, unknown>;
  params: Record<string, string>;
}

interface Route {
  method: 'GET' | 'POST' | 'DELETE';
  segments: string[];
  /** True for routes authenticated by the refresh cookie, which browsers attach on their own. */
  usesCookie?: boolean;
  handle(input: RouteInput): Promise<RouteResult>;
}

function str(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== 'string') throw new RequestError('REQUEST_INVALID', { details: { field } });
  return value;
}

function optionalStr(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw new RequestError('REQUEST_INVALID', { details: { field } });
  return value;
}

function obj(body: Record<string, unknown>, field: string): Record<string, unknown> {
  const value = body[field];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RequestError('REQUEST_INVALID', { details: { field } });
  }
  return value as Record<string, unknown>;
}

function mfaMethod(body: Record<string, unknown>): MfaMethod {
  const method = body.method;
  if (method !== 'totp' && method !== 'recovery_code') throw new RequestError('REQUEST_INVALID', { details: { field: 'method' } });
  return method;
}

/**
 * Builds the response body for a grant field by field. Nothing is spread from the service result,
 * so the refresh token it carries cannot end up in a body by accident.
 */
function grantBody(grant: AccessGrant): AccessGrantResponse {
  return {
    status: 'authenticated',
    accessToken: grant.accessToken,
    accessTokenExpiresAt: grant.accessTokenExpiresAt,
    user: grant.user,
    session: grant.session,
  };
}

/**
 * Creates the HTTP handler for every auth endpoint plus the JWKS document.
 *
 * The handler takes a Fetch `Request` and returns a `Response`, so it mounts directly in any
 * runtime or framework built on those types. For Express, use `@acme/auth-server/express`.
 */
export function createAuthHandler(auth: Auth, handlerOptions: AuthHandlerOptions): AuthHandler {
  const options = resolveOptions(handlerOptions);
  const http = buildContext(auth, options);
  const cookieConfig = auth.config.sessions.cookie;

  const setRefreshCookie = (result: Authenticated): string =>
    refreshCookie(cookieConfig, result.refreshToken, result.refreshTokenExpiresAt - auth.clock.nowSec());

  const loginResult = (result: LoginResult): RouteResult => {
    if (result.status === 'authenticated') return { body: grantBody(result), cookies: [setRefreshCookie(result)] };
    const body: LoginResponse = {
      status: 'mfa_required',
      ticket: result.ticket,
      methods: result.methods,
      reason: result.reason,
      expiresAt: result.expiresAt,
    };
    return { body };
  };

  /** Access token required. `recent` also demands a recent interactive authentication. */
  const authenticated = (request: Request, recent = false) =>
    http.authenticate(request, {
      checkSession: true,
      ...(recent ? { maxAuthAgeSec: auth.config.sessions.recentAuthSec } : {}),
    });

  const routes: Route[] = [
    {
      method: 'POST',
      segments: ['login', 'password'],
      async handle({ body, ctx }) {
        return loginResult(await auth.login.withPassword({ identifier: str(body, 'identifier'), password: str(body, 'password') }, ctx));
      },
    },
    {
      method: 'POST',
      segments: ['login', 'passkey', 'options'],
      async handle({ body, ctx }) {
        const identifier = optionalStr(body, 'identifier');
        return { body: await auth.login.passkeyOptions(identifier === undefined ? {} : { identifier }, ctx) };
      },
    },
    {
      method: 'POST',
      segments: ['login', 'passkey'],
      async handle({ body, ctx }) {
        return loginResult(
          await auth.login.withPasskey(
            { challengeId: str(body, 'challengeId'), response: obj(body, 'response') as unknown as AuthenticationResponseJSON },
            ctx,
          ),
        );
      },
    },
    {
      method: 'POST',
      segments: ['mfa', 'verify'],
      async handle({ body, ctx }) {
        const result = await auth.mfa.verify({ ticket: str(body, 'ticket'), method: mfaMethod(body), code: str(body, 'code') }, ctx);
        return { body: grantBody(result), cookies: [setRefreshCookie(result)] };
      },
    },
    {
      method: 'POST',
      segments: ['refresh'],
      usesCookie: true,
      async handle({ request, ctx }) {
        const token = readCookie(request.headers.get('cookie'), cookieConfig.name);
        if (token === undefined) throw new SessionError('REFRESH_TOKEN_MISSING');
        const result = await auth.sessions.refresh(token, ctx);
        return { body: grantBody(result), cookies: [setRefreshCookie(result)] };
      },
    },
    {
      method: 'POST',
      segments: ['logout'],
      usesCookie: true,
      async handle({ request, ctx }) {
        await auth.sessions.logout(readCookie(request.headers.get('cookie'), cookieConfig.name), {}, ctx);
        return { status: 204, cookies: [clearedRefreshCookie(cookieConfig)] };
      },
    },
    {
      method: 'POST',
      segments: ['logout', 'all'],
      usesCookie: true,
      async handle({ request, ctx }) {
        await auth.sessions.logout(readCookie(request.headers.get('cookie'), cookieConfig.name), { all: true }, ctx);
        return { status: 204, cookies: [clearedRefreshCookie(cookieConfig)] };
      },
    },
    {
      method: 'GET',
      segments: ['session'],
      async handle({ request }) {
        const token = await authenticated(request);
        const [user, session, security] = await Promise.all([
          auth.users.get(token.subject.id),
          auth.sessions.get(token.context.sessionId),
          auth.mfa.status(token.subject.id),
        ]);
        if (!user || !session) throw new SessionError('SESSION_REVOKED');
        const body: SessionResponse = { user: toPublicUser(user), session: { ...session, current: true }, security };
        return { body };
      },
    },
    {
      method: 'GET',
      segments: ['sessions'],
      async handle({ request }) {
        const token = await authenticated(request);
        const body: SessionListResponse = { sessions: await auth.sessions.list(token.subject.id, token.context.sessionId) };
        return { body };
      },
    },
    {
      method: 'DELETE',
      segments: ['sessions', ':id'],
      async handle({ request, ctx, params }) {
        const token = await authenticated(request);
        const own = await auth.sessions.list(token.subject.id);
        // A session id that is not the caller's own is reported as not found, not as forbidden.
        if (!own.some((session) => session.id === params.id)) throw new RequestError('NOT_FOUND');
        await auth.sessions.revoke(params.id as string, 'logout', ctx);
        return params.id === token.context.sessionId
          ? { status: 204, cookies: [clearedRefreshCookie(cookieConfig)] }
          : { status: 204 };
      },
    },
    {
      method: 'POST',
      segments: ['reauthenticate'],
      async handle({ request, ctx, body }) {
        const token = await authenticated(request);
        let factor: ReauthFactor;
        if (body.method === 'password') factor = { method: 'password', password: str(body, 'password') };
        else if (body.method === 'passkey') {
          factor = {
            method: 'passkey',
            challengeId: str(body, 'challengeId'),
            response: obj(body, 'response') as unknown as AuthenticationResponseJSON,
          };
        } else factor = { method: mfaMethod(body), code: str(body, 'code') };
        return { body: grantBody(await auth.sessions.reauthenticate(token.context.sessionId, factor, ctx)) };
      },
    },
    {
      method: 'POST',
      segments: ['mfa', 'totp', 'enroll'],
      async handle({ request }) {
        const token = await authenticated(request, true);
        return { body: await auth.mfa.beginTotpEnrollment(token.subject.id) };
      },
    },
    {
      method: 'POST',
      segments: ['mfa', 'totp', 'confirm'],
      async handle({ request, ctx, body }) {
        const token = await authenticated(request, true);
        const result: RecoveryCodesResponse = await auth.mfa.confirmTotpEnrollment(
          token.subject.id,
          { enrollmentId: str(body, 'enrollmentId'), code: str(body, 'code') },
          ctx,
        );
        return { body: result };
      },
    },
    {
      method: 'DELETE',
      segments: ['mfa', 'totp'],
      async handle({ request, ctx }) {
        const token = await authenticated(request, true);
        await auth.mfa.removeTotp(token.subject.id, ctx);
        return { status: 204 };
      },
    },
    {
      method: 'POST',
      segments: ['mfa', 'recovery-codes'],
      async handle({ request, ctx }) {
        const token = await authenticated(request, true);
        const body: RecoveryCodesResponse = { recoveryCodes: await auth.mfa.regenerateRecoveryCodes(token.subject.id, ctx) };
        return { body };
      },
    },
    {
      method: 'POST',
      segments: ['passkeys', 'options'],
      async handle({ request }) {
        const token = await authenticated(request, true);
        return { body: await auth.passkeys.registrationOptions(token.subject.id) };
      },
    },
    {
      method: 'POST',
      segments: ['passkeys'],
      async handle({ request, ctx, body }) {
        const token = await authenticated(request, true);
        const name = optionalStr(body, 'name');
        const passkey = await auth.passkeys.register(
          token.subject.id,
          {
            challengeId: str(body, 'challengeId'),
            response: obj(body, 'response') as unknown as RegistrationResponseJSON,
            ...(name !== undefined ? { name } : {}),
          },
          ctx,
        );
        return { status: 201, body: passkey };
      },
    },
    {
      method: 'GET',
      segments: ['passkeys'],
      async handle({ request }) {
        const token = await authenticated(request);
        const body: PasskeyListResponse = { passkeys: await auth.passkeys.list(token.subject.id) };
        return { body };
      },
    },
    {
      method: 'DELETE',
      segments: ['passkeys', ':id'],
      async handle({ request, ctx, params }) {
        const token = await authenticated(request, true);
        await auth.passkeys.remove(token.subject.id, params.id as string, ctx);
        return { status: 204 };
      },
    },
    {
      method: 'POST',
      segments: ['password'],
      async handle({ request, ctx, body }) {
        const token = await authenticated(request);
        await auth.users.changePassword(
          token.subject.id,
          str(body, 'currentPassword'),
          str(body, 'newPassword'),
          { keepSessionId: token.context.sessionId },
          ctx,
        );
        return { status: 204 };
      },
    },
  ];

  const match = (method: string, segments: string[]): { route: Route; params: Record<string, string> } | 'wrong-method' | null => {
    let pathMatched = false;
    for (const route of routes) {
      if (route.segments.length !== segments.length) continue;
      const params: Record<string, string> = {};
      const fits = route.segments.every((expected, index) => {
        const actual = segments[index] as string;
        if (expected.startsWith(':')) {
          if (actual.length === 0 || actual.length > 256) return false;
          params[expected.slice(1)] = actual;
          return true;
        }
        return expected === actual;
      });
      if (!fits) continue;
      if (route.method === method) return { route, params };
      pathMatched = true;
    }
    return pathMatched ? 'wrong-method' : null;
  };

  const readBody = async (request: Request): Promise<Record<string, unknown>> => {
    const declared = Number(request.headers.get('content-length') ?? '0');
    if (declared > options.maxBodyBytes) throw new RequestError('REQUEST_INVALID', { details: { reason: 'body_too_large' } });
    const text = await request.text();
    if (text.length === 0) return {};
    if (text.length > options.maxBodyBytes) throw new RequestError('REQUEST_INVALID', { details: { reason: 'body_too_large' } });
    const contentType = request.headers.get('content-type') ?? '';
    // Requiring JSON also keeps cross-site HTML forms out: they cannot send this content type.
    if (!/^application\/json\b/i.test(contentType.trim())) {
      throw new RequestError('REQUEST_INVALID', { details: { reason: 'content_type_must_be_json' } });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new RequestError('REQUEST_INVALID', { details: { reason: 'body_is_not_json' } });
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new RequestError('REQUEST_INVALID', { details: { reason: 'body_must_be_an_object' } });
    }
    return parsed as Record<string, unknown>;
  };

  const withCors = (response: Response, origin: string | null): Response => {
    response.headers.append('vary', 'Origin');
    if (origin !== null && options.allowedOrigins.has(origin)) {
      response.headers.set('access-control-allow-origin', origin);
      response.headers.set('access-control-allow-credentials', 'true');
      response.headers.set('access-control-expose-headers', 'Retry-After, WWW-Authenticate');
    }
    return response;
  };

  return async (request: Request): Promise<Response> => {
    const origin = request.headers.get('origin');
    try {
      const url = new URL(request.url);
      const method = request.method.toUpperCase();

      if (url.pathname === JWKS_PATH) {
        if (method !== 'GET' && method !== 'HEAD') throw new RequestError('NOT_FOUND');
        const response = new Response(method === 'HEAD' ? null : JSON.stringify(await auth.keys.jwks()), {
          status: 200,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': `public, max-age=${auth.config.keys.jwksMaxAgeSec}`,
            'x-content-type-options': 'nosniff',
            // Public keys are for anyone, including resource servers on other origins.
            'access-control-allow-origin': '*',
          },
        });
        return response;
      }

      const prefix = `${options.basePath}/`;
      if (!url.pathname.startsWith(prefix)) throw new RequestError('NOT_FOUND');
      const segments = url.pathname.slice(prefix.length).split('/');

      if (method === 'OPTIONS') {
        if (origin === null || !options.allowedOrigins.has(origin)) throw new RequestError('ORIGIN_NOT_ALLOWED');
        return withCors(
          new Response(null, {
            status: 204,
            headers: {
              'access-control-allow-methods': 'GET, POST, DELETE',
              'access-control-allow-headers': 'Authorization, Content-Type, DPoP',
              'access-control-max-age': '600',
              'cache-control': 'no-store',
            },
          }),
          origin,
        );
      }

      const matched = match(method, segments);
      if (matched === null || matched === 'wrong-method') throw new RequestError('NOT_FOUND');
      const { route, params } = matched;

      // Cross-site request protection, on top of SameSite. A browser always sends Origin on a
      // cross-origin request and on every POST, so a missing Origin means a non-browser client,
      // which is only acceptable where the request is not authenticated by a cookie.
      if (origin !== null ? !options.allowedOrigins.has(origin) : route.usesCookie === true) {
        throw new RequestError('ORIGIN_NOT_ALLOWED');
      }

      const body = method === 'GET' ? {} : await readBody(request);
      let result: RouteResult;
      try {
        result = await route.handle({ request, ctx: http.requestContext(request), body, params });
      } catch (error) {
        // A refresh token the server will never accept again is removed from the browser.
        if (route.usesCookie && isAuthError(error) && error.kind === 'session') {
          const response = http.errorResponse(error, request);
          response.headers.append('set-cookie', clearedRefreshCookie(cookieConfig));
          return withCors(response, origin);
        }
        throw error;
      }

      const status = result.status ?? 200;
      const response = new Response(status === 204 ? null : JSON.stringify(result.body ?? {}), {
        status,
        headers: status === 204 ? { 'cache-control': 'no-store' } : JSON_HEADERS,
      });
      for (const cookie of result.cookies ?? []) response.headers.append('set-cookie', cookie);
      for (const [name, value] of Object.entries(result.headers ?? {})) response.headers.set(name, value);
      return withCors(response, origin);
    } catch (error) {
      return withCors(http.errorResponse(error, request), origin);
    }
  };
}
