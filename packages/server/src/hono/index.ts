/**
 * Hono adapter: mounts the auth endpoints and protects your own routes.
 *
 * Only types are imported from Hono, so this entry point adds no runtime dependency. It runs
 * wherever Hono does: Node, Bun, Deno and the edge runtimes Hono supports.
 *
 * Needs Hono 4.2 or later. Hono 5 calls error handlers differently and is not supported yet.
 */
import { TokenError, isAuthError } from '@koshi-repo/auth-core';
import type { Context, ErrorHandler, MiddlewareHandler } from 'hono';
import type { Auth } from '../auth.js';
import {
  JWKS_PATH,
  createAuthHandler,
  createHttpAuthContext,
  type AuthHandlerOptions,
  type RequireAuthOptions,
} from '../http/handler.js';
import type { VerifiedToken } from '../tokens/token-service.js';

/**
 * The context variable `requireAuth()` sets. Routes behind `requireAuth()` see it typed without
 * further work. Add it to your app's own environment type if you read it elsewhere:
 * `new Hono<AuthEnv & { Bindings: MyBindings }>()`.
 */
export type AuthEnv = { Variables: { auth: VerifiedToken } };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyContext = Context<any>;

export interface HonoAuthOptions extends Omit<AuthHandlerOptions, 'clientIp' | 'onError'> {
  /**
   * Returns the client's IP address, for risk scoring, throttling and the audit log. There is no
   * default, because where the address comes from depends on the runtime and on what stands in
   * front of it. On Bun without a proxy: `(c) => getConnInfo(c).remote.address`, with `getConnInfo`
   * from `@hono/bun`. Behind a proxy, read the header your proxy sets and strips from incoming
   * requests. If this function throws, the request fails with a 500 rather than carrying on
   * without an address.
   */
  clientIp?: (c: AnyContext) => string | undefined;
  /** Called with unexpected errors, before a generic 500 is sent. Log them here. */
  onError?: (error: unknown, c: AnyContext) => void;
}

export interface HonoAuth<P extends string = string> {
  /**
   * Serves the auth endpoints under `basePath` and the JWKS document, and passes every other
   * request on. Mount it with `app.use(routes)`, before your own routes.
   */
  routes: MiddlewareHandler;
  /** Verifies the access token and DPoP proof and sets `c.get('auth')`. Responds with the error otherwise. */
  requireAuth(options?: RequireAuthOptions): MiddlewareHandler<AuthEnv>;
  /**
   * Checks a permission through the configured roles and policies. Use it after `requireAuth()`.
   * Pass `resource` to load the object the policies should look at. Its context does not carry the
   * route's path type, so `c.req.param('id')` is typed `string | undefined` there.
   */
  requirePermission(permission: P, options?: { resource?: (c: Context<AuthEnv>) => unknown }): MiddlewareHandler<AuthEnv>;
  /**
   * For `app.onError(onError)`. Sends the library's JSON error format for `AuthError`s thrown in
   * your handlers. Any other error is reported to `options.onError` and answered with a generic
   * 500 in the same format. To keep your own handling for other errors, call this only when
   * `isAuthError(error)` is true.
   */
  onError: ErrorHandler;
}

/** The verified token of a request that passed `requireAuth()`. Throws `TOKEN_MISSING` if there is none. */
export function getAuth(c: AnyContext): VerifiedToken {
  const token = (c as Context<AuthEnv>).get('auth') as VerifiedToken | undefined;
  if (!token) throw new TokenError('TOKEN_MISSING');
  return token;
}

export function honoAuth<P extends string = string>(auth: Auth<P>, options: HonoAuthOptions): HonoAuth<P> {
  const basePath = options.basePath ?? '/auth';

  // The Fetch handler works on a Request. This map carries the Hono context alongside it.
  const contexts = new WeakMap<Request, AnyContext>();
  const handlerOptions: AuthHandlerOptions = {
    publicOrigin: options.publicOrigin,
    basePath,
    ...(options.maxBodyBytes !== undefined ? { maxBodyBytes: options.maxBodyBytes } : {}),
    ...(options.allowedOrigins !== undefined ? { allowedOrigins: options.allowedOrigins } : {}),
    clientIp: (request) => {
      const c = contexts.get(request);
      return c && options.clientIp ? options.clientIp(c) : undefined;
    },
    onError: (error, request) => {
      const c = contexts.get(request);
      if (c && options.onError) options.onError(error, c);
    },
  };
  const handler = createAuthHandler(auth as unknown as Auth, handlerOptions);
  const http = createHttpAuthContext(auth as unknown as Auth, handlerOptions);

  const requestOf = (c: AnyContext): Request => {
    contexts.set(c.req.raw, c);
    return c.req.raw;
  };

  const routes: MiddlewareHandler = async (c, next) => {
    const path = c.req.path;
    if (path !== JWKS_PATH && !path.startsWith(`${basePath}/`)) {
      await next();
      return;
    }
    let request = c.req.raw;
    if (request.bodyUsed) {
      // An earlier middleware read the body through Hono, which keeps a copy that can be read again.
      request = new Request(request.url, { method: request.method, headers: request.headers, body: await c.req.text() });
    }
    contexts.set(request, c);
    return handler(request);
  };

  const requireAuth = (requirements: RequireAuthOptions = {}): MiddlewareHandler<AuthEnv> => {
    return async (c, next) => {
      let verified: VerifiedToken;
      try {
        // Only the headers and the URL are read, so the body is still there for your handler.
        verified = await http.authenticate(requestOf(c), requirements);
      } catch (error) {
        if (!isAuthError(error)) throw error;
        return http.errorResponse(error, c.req.raw);
      }
      c.set('auth', verified);
      await next();
    };
  };

  const requirePermission = (
    permission: P,
    permissionOptions: { resource?: (c: Context<AuthEnv>) => unknown } = {},
  ): MiddlewareHandler<AuthEnv> => {
    return async (c, next) => {
      try {
        const token = getAuth(c);
        const resource = permissionOptions.resource ? await permissionOptions.resource(c) : undefined;
        await auth.authorize(token, permission, resource, { request: http.requestContext(requestOf(c)) });
      } catch (error) {
        if (!isAuthError(error)) throw error;
        return http.errorResponse(error, c.req.raw);
      }
      await next();
    };
  };

  const onError: ErrorHandler = (error, c) => http.errorResponse(error, requestOf(c));

  return { routes, requireAuth, requirePermission, onError };
}
