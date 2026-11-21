/**
 * Express adapter: mounts the auth endpoints and protects your own routes.
 *
 * Works with Express 5, and with Express 4 as long as rejected promises from your own async
 * handlers are forwarded to `next`.
 */
import { RequestError, TokenError, isAuthError } from '@koshirepo/auth-core';
import type { ErrorRequestHandler, Request as ExpressRequest, RequestHandler, Response as ExpressResponse } from 'express';
import type { Auth } from '../auth.js';
import {
  JWKS_PATH,
  createAuthHandler,
  createHttpAuthContext,
  type AuthHandlerOptions,
  type RequireAuthOptions,
} from '../http/handler.js';
import type { VerifiedToken } from '../tokens/token-service.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Set by `requireAuth()`. */
      auth?: VerifiedToken;
    }
  }
}

export interface ExpressAuthOptions extends Omit<AuthHandlerOptions, 'clientIp' | 'onError'> {
  /**
   * Returns the client's IP address. Default: `req.ip`, which follows Express's `trust proxy`
   * setting. Configure `trust proxy` to match your deployment, or addresses can be forged.
   */
  clientIp?: (req: ExpressRequest) => string | undefined;
  /** Called with unexpected errors raised inside the auth endpoints, before a generic 500 is sent. */
  onError?: (error: unknown, req: ExpressRequest) => void;
}

export interface ExpressAuth<P extends string = string> {
  /** Serves the auth endpoints under `basePath` and the JWKS document. Mount it with `app.use(router)`. */
  router: RequestHandler;
  /** Verifies the access token and DPoP proof, and sets `req.auth`. Responds with the error otherwise. */
  requireAuth(options?: RequireAuthOptions): RequestHandler;
  /**
   * Checks a permission through the configured roles and policies. Use it after `requireAuth()`.
   * Pass `resource` to load the object the policies should look at.
   */
  requirePermission(permission: P, options?: { resource?: (req: ExpressRequest) => unknown }): RequestHandler;
  /** Sends the library's JSON error format for `AuthError`s thrown in your handlers. Mount it last. */
  errorHandler: ErrorRequestHandler;
}

/** The verified token on a request that passed `requireAuth()`. Throws `TOKEN_MISSING` if there is none. */
export function getAuth(req: ExpressRequest): VerifiedToken {
  if (!req.auth) throw new TokenError('TOKEN_MISSING');
  return req.auth;
}

async function readBody(req: ExpressRequest, limit: number): Promise<string | undefined> {
  // A body parser may already have consumed the stream.
  const parsed: unknown = (req as { body?: unknown }).body;
  if (parsed !== undefined) {
    if (typeof parsed === 'string') return parsed;
    if (Buffer.isBuffer(parsed)) return parsed.toString('utf8');
    return JSON.stringify(parsed);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer);
    size += buffer.length;
    if (size > limit) throw new RequestError('REQUEST_INVALID', { details: { reason: 'body_too_large' } });
    chunks.push(buffer);
  }
  return chunks.length === 0 ? undefined : Buffer.concat(chunks).toString('utf8');
}

function toHeaders(req: ExpressRequest): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) for (const item of value) headers.append(name, item);
    else if (value !== undefined) headers.set(name, value);
  }
  return headers;
}

async function send(res: ExpressResponse, response: Response): Promise<void> {
  res.status(response.status);
  response.headers.forEach((value, name) => {
    if (name !== 'set-cookie') res.setHeader(name, value);
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) res.append('Set-Cookie', cookies);
  const body = Buffer.from(await response.arrayBuffer());
  if (body.length > 0) res.end(body);
  else res.end();
}

export function expressAuth<P extends string = string>(auth: Auth<P>, options: ExpressAuthOptions): ExpressAuth<P> {
  const basePath = options.basePath ?? '/auth';
  const maxBodyBytes = options.maxBodyBytes ?? 65_536;
  const clientIp = options.clientIp ?? ((req: ExpressRequest) => req.ip);

  // The Fetch handler receives a Fetch Request. These maps carry the Express request alongside it.
  const expressRequests = new WeakMap<Request, ExpressRequest>();
  const handlerOptions: AuthHandlerOptions = {
    publicOrigin: options.publicOrigin,
    basePath,
    maxBodyBytes,
    ...(options.allowedOrigins !== undefined ? { allowedOrigins: options.allowedOrigins } : {}),
    clientIp: (request) => {
      const req = expressRequests.get(request);
      return req ? clientIp(req) : undefined;
    },
    onError: (error, request) => {
      const req = expressRequests.get(request);
      if (req && options.onError) options.onError(error, req);
    },
  };
  const handler = createAuthHandler(auth as unknown as Auth, handlerOptions);
  const http = createHttpAuthContext(auth as unknown as Auth, handlerOptions);

  /** A Fetch view of an Express request, without its body. Enough for token and proof checks. */
  const toFetchRequest = (req: ExpressRequest, body?: string): Request => {
    const hasBody = body !== undefined && req.method !== 'GET' && req.method !== 'HEAD';
    const request = new Request(`${options.publicOrigin}${req.originalUrl}`, {
      method: req.method,
      headers: toHeaders(req),
      ...(hasBody ? { body } : {}),
    });
    expressRequests.set(request, req);
    return request;
  };

  const sendError = async (error: unknown, req: ExpressRequest, res: ExpressResponse): Promise<void> => {
    await send(res, http.errorResponse(error, toFetchRequest(req)));
  };

  const router: RequestHandler = (req, res, next) => {
    const path = req.originalUrl.split('?')[0] ?? '';
    if (path !== JWKS_PATH && !path.startsWith(`${basePath}/`)) {
      next();
      return;
    }
    (async () => {
      let body: string | undefined;
      try {
        body = req.method === 'GET' || req.method === 'HEAD' ? undefined : await readBody(req, maxBodyBytes);
      } catch (error) {
        await sendError(error, req, res);
        return;
      }
      await send(res, await handler(toFetchRequest(req, body)));
    })().catch(next);
  };

  const requireAuth = (requirements: RequireAuthOptions = {}): RequestHandler => {
    return (req, res, next) => {
      http
        .authenticate(toFetchRequest(req), requirements)
        .then((verified) => {
          req.auth = verified;
          next();
        })
        .catch((error: unknown) => (isAuthError(error) ? sendError(error, req, res) : Promise.reject(error)))
        .catch(next);
    };
  };

  const requirePermission = (
    permission: P,
    permissionOptions: { resource?: (req: ExpressRequest) => unknown } = {},
  ): RequestHandler => {
    return (req, res, next) => {
      (async () => {
        const token = getAuth(req);
        const resource = permissionOptions.resource ? await permissionOptions.resource(req) : undefined;
        await auth.authorize(token, permission, resource, { request: http.requestContext(toFetchRequest(req)) });
        next();
      })()
        .catch((error: unknown) => (isAuthError(error) ? sendError(error, req, res) : Promise.reject(error)))
        .catch(next);
    };
  };

  const errorHandler: ErrorRequestHandler = (error, req, res, next) => {
    if (!isAuthError(error) || res.headersSent) {
      next(error);
      return;
    }
    sendError(error, req, res).catch(next);
  };

  return { router, requireAuth, requirePermission, errorHandler };
}
