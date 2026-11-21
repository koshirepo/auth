import { defineRbac, definePolicy, deny } from '@koshirepo/auth-core';
import { createAuth, memorySink, type AuthConfig } from '@koshirepo/auth-server';
import { memoryAdapter } from '@koshirepo/auth-server/adapters/memory';
import { createAuthHandler, createHttpAuthContext } from '@koshirepo/auth-server/http';
import { argon2id } from '@koshirepo/auth-server/password/argon2';
import { createHmac } from 'node:crypto';
import { createFakeClock, type FakeClock } from '@koshirepo/auth-server/testing';
import {
  createAuthClient,
  memoryKeyStore,
  type AuthClient,
  type AuthClientOptions,
  type ChannelLike,
  type ChannelMessage,
  type DpopKeyStore,
  type LockManagerLike,
} from '../src/index.js';

export const API_ORIGIN = 'https://api.example.com';
export const APP_ORIGIN = 'https://app.example.com';
export const BASE_URL = `${API_ORIGIN}/auth`;
export const PASSWORD = 'correct horse battery staple';

export const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
  },
});

export const ownInvoiceOnly = definePolicy('own-invoice-only', (subject, action, resource: { ownerId: string } | undefined) => {
  if (action !== 'invoice:write' || !resource) return;
  if (resource.ownerId !== subject.id) return deny('invoice belongs to another user');
});

export interface TestServer {
  clock: FakeClock;
  auth: ReturnType<typeof createAuth>;
  sink: ReturnType<typeof memorySink>;
  /** Handles every request the browser sends to the API origin. */
  handle(request: Request): Promise<Response>;
  /** Makes the next `count` requests to a path fail with this status, before they reach the server. */
  failNext(path: string, status: number, count?: number): void;
  /** Requests received, as `METHOD /path`. */
  log: string[];
}

/** A real server: the library's handler plus two application routes protected by it. */
export function createTestServer(config: Partial<AuthConfig> = {}): TestServer {
  const clock = createFakeClock();
  const sink = memorySink();
  const auth = createAuth({
    issuer: API_ORIGIN,
    audience: API_ORIGIN,
    adapter: memoryAdapter({ clock }),
    dataKeys: [{ id: 'k1', key: crypto.getRandomValues(new Uint8Array(32)) }],
    clock,
    password: { hasher: argon2id({ memoryKiB: 64, iterations: 1, unsafeAllowWeakParameters: true }) },
    passkeys: { rpId: 'example.com', rpName: 'Example', origins: [APP_ORIGIN] },
    audit: { sinks: [sink] },
    access: { rbac, policies: [ownInvoiceOnly] },
    ...config,
  });
  const options = { publicOrigin: API_ORIGIN, allowedOrigins: [APP_ORIGIN], clientIp: () => '203.0.113.10' };
  const authHandler = createAuthHandler(auth, options);
  const http = createHttpAuthContext(auth, options);
  const failures = new Map<string, { status: number; remaining: number }>();
  const log: string[] = [];

  return {
    clock,
    auth,
    sink,
    log,
    failNext(path, status, count = 1) {
      failures.set(path, { status, remaining: count });
    },
    async handle(request) {
      const url = new URL(request.url);
      log.push(`${request.method} ${url.pathname}`);
      const failure = failures.get(url.pathname);
      if (failure && failure.remaining > 0) {
        failure.remaining--;
        const code = failure.status === 401 ? 'TOKEN_EXPIRED' : 'INTERNAL_ERROR';
        return new Response(JSON.stringify({ error: { code, message: 'injected failure' } }), {
          status: failure.status,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.pathname.startsWith('/auth/') || url.pathname === '/.well-known/jwks.json') return authHandler(request);

      // Application routes.
      try {
        const token = await http.authenticate(request);
        if (url.pathname === '/api/me' && request.method === 'GET') {
          return Response.json({ id: token.subject.id, roles: token.subject.roles, query: url.search });
        }
        if (url.pathname === '/api/echo' && request.method === 'POST') {
          return Response.json({ id: token.subject.id, received: await request.json() });
        }
        return new Response(null, { status: 404 });
      } catch (error) {
        return http.errorResponse(error, request);
      }
    },
  };
}

export interface SentRequest {
  method: string;
  path: string;
  headers: Headers;
  credentials: RequestCredentials;
  body: string | undefined;
}

/**
 * One browser profile: the things tabs of the same site share. A cookie jar, the device key, the
 * lock that serialises refreshes and the channel tabs talk over.
 */
export class BrowserProfile {
  readonly cookies = new Map<string, string>();
  readonly sent: SentRequest[] = [];
  readonly keyStore: DpopKeyStore = memoryKeyStore();
  readonly broadcasts: ChannelMessage[] = [];
  /** When true, `fetch` throws as it does when the network is down. */
  offline = false;
  /**
   * Awaited after a request has picked up its cookies and before it reaches the server. Tests use
   * it to hold requests back, to line up a race deterministically.
   */
  beforeSend: ((request: SentRequest) => Promise<void>) | null = null;
  private readonly tabs = new Set<(message: ChannelMessage) => void>();
  private readonly lockTails = new Map<string, Promise<void>>();

  constructor(readonly server: TestServer) {}

  /** What `fetch` does in a browser: attaches the Origin and, when asked, the cookies. */
  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const body = request.body ? await request.text() : undefined;
    const sent: SentRequest = {
      method: request.method,
      path: url.pathname,
      headers: new Headers(request.headers),
      credentials: request.credentials,
      body,
    };
    this.sent.push(sent);
    if (this.offline) throw new TypeError('Failed to fetch');

    const headers = new Headers(request.headers);
    headers.set('origin', APP_ORIGIN);
    const sendsCookies = request.credentials === 'include';
    if (sendsCookies && this.cookies.size > 0) {
      headers.set('cookie', [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    if (this.beforeSend) await this.beforeSend(sent);
    const response = await this.server.handle(new Request(request.url, { method: request.method, headers, ...(body !== undefined ? { body } : {}) }));
    if (sendsCookies) {
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(';')[0] as string;
        const separator = pair.indexOf('=');
        const name = pair.slice(0, separator);
        const value = pair.slice(separator + 1);
        if (value === '' || /;\s*Max-Age=0\b/i.test(cookie)) this.cookies.delete(name);
        else this.cookies.set(name, value);
      }
    }
    return response;
  };

  /**
   * Locks shared by every tab of this profile, like `navigator.locks`. Each name is its own lock,
   * so holding one never blocks a request for another.
   */
  readonly locks: LockManagerLike = {
    request: <T>(name: string, callback: () => Promise<T>): Promise<T> => {
      const result = (this.lockTails.get(name) ?? Promise.resolve()).then(callback);
      this.lockTails.set(
        name,
        result.then(
          () => undefined,
          () => undefined,
        ),
      );
      return result;
    },
  };

  /** A channel endpoint for one tab. Messages reach the other tabs, not the sender. */
  channel(): ChannelLike {
    let listener: ((message: ChannelMessage) => void) | null = null;
    const deliver = (message: ChannelMessage) => listener?.(message);
    this.tabs.add(deliver);
    return {
      post: (message) => {
        this.broadcasts.push(message);
        for (const tab of this.tabs) if (tab !== deliver) queueMicrotask(() => tab(message));
      },
      subscribe: (next) => {
        listener = next;
      },
      close: () => {
        this.tabs.delete(deliver);
      },
    };
  }

  /** Opens a tab: a client that shares this profile's cookies, key, lock and channel. */
  openTab(options: Partial<AuthClientOptions> = {}): AuthClient {
    return createAuthClient({
      baseUrl: BASE_URL,
      fetch: this.fetch,
      dpop: { keyStore: this.keyStore },
      locks: this.locks,
      channel: this.channel(),
      now: this.server.clock,
      access: { rbac, policies: [ownInvoiceOnly] },
      ...options,
    });
  }

  requestsTo(path: string): SentRequest[] {
    return this.sent.filter((request) => request.path === path);
  }
}

export async function createUser(server: TestServer, identifier = 'ada@example.com', roles: string[] = ['editor']) {
  return server.auth.users.create({ identifier, password: PASSWORD, roles });
}

/** A server with one user and a browser profile pointed at it. */
export async function setup(config: Partial<AuthConfig> = {}) {
  const server = createTestServer(config);
  const user = await createUser(server);
  const profile = new BrowserProfile(server);
  return { server, user, profile };
}

/** A tab that is signed in with the password. */
export async function signedInTab(profile: BrowserProfile, options: Partial<AuthClientOptions> = {}): Promise<AuthClient> {
  const tab = profile.openTab(options);
  await tab.ready();
  const state = await tab.loginWithPassword({ identifier: 'ada@example.com', password: PASSWORD });
  if (state.status !== 'authenticated') throw new Error(`Expected a completed login, got ${state.status}`);
  return tab;
}

/**
 * The TOTP code an authenticator app would show right now.
 *
 * This is deliberately a separate implementation from the server's, built on Node's HMAC, so the
 * client tests also check the server's TOTP against an independent one.
 */
export function totpCode(clock: FakeClock, base32Secret: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32Secret.toUpperCase()) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const secret = Buffer.from((bits.match(/.{8}/g) ?? []).map((byte) => Number.parseInt(byte, 2)));

  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(clock() / 1000 / 30)));
  const digest = createHmac('sha1', secret).update(counter).digest();
  const offset = (digest[digest.length - 1] as number) & 0x0f;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

/** Lets queued microtasks and promise chains run, for example a broadcast reaching another tab. */
export async function settle(rounds = 20): Promise<void> {
  for (let index = 0; index < rounds; index++) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
}
