import { createDpopProof, type DpopTestKey } from './helpers.js';
import { API_ORIGIN, APP_ORIGIN } from './env.js';

export interface BrowserRequestOptions {
  body?: unknown;
  /** Access token to send in the Authorization header. */
  token?: string;
  /** Send a DPoP proof. Default true. */
  proof?: boolean;
  /** Value of the Origin header. Pass null to send none. Default: the app's origin. */
  origin?: string | null;
  headers?: Record<string, string>;
  /** Send this raw body instead of JSON-encoding `body`. */
  rawBody?: string;
  scheme?: 'DPoP' | 'Bearer';
}

export interface TestResponse {
  status: number;
  headers: Headers;
  /** Parsed JSON body, or undefined when there is none. */
  json: any; // eslint-disable-line @typescript-eslint/no-explicit-any
  text: string;
  setCookies: string[];
}

/**
 * A minimal stand-in for a browser: it keeps cookies between requests, sends an Origin header and
 * signs a DPoP proof for every request. `send` is whatever delivers a Request to the server:
 * the Fetch handler directly, or real HTTP to an Express app.
 */
export class TestBrowser {
  readonly cookies = new Map<string, string>();
  /** Every response body seen, for checks that nothing sensitive was ever sent. */
  readonly bodies: string[] = [];

  constructor(
    private readonly send: (request: Request) => Promise<Response>,
    readonly key: DpopTestKey,
    private readonly clock: () => number,
    private readonly origin: string = APP_ORIGIN,
  ) {}

  async request(method: string, path: string, options: BrowserRequestOptions = {}): Promise<TestResponse> {
    const url = `${API_ORIGIN}${path}`;
    const headers = new Headers({ 'user-agent': 'test-browser', ...options.headers });
    const origin = options.origin === undefined ? this.origin : options.origin;
    if (origin !== null) headers.set('origin', origin);
    if (this.cookies.size > 0) {
      headers.set('cookie', [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    if (options.token !== undefined) headers.set('authorization', `${options.scheme ?? 'DPoP'} ${options.token}`);
    if (options.proof !== false) {
      headers.set(
        'dpop',
        await createDpopProof(this.key, {
          method,
          url: url.split('?')[0] as string,
          nowMs: this.clock(),
          ...(options.token !== undefined ? { accessToken: options.token } : {}),
        }),
      );
    }
    let body: string | undefined;
    if (options.rawBody !== undefined) body = options.rawBody;
    else if (options.body !== undefined) {
      body = JSON.stringify(options.body);
      if (!headers.has('content-type')) headers.set('content-type', 'application/json');
    }

    const response = await this.send(new Request(url, { method, headers, ...(body !== undefined ? { body } : {}) }));
    const setCookies = response.headers.getSetCookie();
    for (const cookie of setCookies) {
      const [pair] = cookie.split(';');
      const separator = (pair as string).indexOf('=');
      const name = (pair as string).slice(0, separator);
      const value = (pair as string).slice(separator + 1);
      if (/;\s*Max-Age=0\b/i.test(cookie) || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await response.text();
    this.bodies.push(text);
    let json: unknown;
    try {
      json = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, json, text, setCookies };
  }

  get(path: string, options: BrowserRequestOptions = {}) {
    return this.request('GET', path, options);
  }

  post(path: string, body?: unknown, options: BrowserRequestOptions = {}) {
    return this.request('POST', path, body === undefined ? options : { ...options, body });
  }

  delete(path: string, options: BrowserRequestOptions = {}) {
    return this.request('DELETE', path, options);
  }
}
