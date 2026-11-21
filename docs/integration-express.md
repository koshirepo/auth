# Integrating with Express

This guide takes an Express API and a React single-page app from nothing to password login, a second factor, passkeys, device-bound tokens and permission checks. Sections at the end cover the differences for [Next.js](#12-nextjs) and for [Hono on Bun](#13-hono-bun-and-other-fetch-based-servers).

The server code in sections 2 to 4 is exercised end to end by `packages/server/test/guide.test.ts`, with an in-process Postgres standing in for a real one.

## What you need

- Node 22.12 or later. Bun also works: see [section 13](#13-hono-bun-and-other-fetch-based-servers).
- Postgres.
- The web app and the API on the same registrable domain, for example `app.example.com` and `api.example.com`. The refresh cookie is `SameSite=Strict`, so two unrelated domains will not work.
- HTTPS in production. The refresh cookie is `Secure`. For local development see [section 11](#11-local-development).

The package scope `@acme` is a placeholder. Replace it with your own scope, and point that scope at your registry in `.npmrc`:

```ini
@acme:registry=https://npm.your-company.example/
```

## 1. Install

In the API:

```powershell
pnpm add @acme/auth-core @acme/auth-server argon2 pg express
```

In the web app:

```powershell
pnpm add @acme/auth-core @acme/auth-client @simplewebauthn/browser
```

`argon2` is a native module that ships prebuilt binaries. pnpm asks whether its install script may run. It does not need to: add this to `pnpm-workspace.yaml`.

```yaml
allowBuilds:
  argon2: false
```

## 2. Roles and policies

Put these in a module both the API and the web app can import, so the interface and the server apply the same rules.

```ts
// access.ts
import { defineRbac, definePolicy, deny } from '@acme/auth-core';

export const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
    admin: { grants: ['invoice:*'] },
  },
});

export interface Invoice {
  id: string;
  ownerId: string;
}

// Editors may change only their own invoices. Admins may change any.
const changeOwnInvoiceOnly = definePolicy('change-own-invoice-only', (subject, action, invoice: Invoice | undefined) => {
  if (action !== 'invoice:write' || !invoice) return;
  if (invoice.ownerId !== subject.id && !subject.roles.includes('admin')) {
    return deny('invoice belongs to another user');
  }
});

export const policies = [changeOwnInvoiceOnly];
```

A misspelt permission or role name in this file is a compile error.

## 3. Configure the server

Generate a data key once and store it in your secret manager:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

```ts
// auth.ts
import { createAuth } from '@acme/auth-server';
import { migrate, postgresAdapter } from '@acme/auth-server/adapters/postgres';
import { argon2id } from '@acme/auth-server/password/argon2';
import pg from 'pg';
import { policies, rbac } from './access.js';

export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

// Creates the "auth" schema and its tables. Safe to run on every start.
await migrate(pool);

export const auth = createAuth({
  issuer: 'https://api.example.com',
  audience: 'https://api.example.com',
  adapter: postgresAdapter({ db: pool }),
  dataKeys: [{ id: '2026-11', key: process.env.AUTH_DATA_KEY! }],

  password: { hasher: argon2id() },
  passkeys: { rpId: 'example.com', rpName: 'Example', origins: ['https://app.example.com'] },
  access: { rbac, policies },
});
```

That is a complete configuration. Everything else has a default, listed in the [configuration reference](configuration.md).

One default deserves a decision later. When a login looks risky, the library asks for a second factor. A user who has none cannot be asked, and by default is let through. Once every user has a second factor or a passkey, tighten that so such a login is refused instead:

```ts
  risk: { whenStepUpUnavailable: 'deny' },
```

Do not set it earlier. With the default weights it would refuse a user without a second factor after a single mistyped password on a new device.

## 4. Mount it in Express

```ts
// server.ts
import { expressAuth, getAuth } from '@acme/auth-server/express';
import express from 'express';
import { auth } from './auth.js';
import { invoices } from './invoices.js';

const APP_ORIGIN = 'https://app.example.com';

const app = express();

// Tell Express which proxies to trust, so req.ip is the real client address.
// The value depends on your infrastructure. 1 means "one proxy in front of me".
app.set('trust proxy', 1);

const { router, requireAuth, requirePermission, errorHandler } = expressAuth(auth, {
  publicOrigin: 'https://api.example.com',   // the origin browsers use, not an internal address
  allowedOrigins: [APP_ORIGIN],
  onError: (error) => console.error(error),  // unexpected failures: send these to your error tracker
});

// 1. The auth endpoints under /auth, and /.well-known/jwks.json. They handle their own CORS.
app.use(router);

// 2. CORS for your own routes. The browser sends two headers it needs permission for.
app.use((req, res, next) => {
  if (req.headers.origin === APP_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', APP_ORIGIN);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, DPoP');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Expose-Headers', 'WWW-Authenticate');
  }
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});
app.use(express.json());

// 3. Your routes.

// Signed in, with a permission a role grants.
app.get('/invoices/:id', requireAuth(), requirePermission('invoice:read'), async (req, res) => {
  res.json(await invoices.get(String(req.params.id)));
});

// A permission that depends on the object: load it and let the policies see it.
app.put(
  '/invoices/:id',
  requireAuth(),
  requirePermission('invoice:write', { resource: (req) => invoices.get(String(req.params.id)) }),
  async (req, res) => {
    res.json(await invoices.update(String(req.params.id), req.body));
  },
);

// A sensitive action: two factors, proven within the last five minutes.
app.delete(
  '/invoices/:id',
  requireAuth({ assurance: 'aal2', maxAuthAgeSec: 300 }),
  requirePermission('invoice:delete'),
  async (req, res) => {
    await invoices.remove(String(req.params.id));
    res.status(204).end();
  },
);

// The verified identity is on the request.
app.get('/me', requireAuth(), (req, res) => {
  const { subject, context } = getAuth(req);
  res.json({ id: subject.id, roles: subject.roles, assurance: context.assurance });
});

// 4. Last: turns AuthErrors thrown in your handlers into the JSON error format.
app.use(errorHandler);

app.listen(3000);
```

What the middleware does:

| Middleware | Passes when | Otherwise |
|---|---|---|
| `requireAuth()` | The access token is valid and the request carries a proof signed by the device the token is bound to | 401 with a token or DPoP error code |
| `requireAuth({ assurance: 'aal2' })` | The session also has two factors, or a passkey with user verification | 403 `STEP_UP_REQUIRED` |
| `requireAuth({ maxAuthAgeSec })` | The user also authenticated interactively within that time | 403 `STEP_UP_REQUIRED` |
| `requireAuth({ checkSession: true })` | The session also has not been revoked. Costs one database read. | 401 `SESSION_REVOKED` |
| `requirePermission(p)` | A role grants `p` or a policy allows it, and no policy denies | 403 `FORBIDDEN` with the reason, and an `access.denied` audit event |

Without `checkSession`, an access token keeps working for up to 15 minutes after its session is revoked. Use it on the routes where that is too long.

## 5. Create users

The library has no sign-up endpoint. Create users from your own sign-up flow, an admin tool or a seed script:

```ts
import { isAuthError } from '@acme/auth-core';
import { auth } from './auth.js';

try {
  const user = await auth.users.create({
    identifier: 'ada@example.com',
    password: 'correct horse battery staple',
    roles: ['editor'],
  });
  console.log('created', user.id);
} catch (error) {
  if (isAuthError(error) && error.code === 'IDENTIFIER_TAKEN') console.log('already exists');
  else if (isAuthError(error) && error.code === 'PASSWORD_POLICY_VIOLATION') console.log('rejected:', error.details);
  else throw error;
}
```

Email verification and password reset are yours to build as well. `auth.users.setPassword(userId, newPassword)` is the primitive for a reset: it sets the password and ends every session of that user.

## 6. The browser client

```ts
// auth-client.ts
import { createAuthClient } from '@acme/auth-client';
import { policies, rbac } from './access';

export const authClient = createAuthClient({
  baseUrl: 'https://api.example.com/auth',
  access: { rbac, policies },
});
```

Creating the client starts one request that restores the session from the refresh cookie, so a reload keeps the user signed in. Until it answers, the state is `loading`.

```tsx
// main.tsx
import { AuthProvider } from '@acme/auth-client/react';
import { authClient } from './auth-client';

root.render(
  <AuthProvider client={authClient}>
    <App />
  </AuthProvider>,
);
```

### Sign-in form

`useLogin` tracks the request and its error for you. The same component handles the second factor, because the state tells you when one is needed.

```tsx
import { useLogin } from '@acme/auth-client/react';
import { useState } from 'react';

export function SignIn() {
  const { state, loginWithPassword, loginWithPasskey, submitMfa, cancelMfa, pending, error } = useLogin();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');

  if (state.status === 'mfa_required') {
    return (
      <form onSubmit={(event) => { event.preventDefault(); void submitMfa({ method: 'totp', code }); }}>
        <label>
          Code from your authenticator app
          <input value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" />
        </label>
        <button disabled={pending}>Verify</button>
        <button type="button" onClick={cancelMfa}>Start again</button>
        {error && <p role="alert">{error.message}</p>}
      </form>
    );
  }

  return (
    <form onSubmit={(event) => { event.preventDefault(); void loginWithPassword({ identifier, password }); }}>
      <label>
        Email
        <input value={identifier} onChange={(event) => setIdentifier(event.target.value)} autoComplete="username" />
      </label>
      <label>
        Password
        <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" />
      </label>
      <button disabled={pending}>Sign in</button>
      <button type="button" disabled={pending} onClick={() => void loginWithPasskey()}>Sign in with a passkey</button>
      {error && <p role="alert">{error.message}</p>}
    </form>
  );
}
```

`error.message` is always safe to show: it is the fixed public text for the error code. Branch on `error.code` when you want your own wording, for example `RATE_LIMITED` with `error.details.retryAfterSec`.

For a recovery code, call `submitMfa({ method: 'recovery_code', code })`. `state.methods` lists what the user can use.

### Calling your API

Use the client's `fetch`. It attaches the access token and the proof, refreshes the token shortly before it expires, and on a 401 refreshes once and retries once.

```ts
const response = await authClient.fetch('https://api.example.com/invoices/42');
if (response.ok) show(await response.json());
```

If you use another HTTP library, get the token with `await authClient.getAccessToken()`. Be aware that a device-bound token also needs a `DPoP` proof per request, which `authClient.fetch` creates for you.

### Showing and hiding interface

```tsx
import { AuthGuard, useAuth, useCan } from '@acme/auth-client/react';

function InvoiceActions({ invoice }: { invoice: Invoice }) {
  const canEdit = useCan('invoice:write', invoice);
  return canEdit ? <button>Edit</button> : null;
}

function InvoicesPage() {
  return (
    <AuthGuard
      require={{ permissions: ['invoice:read'] }}
      pending={<p>Loading</p>}
      fallback={(result) => (result.action === 'login' ? <Navigate to="/login" /> : <p>{result.reason}</p>)}
    >
      <Invoices />
    </AuthGuard>
  );
}

function AccountMenu() {
  const { user, logout } = useAuth();
  return user ? <button onClick={() => void logout()}>Sign out {user.identifier}</button> : null;
}
```

The guard result's `action` is `login`, `mfa`, `step_up` or `forbidden`, and the guard itself navigates nowhere. `<Navigate>` above is your router's component.

These checks decide what to show. They are not security: a user controls their own browser. The middleware in section 4 is what protects the data.

Without React, use the client directly: `authClient.subscribe(listener)`, `authClient.getState()`, `authClient.check(requirement)` and `authClient.can(action, resource)`.

## 7. Second factor

Enrolment is two calls, with the user scanning a QR code in between:

```ts
const { enrollmentId, secret, otpauthUri } = await authClient.mfa.beginTotpEnrollment();
// Render otpauthUri as a QR code with a library of your choice, and show `secret` for manual entry.

const { recoveryCodes } = await authClient.mfa.confirmTotpEnrollment({ enrollmentId, code });
// Show the recovery codes now. They cannot be retrieved again.
```

From then on, password logins for that user return `mfa_required`. Other calls: `authClient.mfa.status()`, `regenerateRecoveryCodes()` and `removeTotp()`.

## 8. Passkeys

```ts
await authClient.passkeys.register({ name: 'Work laptop' });   // the browser shows its passkey dialog
const list = await authClient.passkeys.list();
await authClient.passkeys.remove(list[0].id);

await authClient.loginWithPasskey();                            // sign in, no identifier needed
```

A passkey that checked a PIN or biometric counts as two factors, so the user is not asked for a TOTP code afterwards.

Passkeys are bound to `rpId` permanently. Choose the registrable domain, such as `example.com`, so they keep working if you move the app between subdomains.

## 9. Step-up

Two situations ask a signed-in user to prove a factor again:

- your route requires it, through `requireAuth({ assurance: 'aal2' })` or `maxAuthAgeSec`;
- the user manages their second factor or passkeys more than ten minutes after signing in.

Both answer 403 with `STEP_UP_REQUIRED`. Handle it once, wherever you make requests:

```ts
async function withStepUp(request: () => Promise<Response>): Promise<Response> {
  const response = await request();
  if (response.status !== 403) return response;
  const body = await response.clone().json().catch(() => null);
  if (body?.error?.code !== 'STEP_UP_REQUIRED') return response;

  const code = await askUserForCode();                         // your dialog
  await authClient.reauthenticate({ method: 'totp', code });   // or { method: 'password', password }, or { method: 'passkey' }
  return request();
}

await withStepUp(() => authClient.fetch('https://api.example.com/invoices/42', { method: 'DELETE' }));
```

Calls on `authClient.mfa` and `authClient.passkeys` reject with an error whose `code` is `STEP_UP_REQUIRED` in the same situation.

In the interface, `authClient.check({ assurance: 'aal2' })` returns `{ status: 'deny', action: 'step_up' }` before the user even tries.

## 10. Operations

**Scheduled cleanup.** Run this hourly, from a cron job or a timer in one instance:

```ts
await auth.maintenance.purgeExpired();
```

**More than one instance.** The Postgres adapter already shares everything that needs sharing: rate limits, MFA tickets, the proof replay cache and the signing keys. The memory adapter does not, and is for tests.

**Audit log.** By default events are written to the `audit_events` table. To also stream them:

```ts
import { consoleSink, storeSink } from '@acme/auth-server';

audit: { sinks: [storeSink(adapter.audit), consoleSink()] },
```

Events never contain passwords, tokens, codes or keys.

**Other services.** A service that only needs to check tokens does not need the database:

```ts
import { createAccessTokenVerifier } from '@acme/auth-server/verifier';

const verify = createAccessTokenVerifier({
  issuer: 'https://api.example.com',
  audience: 'https://api.example.com',
  jwksUri: 'https://api.example.com/.well-known/jwks.json',
});

const { subject } = await verify(token, { method: req.method, url: publicUrlOf(req), dpopProof: req.headers.dpop });
```

`url` must be the URL the browser used. Behind a proxy, rebuild it from the public origin and the request path.

**Signing keys** rotate on their own every 90 days. Nothing to schedule.

The [threat model](threat-model.md) ends with a deployment checklist.

## 11. Local development

`localhost` with two ports is the same site, so the cookie rules are satisfied:

```ts
// API on http://localhost:3000, app on http://localhost:5173
passkeys: { rpId: 'localhost', rpName: 'Example (dev)', origins: ['http://localhost:5173'] },

expressAuth(auth, { publicOrigin: 'http://localhost:3000', allowedOrigins: ['http://localhost:5173'] });

createAuthClient({ baseUrl: 'http://localhost:3000/auth' });
```

The refresh cookie is always `Secure`. Chrome and Firefox treat `http://localhost` as secure and accept it. Safari does not, so for Safari run both servers over HTTPS with a locally trusted certificate.

For tests, use the memory adapter, small Argon2 parameters and a fake clock:

```ts
import { memoryAdapter } from '@acme/auth-server/adapters/memory';
import { argon2id } from '@acme/auth-server/password/argon2';
import { createFakeClock } from '@acme/auth-server/testing';

const clock = createFakeClock();
const auth = createAuth({
  // ...
  clock,
  adapter: memoryAdapter({ clock }),
  password: { hasher: argon2id({ memoryKiB: 64, iterations: 1, unsafeAllowWeakParameters: true }) },
});

clock.advanceSec(900);   // the access token has now expired
```

## 12. Next.js

This section follows from the design and has not been run against a Next.js app in this repository.

The handler takes a `Request` and returns a `Response`, which is what route handlers use:

```ts
// lib/auth-http.ts
import { createAuthHandler, createHttpAuthContext } from '@acme/auth-server/http';
import { auth } from './auth';

const options = { publicOrigin: 'https://example.com' };   // one origin: allowedOrigins defaults to it
export const handler = createAuthHandler(auth, options);
export const http = createHttpAuthContext(auth, options);
```

```ts
// app/auth/[...path]/route.ts
import { handler } from '@/lib/auth-http';

export const runtime = 'nodejs';   // Argon2 is a native module
export { handler as GET, handler as POST, handler as DELETE, handler as OPTIONS };
```

```ts
// app/.well-known/jwks.json/route.ts
import { handler } from '@/lib/auth-http';

export const runtime = 'nodejs';
export { handler as GET };
```

Protect your own route handlers with the same checks the Express middleware uses:

```ts
// app/api/invoices/[id]/route.ts
import { auth } from '@/lib/auth';
import { http } from '@/lib/auth-http';

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const token = await http.authenticate(request);
    await auth.authorize(token, 'invoice:read');
    return Response.json(await invoices.get((await params).id));
  } catch (error) {
    return http.errorResponse(error, request);
  }
}
```

On the client, create the client in a module marked `'use client'`, with `baseUrl: '/auth'`, and wrap the app in `AuthProvider` from a client component.

What is different from a single-page app:

- **Server components cannot make authenticated requests on the user's behalf.** The access token exists only in the browser's memory, and the proof that must accompany it can only be signed by the key in the browser. Fetch protected data from client components with `authClient.fetch`, or render it after the client has loaded.
- **Do not treat the presence of the refresh cookie as authentication** in middleware or server components. It shows that a session may exist, nothing more. It is acceptable for deciding which shell to render first. With the default `SameSite=Strict` it is also absent on navigations that arrive from other sites, so use `sessions.cookie.sameSite: 'lax'` if you rely on it for that.
- **The first render is always signed out or loading.** The session is restored by a request the client makes after it starts.

## 13. Hono, Bun and other Fetch-based servers

The Hono adapter mirrors the Express one. It needs Hono 4.2 or later and is covered by the automated tests. The server below was also run as written on Bun 1.4 with Hono 4.13. Hono 5 is not supported yet: its release candidate calls error handlers differently.

Besides the packages from section 1, without `express`, install Hono and its Bun adapter:

```powershell
bun add hono @hono/bun
```

```ts
// server.ts
import { honoAuth } from '@acme/auth-server/hono';
import { getConnInfo } from '@hono/bun';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { auth } from './auth';
import { invoices } from './invoices';

const APP_ORIGIN = 'https://app.example.com';

const { routes, requireAuth, requirePermission, onError } = honoAuth(auth, {
  publicOrigin: 'https://api.example.com',   // the origin browsers use, not an internal address
  allowedOrigins: [APP_ORIGIN],
  // The address of the connection. Behind a proxy, read the header your proxy sets instead.
  clientIp: (c) => getConnInfo(c).remote.address,
  onError: (error) => console.error(error),  // unexpected failures: send these to your error tracker
});

const app = new Hono();

// 1. The auth endpoints under /auth, and /.well-known/jwks.json. They handle their own CORS.
app.use(routes);

// 2. CORS for your own routes. Register it before them: Hono does not run middleware added after a route.
app.use(
  '/api/*',
  cors({ origin: [APP_ORIGIN], allowHeaders: ['Authorization', 'Content-Type', 'DPoP'], exposeHeaders: ['WWW-Authenticate'] }),
);

// 3. Your routes.
app.get('/api/invoices/:id', requireAuth(), requirePermission('invoice:read'), async (c) => {
  return c.json(await invoices.get(c.req.param('id')));
});

// A permission that depends on the object: load it and let the policies see it. The loader's
// context does not carry the route's path type, hence the "!" on the parameter.
app.put(
  '/api/invoices/:id',
  requireAuth(),
  requirePermission('invoice:write', { resource: (c) => invoices.get(c.req.param('id')!) }),
  async (c) => c.json(await invoices.update(c.req.param('id'), await c.req.json())),
);

app.delete(
  '/api/invoices/:id',
  requireAuth({ assurance: 'aal2', maxAuthAgeSec: 300 }),
  requirePermission('invoice:delete'),
  async (c) => {
    await invoices.remove(c.req.param('id'));
    return c.body(null, 204);
  },
);

// The verified identity is on the context, typed.
app.get('/api/me', requireAuth(), (c) => {
  const { subject, context } = c.get('auth');
  return c.json({ id: subject.id, roles: subject.roles, assurance: context.assurance });
});

// 4. AuthErrors thrown in your handlers get the JSON error format.
app.onError(onError);

export default { port: 3000, fetch: app.fetch };
```

`auth.ts` is the one from section 3, and the middleware behaves as the table in section 4 describes. What differs from Express:

- **`clientIp` has no default.** Where the address comes from depends on the runtime. On Bun, `getConnInfo` reads it from the connection. It comes from `@hono/bun`, which needs Hono 4.13.9 or later. From Hono 4.4 until then, `hono/bun` exports the same function. It throws when the app is not being served by Bun, as in a test that calls `app.request()`, and a `clientIp` that throws fails the request with a 500. In such a test, pass a stand-in for Bun's server as the third argument: `app.request(path, init, { requestIP: () => null })`.
- **Route parameters in a `resource` loader.** Its context does not carry the route's path type, as in any Hono middleware created outside the route, so `c.req.param('id')` is `string | undefined` there. In the route's own handler it is typed as usual.
- **`onError` answers every error.** `AuthError`s get their own status and code. Anything else is reported to the `onError` option and answered with a generic 500. To keep your own handling for other errors, branch first: `app.onError((error, c) => (isAuthError(error) ? onError(error, c) : yours(error, c)))`.
- **Body parsing.** `routes` copes with an earlier middleware that read the body through Hono, such as `c.req.json()`. It cannot recover a body that was consumed from `c.req.raw` directly.

**Password hashing on Bun.** `argon2id()` works under Bun as it is. If you would rather not ship a native addon, Bun's built-in `Bun.password` fits the `PasswordHasher` interface:

```ts
import type { PasswordHasher } from '@acme/auth-server';

export const bunArgon2id: PasswordHasher = {
  hash: (password) => Bun.password.hash(password, { algorithm: 'argon2id', memoryCost: 19_456, timeCost: 2 }),
  verify: async (hash, password) => {
    try {
      return await Bun.password.verify(password, hash);
    } catch {
      return false;
    }
  },
  needsRehash: (hash) => {
    const match = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(hash);
    return !match || Number(match[1]) < 19 || Number(match[2]) < 19_456 || Number(match[3]) < 2;
  },
};
```

Not tried on Bun: the Postgres adapter. It only needs `query(text, params)` returning `{ rows }`, which a `pg` Pool provides.

On the client nothing changes. A React app using the hooks from section 6 was built with Vite 8 and run in a browser against a Bun server like the one above, from the dev server and from a production build. When the Vite dev server and the API run on different ports, list the dev server's origin in `allowedOrigins`, in the `cors()` options and in `passkeys.origins`, as in section 11.

**Other servers.** Anything built on `Request` and `Response` can use the pieces the adapters are made of, as the Next.js section does: route the auth paths to `createAuthHandler(auth, options)`, and call `createHttpAuthContext(auth, options).authenticate(request)` in front of your own routes.

## 14. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| 403 `ORIGIN_NOT_ALLOWED` | The app's origin is not in `allowedOrigins`, or a non-browser client called `/refresh` or `/logout` without an `Origin` header | Add the exact origin, with scheme and port and without a trailing slash |
| 401 `DPOP_PROOF_INVALID` on every request | `publicOrigin` is not the origin the browser uses, or a proxy rewrites the path | Set `publicOrigin` to the external origin. Make sure the path the server sees equals the path the browser requested. |
| 401 `DPOP_PROOF_INVALID` once, then success | The device's clock is wrong. The server sends its time and the client corrects itself. | Nothing |
| The refresh cookie is never stored | The page is not HTTPS, the two origins are on different sites, or it is Safari on `http://localhost` | See sections "What you need" and 11 |
| Signed out when two tabs are open | The tab lock is disabled or unsupported, so two tabs presented the same refresh token | Leave `locks` at its default. Every current browser has the Web Locks API. |
| Signed out after a flaky connection | A refresh response was lost and the retry counted as reuse of the old token | By design. See the threat model, risk 11. |
| `RISK_DENIED` for real users | The risk score reached `risk.denyAt`, or `whenStepUpUnavailable` is `'deny'` and the user has no second factor | Look at the `risk.evaluated` audit event for that login. It lists the signals that fired and their scores. |
| 403 `STEP_UP_REQUIRED` when managing MFA or passkeys | The last interactive sign-in is more than ten minutes old | `authClient.reauthenticate(...)`, then retry |
| 429 `RATE_LIMITED` | Too many wrong passwords or codes | Wait `details.retryAfterSec`. The `Retry-After` header carries the same number. |
| CORS error calling your own routes | Your routes do not allow the `Authorization` and `DPoP` headers. On Hono, the same symptom appears when `cors()` is registered after the routes, because Hono does not run middleware added after a route. | See the CORS middleware in section 4, or section 13 for Hono |
| `ExperimentalWarning` mentioning ML-DSA in the server log | Node prints it when `@simplewebauthn/server` checks for post-quantum signature support | Harmless |
| pnpm reports "Ignored build scripts: argon2" | pnpm wants a decision about the install script | Set `allowBuilds: argon2: false`. The prebuilt binary is used. |
