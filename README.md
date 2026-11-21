# Auth library

A TypeScript authentication library in three packages: shared types and access control, a server, and a headless browser client.

| Package | Contents | Runtime dependencies |
|---|---|---|
| [`@acme/auth-core`](packages/core) | Types, typed errors with stable codes, RBAC and ABAC policy evaluation, audit event types, HTTP wire types | None |
| [`@acme/auth-server`](packages/server) | Signing keys and JWKS, access tokens, sessions and refresh rotation, password login, TOTP and recovery codes, passkeys, device binding, risk scoring, audit log, persistence adapters, HTTP handler, Express adapter | `jose`, `@simplewebauthn/server` |
| [`@acme/auth-client`](packages/client) | Session state, automatic refresh, device key and proofs, MFA and passkey flows, route guards, React hooks. No styling. | `jose` |

`@acme` is a placeholder scope. Replace it across the repository with your own before publishing.

## What it does

- **Login** with a password (Argon2id) or a passkey (WebAuthn, through `@simplewebauthn`).
- **Access tokens**: JWTs signed with EdDSA or ES256, 15-minute lifetime, verified against an algorithm allowlist. Keys are published as JWKS and rotate without downtime.
- **Refresh tokens**: opaque, rotated on every use. Reusing an old one revokes the whole session. The client refreshes automatically, shares one refresh between concurrent callers and takes turns across tabs.
- **Storage**: the refresh token lives in an `HttpOnly; Secure; SameSite=Strict` cookie. The access token lives in memory only.
- **Access control**: roles mapped to permissions, plus policy functions of subject, action, resource and context that return allow or deny with a reason.
- **MFA**: TOTP (RFC 6238) with enrolment, recovery codes, replay protection and rate limiting.
- **Device binding**: DPoP (RFC 9449). Tokens and sessions are bound to a key that cannot be exported from the browser.
- **Risk-based authentication**: scores each login on new device, new network, location change and failed attempts, then allows, requires MFA or denies.
- **Audit log**: a typed event for every auth action, written through pluggable sinks, never containing secrets or tokens.
- **Persistence**: adapter interfaces, with an in-memory adapter and a Postgres adapter.

## Quick start

Server:

```ts
import { createAuth } from '@acme/auth-server';
import { migrate, postgresAdapter } from '@acme/auth-server/adapters/postgres';
import { expressAuth } from '@acme/auth-server/express';
import { argon2id } from '@acme/auth-server/password/argon2';

await migrate(pool);

const auth = createAuth({
  issuer: 'https://api.example.com',
  audience: 'https://api.example.com',
  adapter: postgresAdapter({ db: pool }),
  dataKeys: [{ id: '2026-11', key: process.env.AUTH_DATA_KEY }],
  password: { hasher: argon2id() },
});

const { router, requireAuth, errorHandler } = expressAuth(auth, {
  publicOrigin: 'https://api.example.com',
  allowedOrigins: ['https://app.example.com'],
});

app.use(router);
app.get('/me', requireAuth(), (req, res) => res.json(req.auth));
app.use(errorHandler);
```

Browser:

```ts
import { createAuthClient } from '@acme/auth-client';

const authClient = createAuthClient({ baseUrl: 'https://api.example.com/auth' });

await authClient.loginWithPassword({ identifier: 'ada@example.com', password });
const response = await authClient.fetch('https://api.example.com/me');
```

The [Express integration guide](docs/integration-express.md) builds this out step by step, including the React hooks, MFA, passkeys and permission checks.

## Documentation

| Document | Contents |
|---|---|
| [Integration guide for Express](docs/integration-express.md) | From nothing to a working app, with a Next.js section and troubleshooting |
| [API reference](docs/api-reference.md) | Every export, error code, audit event and HTTP endpoint |
| [Configuration reference](docs/configuration.md) | Every option and default, plus key management and operations |
| [Threat model](docs/threat-model.md) | What is defended and how, the risks that remain, and a deployment checklist |
| [Architecture proposal](docs/architecture-proposal.md) | The design as approved |

## Development

Requires Node 22.12 or later and pnpm.

```powershell
pnpm install
```

```powershell
pnpm check
```

`pnpm check` runs `pnpm build`, `pnpm typecheck` and `pnpm test` in that order. Type-checking a package needs the packages it depends on to be built first, which is why the build comes first. The tests themselves run against source and need no build.

The Postgres adapter is tested in PGlite, which is Postgres compiled to WebAssembly and running in the test process. To run the same adapter contract against a real server as well, set `DATABASE_URL`:

```powershell
$env:DATABASE_URL = 'postgres://user:password@localhost:5432/auth_test'; pnpm test
```

Each test creates and drops its own schema in that database.

## Status

Verified in this repository:

- All three packages build and type-check under TypeScript 7 in strict mode.
- The test suite passes. It covers every module, including the security cases: expired tokens, wrong algorithm, `alg: none`, HMAC signed with the public key, refresh reuse, concurrent refresh, TOTP replay, DPoP replay and key mismatch, passkey origin and counter checks, and a test that drives every flow and asserts that no secret reaches the audit log.
- The Postgres adapter's SQL runs in a real Postgres engine (PGlite), including a full login, refresh and logout through Express.
- The Express adapter is tested against a real Express 5 server over HTTP.
- Passkeys are tested with a software authenticator against the real `@simplewebauthn/server` verification.
- The browser client is tested against the real server handler, in process.

Not verified:

- The Postgres adapter against a real server with several connections racing. PGlite uses one connection, so the atomic statements are tested for their logic, not under true concurrency. Run the suite with `DATABASE_URL` set to check this.
- The client in a real browser. IndexedDB, the Web Locks API and the passkey dialog are simulated in the tests.
- Any edge runtime, and Next.js.
- Publishing to a registry.

## Publishing

The packages are versioned together with [Changesets](https://github.com/changesets/changesets).

1. Replace the `@acme` scope and point it at your registry in `.npmrc`.
2. Record a change: `pnpm changeset`.
3. Apply versions: `pnpm changeset version`.
4. Publish: `pnpm release`, which runs the full check first.

## Differences from the proposal

The implementation follows the approved proposal, with these changes. Each came out of a test or a gap found while building.

1. **Passkey sign-in ignores a submitted identifier by default.** Returning an account's credential ids would have revealed which accounts exist, which the proposal ruled out. `passkeys.identifierHints` turns the old behaviour on, and `passkeys.residentKey` now defaults to `required` so that every passkey can sign in without a hint.
2. **`SigningKeyStore.insertPending` also takes the key the caller believes is active.** Without it, two instances starting on an empty store could leave a redundant second key.
3. **More error codes** than the proposal's table: `IDENTIFIER_TAKEN`, `PASSWORD_POLICY_VIOLATION`, `USER_NOT_FOUND`, `NOT_FOUND`, `INTERNAL_ERROR` and `NETWORK_ERROR`.
4. **A wrong device clock is corrected automatically.** When the server rejects a proof for its timestamp it includes its own time, and the client adjusts and retries once.
5. **Additions to the server API:** `auth.authorize` (an audited permission check), `sessions.logout`, `sessions.get`, `mfa.status`, `users.get`, `auth.config`, `auth.clock`, the `tokens.allowedAlgorithms` option, and `createHttpAuthContext` for frameworks other than Express. `maintenance.purgeExpired` returns counts.
6. **Express:** `req.auth` is typed as optional and `getAuth(req)` reads it. `errorHandler` is new. `requirePermission` takes an optional resource loader.
7. **Client:** `reauthenticate({ method: 'passkey' })` runs the browser ceremony itself. `cancelMfa`, `changePassword`, `mfa.status` and `dispose` are new. `fetch` retries after any 401, not only after token errors.
8. **`risk.whenStepUpUnavailable` defaults to `'allow'`**, where the proposal said `'deny'`. Under `'deny'`, a user without a second factor was refused after a single mistyped password on a new device. Changed after review of the finished build.
