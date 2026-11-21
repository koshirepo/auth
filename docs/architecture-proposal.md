# Auth library: architecture and public API proposal

**Status:** approved on 2026-11-21 and implemented. This document is the design as it was proposed and is kept for reference. The [README](../README.md#differences-from-the-proposal) lists where the implementation differs. For current behaviour, read the [API reference](api-reference.md), the [configuration reference](configuration.md) and the [threat model](threat-model.md).

Section 1 lists the choices that were open. Section 2 lists decisions made where the spec was silent. Everything after that describes the design with the recommended choices applied.

Library versions were checked against the npm registry on 2026-11-21: `jose` 6.2, `@simplewebauthn/server` 14.1, `@simplewebauthn/browser` 14.0, `argon2` 0.45, TypeScript 7.0, Vitest 5.1.

## 1. Choices to confirm

| # | Open choice | Recommendation | Reason | Cost of choosing otherwise |
|---|---|---|---|---|
| 1 | Server runtime | **Node 22.12 or later**, built on Web-standard APIs | Node 20 reached end of life on 2026-04-30. Current `@simplewebauthn/server` (14) and Vitest (5) require Node 22. Using `Request`, `Response` and WebCrypto throughout keeps token verification usable on edge runtimes. | A Node 20 floor means pinning `@simplewebauthn/server` to the 13 line and an older Vitest. A full edge target has no native Argon2id (section 5.5). |
| 2 | Client | **Both**: a framework-agnostic client, with React hooks as a subpath export | The hooks are a thin wrapper over the agnostic client, so offering both costs little and the logic is testable without React. | Either half can be dropped without touching the other. |
| 3 | Distribution | **Private npm registry** | The packages are built to be publishable. The same packages also work as `workspace:*` dependencies inside a larger monorepo. | Configuration only. |
| 4 | Primary login | **Password with Argon2id**, plus passkey sign-in as an alternative | Requirement 7 brings in WebAuthn regardless, so passkey sign-in is a small addition. Magic links need email delivery and are left out of v1. | Passkey-only removes the password module. Magic links add a mailer interface. |
| 5 | JWT algorithm | **EdDSA (Ed25519)** | Deterministic signatures, small keys, fast verification. ES256 remains a config option for environments that require NIST curves. | One config value. |
| 6 | Device binding | **DPoP (RFC 9449)** | DPoP is the standard form of a device-bound key registered at login: the browser's key is registered by its first proof, and every later refresh and API call must be signed by it. Resource servers can check it without calling the auth server. | A custom scheme means designing and reviewing our own proof format. |
| 7 | Persistence | **Postgres with plain SQL** | Refresh rotation, TOTP replay protection and recovery-code use each depend on an atomic compare-and-set, which is simplest to write and review as a single SQL statement. The library stays independent of your Prisma version and schema. | A Prisma adapter can implement the same interfaces later. |
| 8 | Integration guide | **Express**, with a short Next.js section | A single-page app calling an API matches the token model directly. The handlers take a `Request` and return a `Response`, so they mount in Next.js route handlers in a few lines, but server-rendered pages cannot hold an in-memory access token or sign DPoP proofs, which needs separate guidance. | Swap which framework gets the full guide. |

I also need two values from you: the npm scope (written as `@koshirepo` below) and the registry URL.

## 2. Decisions the spec did not cover

1. **Account flows stop at primitives.** Sign-up screens, email verification and password reset are not in the requirements, and all of them need email delivery. v1 provides `users.create`, `users.setPassword` and `users.changePassword` only.
2. **ABAC policies may abstain.** The spec says a policy returns allow or deny with a reason. Combining several policies needs a third outcome, "does not apply". The combined decision is always allow or deny with a reason (section 4.3).
3. **Seven stores, not four.** Besides users, sessions, credentials and audit events, the features need stores for signing keys, known devices (for risk scoring) and short-lived state such as challenges, rate-limit counters and replay caches (section 5.11).
4. **Refresh reuse detection has no grace period.** Any second use of a refresh token revokes the session, including a retry after a lost response. The client prevents the usual cause, parallel refreshes, within a tab and across tabs.
5. **Access tokens are not checked against the session store by default.** Revoking a session stops refresh at once, but an access token already issued works until it expires, at most 15 minutes later. Verification can opt in to a session check per route.
6. **A failing audit sink does not block sign-in by default.** The failure is reported through a hook. `audit.failClosed` reverses this for deployments where an unlogged action must not happen.
7. **TOTP arithmetic is implemented in the library.** The HMAC comes from WebCrypto. The RFC 4226 truncation and RFC 6238 time-step logic are about twenty lines, tested against the RFC vectors. The alternative is a dependency such as `otpauth`.
8. **The app and the auth endpoints must be same-site.** The refresh cookie is `SameSite=Strict`, so both must share a registrable domain, for example `app.example.com` and `api.example.com`.
9. **MFA enrolment is not forced at login.** A user without a second factor can sign in, unless the risk score calls for step-up, in which case the login is denied (configurable).

## 3. Architecture

### 3.1 Packages

```text
packages/
  core/     @koshirepo/auth-core     types, errors, RBAC and ABAC, audit event types, HTTP wire types
  server/   @koshirepo/auth-server   keys, tokens, sessions, login, MFA, passkeys, DPoP, risk, audit, adapters, HTTP
  client/   @koshirepo/auth-client   session state, automatic refresh, DPoP signing, MFA and passkey flows, guards
docs/       threat model, API reference, configuration reference, integration guide
```

- `core` has no dependencies and uses no Node or DOM globals, so it runs on the server, in the browser and on edge runtimes.
- `server` and `client` each depend on `core` and never on each other. They meet only at the HTTP wire types defined in `core`.
- `server` is one directory per concern, each with its own unit tests: `keys`, `tokens`, `dpop`, `sessions`, `password`, `mfa`, `passkeys`, `risk`, `ratelimit`, `audit`, `adapters`, `http`, `express`, `verifier`.

| Package | Dependencies | Optional peer dependencies |
|---|---|---|
| `core` | none | none |
| `server` | `jose`, `@simplewebauthn/server` | `argon2` (password hashing), `pg` (Postgres adapter), `express` (Express adapter) |
| `client` | `jose` (signs DPoP proofs) | `@simplewebauthn/browser` (passkeys), `react` 18 or later (hooks) |

| Import path | Contents |
|---|---|
| `@koshirepo/auth-core` | Everything in section 4 |
| `@koshirepo/auth-server` | `createAuth`, config and service types, adapter interfaces, audit sinks, risk signals |
| `@koshirepo/auth-server/verifier` | `createAccessTokenVerifier`: stateless verification for resource servers, needing only a JWKS URL |
| `@koshirepo/auth-server/http` | `createAuthHandler`: a `(Request) => Promise<Response>` function |
| `@koshirepo/auth-server/express` | `expressAuth`: router and middleware |
| `@koshirepo/auth-server/adapters/memory` | `memoryAdapter()` |
| `@koshirepo/auth-server/adapters/postgres` | `postgresAdapter()` and SQL migrations |
| `@koshirepo/auth-server/password/argon2` | `argon2id()` hasher |
| `@koshirepo/auth-server/testing` | Adapter contract test suite and fake clock, for anyone writing an adapter |
| `@koshirepo/auth-client` | `createAuthClient`, state and guard types |
| `@koshirepo/auth-client/react` | `AuthProvider`, hooks, `AuthGuard` |

Tooling: pnpm workspaces, TypeScript 7 in strict mode, Vitest 5, Changesets for versioning. Output is ESM only, with type declarations. Node 22.12 and later can `require()` ESM, so CommonJS consumers still work, and a single module format avoids loading two copies of the error classes.

### 3.2 Requirement coverage

| # | Requirement | Where it lives | Section |
|---|---|---|---|
| 1 | Primary login | `server/password`, `server/passkeys` | 5.5, 5.7 |
| 2 | Access JWT, algorithm allowlist, JWKS rotation | `server/tokens`, `server/keys`, `server/verifier` | 5.3 |
| 3 | Refresh rotation, reuse detection, client deduplication | `server/sessions`, `client` | 5.4, 6 |
| 4 | Refresh token in a cookie, access token in memory | `server/http`, `client` | 5.4, 6 |
| 5 | RBAC and ABAC | `core` | 4.3 |
| 6 | TOTP, recovery codes, rate limiting | `server/mfa`, `server/ratelimit` | 5.6 |
| 7 | Passkeys | `server/passkeys`, `client` | 5.7 |
| 8 | Device binding | `server/dpop`, `client` | 5.8 |
| 9 | Risk-based authentication | `server/risk` | 5.9 |
| 10 | Audit log | `core` (event types), `server/audit` | 4.4, 5.10 |
| 11 | Persistence adapters | `server/adapters` | 5.11 |
| 12 | Typed errors with stable codes | `core` | 4.2 |

## 4. `core`

### 4.1 Identity types

```ts
interface Subject {
  id: string;
  roles: readonly string[];
  attributes?: Readonly<Record<string, unknown>>;
}

/** How the subject authenticated. Carried in the access token and passed to policies. */
interface AuthContext {
  sessionId: string;
  methods: readonly ('pwd' | 'otp' | 'recovery' | 'passkey')[];
  assurance: 'aal1' | 'aal2';   // aal2: two factors, or one passkey with user verification
  authenticatedAt: number;      // epoch seconds of the last interactive authentication
  deviceBound: boolean;
}
```

Access token contents:

| Claim | Value |
|---|---|
| Header | `alg`, `kid`, `typ: "at+jwt"` |
| `iss`, `aud`, `sub`, `iat`, `exp`, `jti` | Standard. `exp` is `iat` plus 900 seconds. |
| `sid` | Session id |
| `roles` | Role names |
| `amr`, `acr`, `auth_time` | Methods used, assurance level, time of last interactive authentication |
| `cnf.jkt` | Thumbprint of the device's DPoP key |

Permissions are not embedded in the token. The verifier resolves them from `roles` through the role map, so a change to the map applies at once, and a change to a user's roles applies at their next refresh.

### 4.2 Errors

```ts
class AuthError extends Error {
  readonly code: ErrorCode;       // stable: never renamed or reused
  readonly status: number;        // suggested HTTP status
  readonly details?: Readonly<Record<string, JsonValue>>;   // safe to send to clients
  toJSON(): ErrorBody;            // { code, message, details? } with no stack and no cause
}

function isAuthError(value: unknown): value is AuthError;   // brand check, not instanceof
function errorFromBody(body: ErrorBody): AuthError;          // used by the client
```

| Class | Codes | HTTP |
|---|---|---|
| `AuthenticationError` | `INVALID_CREDENTIALS`, `ACCOUNT_DISABLED` | 401, 403 |
| `TokenError` | `TOKEN_MISSING`, `TOKEN_MALFORMED`, `TOKEN_EXPIRED`, `TOKEN_SIGNATURE_INVALID`, `TOKEN_ALGORITHM_NOT_ALLOWED`, `TOKEN_KEY_UNKNOWN`, `TOKEN_CLAIMS_INVALID` | 401 |
| `SessionError` | `REFRESH_TOKEN_MISSING`, `REFRESH_TOKEN_INVALID`, `REFRESH_TOKEN_EXPIRED`, `REFRESH_TOKEN_REUSED`, `SESSION_REVOKED`, `SESSION_EXPIRED` | 401 |
| `MfaError` | `MFA_TICKET_INVALID`, `MFA_CODE_INVALID`, `MFA_NOT_ENROLLED`, `MFA_ALREADY_ENROLLED`, `STEP_UP_REQUIRED` | 401, 403, 409 |
| `PasskeyError` | `PASSKEY_CHALLENGE_INVALID`, `PASSKEY_VERIFICATION_FAILED`, `PASSKEY_NOT_FOUND` | 400, 401, 404 |
| `DpopError` | `DPOP_PROOF_REQUIRED`, `DPOP_PROOF_INVALID`, `DPOP_PROOF_REPLAYED`, `DPOP_KEY_MISMATCH` | 401 |
| `RiskError` | `RISK_DENIED` | 403 |
| `RateLimitError` | `RATE_LIMITED`, with `details.retryAfterSec` | 429 |
| `AuthorizationError` | `FORBIDDEN`, with `details.reason` and `details.policy` | 403 |
| `RequestError` | `REQUEST_INVALID`, `ORIGIN_NOT_ALLOWED` | 400, 403 |
| `ConfigurationError` | `CONFIGURATION_INVALID` | Thrown at startup, never sent |

Two rules shape the list:

- A code tells the caller what it can do next, not what an attacker would like to learn. A wrong, expired or replayed TOTP code all return `MFA_CODE_INVALID`. An unknown account and a wrong password both return `INVALID_CREDENTIALS`. The audit log records the precise reason.
- An outcome that is not a failure is not an error. "MFA required" is a result state of login, not an exception.

### 4.3 Access control

**RBAC.** Permissions are declared once, and roles grant them.

```ts
const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete', 'user:manage'],
  roles: {
    viewer:  { grants: ['invoice:read'] },
    editor:  { inherits: ['viewer'], grants: ['invoice:write'] },
    support: { grants: [] },
    admin:   { grants: ['invoice:*', 'user:manage'] },
  },
});

rbac.permissionsFor(['editor']);            // Set { 'invoice:read', 'invoice:write' }
rbac.grants(['editor'], 'invoice:write');   // true
```

- Role and permission names are inferred as literal types, so a misspelt name does not compile.
- A grant may end in `*`. Wildcards expand against the declared list, so a grant can never cover a permission nobody declared.
- Inheritance cycles and unknown parents throw when the map is defined.

**ABAC.** A policy is a function of subject, action, resource and context.

```ts
const changeOwnInvoiceOnly = definePolicy('change-own-invoice-only', (subject, action, resource: Invoice) => {
  if (action !== 'invoice:write' && action !== 'invoice:delete') return;   // does not apply
  if (resource.ownerId !== subject.id && !subject.roles.includes('admin')) {
    return deny('invoice belongs to another user');
  }
});

const supportReadsDuringIncident = definePolicy('support-incident-read', (subject, action, _resource, ctx) => {
  if (action === 'invoice:read' && subject.roles.includes('support') && ctx.incidentOpen) {
    return allow('support may read invoices during an open incident');
  }
});
```

```ts
type PolicyFn<S, A, R, C> =
  (subject: S, action: A, resource: R, context: C) => { effect: 'allow' | 'deny'; reason: string } | undefined;

interface Decision { effect: 'allow' | 'deny'; reason: string; policy: string }

interface PolicyContext { auth: AuthContext; now: number; ip?: string; [key: string]: unknown }
```

**Combining.**

```ts
const authorizer = createAuthorizer({ rbac, policies: [changeOwnInvoiceOnly, supportReadsDuringIncident] });

authorizer.evaluate(subject, 'invoice:write', invoice, ctx);
// { effect: 'deny', reason: 'invoice belongs to another user', policy: 'change-own-invoice-only' }

authorizer.can(subject, 'invoice:read', invoice, ctx);       // boolean
authorizer.assert(subject, 'invoice:write', invoice, ctx);   // throws AuthorizationError (FORBIDDEN)
```

1. If any policy denies, the decision is deny. The first denying policy in list order supplies the reason.
2. Otherwise, if a role grants the permission or any policy allows, the decision is allow.
3. Otherwise the decision is deny, with the reason "no role or policy allows" followed by the action.

Policies are synchronous and have no side effects. Load whatever data they need first and pass it in as the resource or context. Because of that, the same authorizer runs in the browser for interface gating.

### 4.4 Audit event types

```ts
interface AuditEventBase {
  id: string;
  at: string;                         // ISO 8601
  outcome: 'success' | 'failure';
  userId?: string;
  sessionId?: string;
  ip?: string;
  userAgent?: string;
  reason?: string;                    // an ErrorCode or a fixed enum value, never text taken from a request
}

type AuditEvent = AuditEventBase & (
  | { type: 'login.succeeded'; data: { method: 'pwd' | 'passkey'; riskScore: number } }
  | { type: 'login.failed';    data: { method: 'pwd' | 'passkey'; identifierHash: string } }
  | { type: 'risk.evaluated';  data: { score: number; decision: 'allow' | 'step_up' | 'deny'; signals: { name: string; score: number }[] } }
  | { type: 'session.refresh_reuse_detected'; data: { refreshTokenId: string } }
  // one member per event below
);
```

| Area | Events |
|---|---|
| Login | `login.succeeded`, `login.failed`, `risk.evaluated` |
| MFA | `mfa.challenged`, `mfa.verified`, `mfa.failed`, `mfa.totp.enrolled`, `mfa.totp.removed`, `mfa.recovery_codes.generated`, `mfa.recovery_code.used` |
| Passkeys | `passkey.registered`, `passkey.removed` |
| Sessions | `session.created`, `session.refreshed`, `session.reauthenticated`, `session.revoked`, `session.refresh_reuse_detected` |
| Tokens and device binding | `token.rejected`, `dpop.rejected` |
| Accounts | `user.created`, `user.disabled`, `password.changed` |
| Keys | `key.created`, `key.activated`, `key.retired` |
| Protection | `rate_limit.exceeded`, `access.denied` |

`token.rejected` is emitted for anomalies such as a disallowed algorithm, a bad signature or an unknown key. Routine expiry is not logged.

Secrets are kept out of events in three ways:

1. **By type.** No event has a field that can hold a credential. Fields are ids, enum values, numbers and one keyed hash. A failed login records `identifierHash` instead of the identifier, because people type passwords into the username box.
2. **By construction.** The server builds every event through one typed function. Sinks receive finished events and nothing else.
3. **By test.** One test runs every flow end to end, collects every secret issued or submitted (passwords, access and refresh tokens, TOTP seeds and codes, recovery codes, MFA tickets, DPoP proofs, WebAuthn challenges) and asserts that none appears in any serialised event.

### 4.5 Wire protocol

Request and response types for every HTTP endpoint live in `core`, so the server handler and the client compile against the same definitions. Errors are always `{ "error": { "code": "...", "message": "...", "details": {} } }`.

## 5. `server`

### 5.1 Configuration

```ts
import { createAuth } from '@koshirepo/auth-server';
import { postgresAdapter } from '@koshirepo/auth-server/adapters/postgres';
import { argon2id } from '@koshirepo/auth-server/password/argon2';

export const auth = createAuth({
  issuer: 'https://api.example.com',
  audience: 'https://api.example.com',
  adapter: postgresAdapter({ db: pool }),
  dataKeys: [{ id: '2026-11', key: process.env.AUTH_DATA_KEY }],   // AES-256. First entry encrypts, all entries decrypt.

  tokens:   { algorithm: 'EdDSA', accessTtlSec: 900 },
  sessions: { ttlSec: 30 * 86_400, idleTtlSec: 7 * 86_400 },
  password: { hasher: argon2id() },
  mfa:      { totp: { issuer: 'Example' } },
  passkeys: { rpId: 'example.com', rpName: 'Example', origins: ['https://app.example.com'] },
  dpop:     { mode: 'required' },
  risk:     { stepUpAt: 40, denyAt: 90 },
  access:   { rbac, policies },
});
```

`issuer`, `audience`, `adapter` and `dataKeys` are required. `password` and `passkeys` are each enabled by being present, and at least one must be. Everything else has a default. `createAuth` validates the whole object and throws `ConfigurationError` at startup.

| Setting | Default |
|---|---|
| `tokens.algorithm` | `'EdDSA'` |
| `tokens.accessTtlSec` | 900 |
| `tokens.clockToleranceSec` | 5 |
| `keys.rotateEveryDays` | 90 |
| `sessions.ttlSec`, `sessions.idleTtlSec` | 30 days, 7 days |
| `sessions.cookie` | Name `__Host-rt`, `Path=/`, `SameSite=Strict`. `HttpOnly` and `Secure` cannot be turned off. |
| Argon2id parameters | 19 MiB memory, 2 iterations, 1 lane (the OWASP minimum) |
| `password.minLength` | 12 |
| `mfa.totp` | SHA-1, 6 digits, 30-second period, one step either side |
| `mfa.rateLimit` | 5 failures per 15 minutes per user |
| `mfa.recoveryCodes` | 10 codes of 80 bits |
| `dpop.mode` | `'required'` |
| `dpop.iatToleranceSec` | 60 |
| `risk.stepUpAt`, `risk.denyAt` | 40, 90 on a scale of 0 to 100 |
| `audit.sinks` | The adapter's audit store |

### 5.2 Service API

Services take plain inputs and a `RequestContext`. They know nothing about HTTP. Failures throw `AuthError` subclasses.

```ts
interface Auth {
  login: {
    withPassword(input: { identifier: string; password: string }, ctx: RequestContext): Promise<LoginResult>;
    passkeyOptions(input: { identifier?: string }, ctx: RequestContext): Promise<PasskeyLoginOptions>;
    withPasskey(input: { challengeId: string; response: AuthenticationResponseJSON }, ctx: RequestContext): Promise<LoginResult>;
  };
  mfa: {
    verify(input: { ticket: string; method: 'totp' | 'recovery_code'; code: string }, ctx: RequestContext): Promise<Authenticated>;
    beginTotpEnrollment(userId: string): Promise<{ enrollmentId: string; secret: string; otpauthUri: string }>;
    confirmTotpEnrollment(userId: string, input: { enrollmentId: string; code: string }): Promise<{ recoveryCodes: string[] }>;
    removeTotp(userId: string): Promise<void>;
    regenerateRecoveryCodes(userId: string): Promise<string[]>;
  };
  passkeys: {
    registrationOptions(userId: string): Promise<PasskeyRegistrationOptions>;
    register(userId: string, input: { challengeId: string; response: RegistrationResponseJSON; name?: string }): Promise<PasskeyInfo>;
    list(userId: string): Promise<PasskeyInfo[]>;
    remove(userId: string, passkeyId: string): Promise<void>;
  };
  sessions: {
    refresh(refreshToken: string, ctx: RequestContext): Promise<Authenticated>;
    reauthenticate(sessionId: string, factor: ReauthFactor, ctx: RequestContext): Promise<AccessGrant>;
    list(userId: string): Promise<SessionInfo[]>;
    revoke(sessionId: string, reason?: RevokeReason): Promise<void>;
    revokeAll(userId: string, options?: { except?: string }): Promise<number>;
  };
  tokens: {
    verify(accessToken: string, ctx: RequestContext, options?: { checkSession?: boolean }): Promise<VerifiedToken>;
  };
  keys: {
    jwks(): Promise<{ keys: JWK[] }>;
    rotate(): Promise<{ kid: string }>;
  };
  users: {
    create(input: { identifier: string; password?: string; roles?: string[] }): Promise<User>;
    setPassword(userId: string, password: string): Promise<void>;
    changePassword(userId: string, current: string, next: string): Promise<void>;
    disable(userId: string): Promise<void>;
  };
  maintenance: { purgeExpired(): Promise<void> };   // run from a scheduled job
  authorizer: Authorizer;
}

interface RequestContext {
  ip?: string;
  userAgent?: string;
  dpop?: { proof: string; method: string; url: string };
}

interface AccessGrant {
  accessToken: string;
  accessTokenExpiresAt: number;
  user: PublicUser;
  session: SessionInfo;
}

type Authenticated = AccessGrant & { status: 'authenticated'; refreshToken: string };

type LoginResult =
  | Authenticated
  | { status: 'mfa_required'; ticket: string; methods: ('totp' | 'recovery_code')[]; reason: 'enrolled' | 'risk'; expiresAt: number };

interface VerifiedToken { subject: Subject; context: AuthContext; claims: AccessTokenClaims }
```

The HTTP layer moves `refreshToken` into the cookie. It never appears in a response body.

### 5.3 Access tokens and signing keys

**Signing.** `jose` signs with the active key. The token lives for 900 seconds.

**Verification.** `jose.jwtVerify` runs with these checks:

- An algorithm allowlist, by default containing only the configured algorithm. The header's `alg` is checked against the list before any key is looked up, and each key can be used only with the algorithm stored beside it. A token with `alg: none`, or an HMAC token signed with the public key, fails at that first step.
- Exact `iss`, `aud` and `typ`. `exp` and `nbf` with 5 seconds of tolerance. `sub`, `sid` and `jti` must be present.

**Algorithm name.** RFC 9864 deprecates the JOSE name `EdDSA` in favour of the fully specified `Ed25519`, and `jose` 6 accepts both. I propose keeping `EdDSA` as the default because API gateways and older verifiers expect it, with `Ed25519` as a config option.

**Key rotation.** A key moves through four states.

| State | Signs new tokens | Published in JWKS | Purpose |
|---|---|---|---|
| Pending | No | Yes | Published ahead of use so verifier caches learn it |
| Active | Yes | Yes | The single signing key |
| Retiring | No | Yes | Kept until the last token it signed has expired |
| Retired | No | No | Tokens signed with it are rejected |

- `keys.rotate()` adds a pending key. It becomes active once it has been published for longer than the JWKS cache lifetime, 10 minutes by default. The previous key then retires.
- Rotation also happens on its own when the active key is older than `keys.rotateEveryDays`. The check runs when a token is issued, so no background timer is needed, and the store guarantees a single pending key when several instances try at once.
- Private keys are stored encrypted under `dataKeys` using JWE with AES-256-GCM. The key id is the RFC 7638 thumbprint.
- `GET /.well-known/jwks.json` returns public keys only, with `Cache-Control: max-age=600`.

**Resource servers.** A service that only needs to check tokens imports the verifier, which has no database dependency:

```ts
import { createAccessTokenVerifier } from '@koshirepo/auth-server/verifier';

const verify = createAccessTokenVerifier({
  issuer: 'https://api.example.com',
  audience: 'https://api.example.com',
  algorithms: ['EdDSA'],
  jwksUri: 'https://api.example.com/.well-known/jwks.json',
  dpop: { mode: 'required', replayStore },
});

const { subject, context } = await verify(token, { method, url, dpopProof });
```

### 5.4 Sessions and refresh tokens

A login creates one **session**. This is the "family" in requirement 3. Every refresh token issued during that login's lifetime is a row in the session's chain.

A refresh token is 256 random bits from WebCrypto, base64url-encoded. The server stores only its SHA-256 hash.

| Presented token | Result |
|---|---|
| Unknown | `REFRESH_TOKEN_INVALID`. Cookie cleared. |
| Current, session healthy, DPoP proof from the bound key | Rotated: the token is marked used, a successor is issued, and the response carries a new cookie and a new access token. |
| Current, but the proof is missing or signed by another key | `DPOP_KEY_MISMATCH`. The token is not consumed. A `dpop.rejected` event is written, since this is what a stolen cookie looks like. |
| Already used | The whole session is revoked. `REFRESH_TOKEN_REUSED`. A `session.refresh_reuse_detected` event is written. |
| Expired, or the session is revoked or idle too long | `REFRESH_TOKEN_EXPIRED`, `SESSION_REVOKED` or `SESSION_EXPIRED` |

Rotation is one compare-and-set in the adapter. When two requests present the same token at the same moment, exactly one rotates and the other takes the "already used" path.

The cookie is set and read only by the HTTP layer. The endpoints that read it, refresh and logout, also require `POST` and an `Origin` header on the allowlist.

### 5.5 Passwords

```ts
interface PasswordHasher {
  hash(password: string): Promise<string>;                  // PHC-format string
  verify(hash: string, password: string): Promise<boolean>;
  needsRehash(hash: string): boolean;
}
```

- `argon2id()` wraps the `argon2` package, which binds the Argon2 reference implementation. It accepts memory, iterations, lanes and an optional pepper.
- When a login succeeds against a hash made with older parameters, the hash is replaced.
- An unknown identifier is verified against a fixed dummy hash and returns the same `INVALID_CREDENTIALS`, so neither the response nor its timing reveals whether an account exists.
- Throttling is per identifier and per IP, using a growing delay. There is no hard lockout, which would let an attacker lock a victim out.
- Policy is a length range of 12 to 256 characters with no composition rules, plus an optional async `check(password)` hook for a breached-password lookup.
- `argon2` is a native addon, so password login needs Node. On an edge runtime, use passkey sign-in or supply your own `PasswordHasher`. Node 24.7 added a built-in `crypto.argon2`, and a hasher built on it can replace the addon once the floor is Node 24.

### 5.6 MFA

- **Enrolment.** `beginTotpEnrollment` returns the secret and an `otpauth://` URI for the app to render as a QR code. `confirmTotpEnrollment` checks a first code, activates the credential and returns the recovery codes once.
- **Storage.** TOTP seeds are encrypted with JWE (AES-256-GCM) under `dataKeys`. The key id in the JWE header allows data keys to rotate.
- **Replay.** Each credential records the last time step it accepted. A code is accepted only if its step is later, through an atomic compare-and-set.
- **Rate limiting.** Failures are counted per user. An MFA ticket also dies after 5 failed attempts.
- **Recovery codes.** Ten codes of 80 bits each, shown as `XXXX-XXXX-XXXX-XXXX`, stored as SHA-256 hashes, each usable once. Regenerating replaces all of them.
- **MFA ticket.** After the first factor, the server issues an opaque ticket that is valid for 5 minutes, stored as a hash, and bound to the user and to the DPoP key that passed the first factor.

### 5.7 Passkeys

- `@simplewebauthn/server` generates options and verifies responses. `@simplewebauthn/browser` runs the browser ceremony in the client package.
- Challenges are stored server-side, expire after 5 minutes, and are consumed by an atomic read-and-delete.
- Sign-in supports discoverable credentials, so the identifier is optional.
- `userVerification` defaults to `'required'`. A passkey sign-in with user verification counts as `aal2` and skips TOTP.
- The store keeps the credential id, public key, signature counter, transports and backup flags. A counter that goes backwards rejects the sign-in and writes an audit event.

### 5.8 Device binding

- **Key.** The client generates an ES256 key pair with WebCrypto, marked non-extractable, and keeps it in IndexedDB. Script on the page can ask the browser to sign with it but cannot read the private key.
- **Proof.** Every auth request and API call carries a `DPoP` header: a short JWT signed by that key over the HTTP method, the URL, the time, a unique id and, for API calls, a hash of the access token.
- **Registration.** The thumbprint of the key in the login proof is stored on the session and stamped into each access token as `cnf.jkt`.
- **Checks.** `typ` is `dpop+jwt`. The algorithm is on the DPoP allowlist. The signature verifies against the embedded public key. Method and URL match the request. `iat` is within 60 seconds. The proof id has not been seen before. The token hash matches. The key thumbprint equals the one on the token or session.
- **Modes.** `'required'`, `'optional'` (for clients that cannot hold a key) and `'off'`.
- **Not in v1.** Server-issued nonces. They can be added later without an API change.

### 5.9 Risk scoring

```ts
risk: {
  signals: [
    newDevice({ score: 30 }),
    newNetwork({ score: 15 }),
    newLocation({ score: 25, locate: (ip) => geoip.lookup(ip) }),   // you supply the lookup
    failedAttempts({ scorePerFailure: 10, max: 40 }),
  ],
  stepUpAt: 40,
  denyAt: 90,
  whenStepUpUnavailable: 'deny',   // the user has no second factor enrolled
}

type RiskSignal = (input: RiskInput) => Promise<{ name: string; score: number } | null>;
```

| Signal | Fires when |
|---|---|
| `newDevice` | The DPoP key thumbprint has not been seen for this user |
| `newNetwork` | The IP is outside the networks of the user's recent successful logins |
| `newLocation` | The country differs from recent logins, or the distance implies impossible travel |
| `failedAttempts` | There are recent failures for the account or the IP |

- Scores add up, capped at 100. Below `stepUpAt` the login proceeds. From `stepUpAt` MFA is required even if it would not otherwise be. From `denyAt` the login fails with `RISK_DENIED`.
- With the defaults, a new device or a new network alone is allowed, any two of the first three signals require MFA, and denial takes a new device in a new location together with repeated failures.
- Signals that compare against history do not fire on an account's first login.
- Risk is evaluated after the first factor succeeds, so an unauthenticated caller learns nothing from it.
- A custom signal is any function of the shape above.
- The library does not bundle a GeoIP database and never reads `X-Forwarded-For`. The IP comes from the `clientIp` function you give the HTTP layer.
- Every assessment is written as a `risk.evaluated` event.

### 5.10 Audit sinks

```ts
interface AuditSink { write(event: AuditEvent): void | Promise<void> }
```

Included sinks: the adapter's audit store (the default), `consoleSink()` writing JSON lines, and `memorySink()` for tests. `audit.sinks` takes any number of them.

### 5.11 Persistence adapters

```ts
interface AuthAdapter {
  users: UserStore;
  credentials: CredentialStore;   // password hashes, TOTP, recovery codes, passkeys
  sessions: SessionStore;         // sessions and their refresh-token chains
  audit: AuditStore;
  keys: SigningKeyStore;
  devices: DeviceStore;           // devices and networks seen per user
  ephemeral: EphemeralStore;      // short-lived state with expiry
}
```

The methods that carry security guarantees:

```ts
interface SessionStore {
  create(session: NewSession, firstToken: NewRefreshToken): Promise<Session>;
  findById(id: string): Promise<Session | null>;
  findByRefreshTokenHash(hash: string): Promise<{ session: Session; token: RefreshTokenRecord } | null>;
  /** Atomic. Marks `tokenId` used and inserts `next` only if `tokenId` is still unused. Otherwise returns false. */
  rotate(tokenId: string, next: NewRefreshToken, now: Date): Promise<boolean>;
  listByUser(userId: string): Promise<Session[]>;
  revoke(sessionId: string, reason: RevokeReason, now: Date): Promise<void>;
  revokeAllForUser(userId: string, reason: RevokeReason, now: Date, exceptSessionId?: string): Promise<number>;
}

interface CredentialStore {
  // password, TOTP, recovery-code and passkey reads and writes, plus:
  /** Atomic. Advances the last accepted TOTP step only if `step` is later. False means replay. */
  advanceTotpStep(userId: string, step: number): Promise<boolean>;
  /** Atomic. Removes the matching unused recovery code. False means unknown or already used. */
  consumeRecoveryCode(userId: string, codeHash: string, now: Date): Promise<boolean>;
}

interface EphemeralStore {
  set(key: string, value: JsonValue, ttlSec: number): Promise<void>;
  get(key: string): Promise<JsonValue | null>;
  take(key: string): Promise<JsonValue | null>;                // atomic read-and-delete: challenges, MFA tickets
  setIfAbsent(key: string, ttlSec: number): Promise<boolean>;  // replay caches
  increment(key: string, ttlSec: number): Promise<number>;     // rate-limit counters
}
```

Every one-time value is consumed through one of these atomic methods, so correctness under concurrency is part of the adapter contract. A shared contract test suite, exported from `/testing`, runs the same cases against every adapter, including concurrent ones.

**Memory adapter.** Maps in process memory. For tests and local development, and for a single process only.

**Postgres adapter.**

```ts
postgresAdapter({
  db,                                // anything with query(text, params) returning { rows }. A pg Pool works as is.
  schema: 'auth',
  stores: { users: myUserStore },    // optional: keep users in a table you already have
})
```

- Each adapter method is a single SQL statement, using data-modifying CTEs where two rows change together. The adapter therefore needs only `query()`, with no transaction API, and works with pooled and HTTP-based drivers alike.
- Tables: `users`, `password_credentials`, `totp_credentials`, `recovery_codes`, `passkeys`, `sessions`, `refresh_tokens`, `devices`, `signing_keys`, `audit_events`, `ephemeral`. SQL migrations ship in the package.
- Tests run against PGlite, which is Postgres compiled to WebAssembly and runs in process, and against a real server when `DATABASE_URL` is set.

### 5.12 HTTP handler and Express adapter

| Method and path | Authenticated by | Purpose |
|---|---|---|
| `POST /login/password` | Nothing | First factor |
| `POST /login/passkey/options`, `POST /login/passkey` | Nothing | Passkey sign-in |
| `POST /mfa/verify` | MFA ticket | TOTP or recovery code |
| `POST /refresh` | Refresh cookie | Rotate and issue a new access token |
| `POST /logout`, `POST /logout/all` | Refresh cookie | Revoke this session, or all of the user's sessions |
| `GET /session` | Access token | Current user and session |
| `GET /sessions`, `DELETE /sessions/:id` | Access token | List and revoke sessions |
| `POST /reauthenticate` | Access token | Step up inside an existing session |
| `POST /mfa/totp/enroll`, `POST /mfa/totp/confirm`, `DELETE /mfa/totp`, `POST /mfa/recovery-codes` | Access token and recent authentication | Manage the second factor |
| `POST /passkeys/options`, `POST /passkeys`, `GET /passkeys`, `DELETE /passkeys/:id` | Access token and recent authentication | Manage passkeys |
| `POST /password` | Access token and current password | Change password |
| `GET /.well-known/jwks.json` | Nothing | Public keys |

All paths except the last sit under `basePath`. Request bodies are checked by small hand-written validators, so there is no schema-library dependency.

```ts
import { createAuthHandler } from '@koshirepo/auth-server/http';

export const handler = createAuthHandler(auth, {
  basePath: '/auth',
  publicOrigin: 'https://api.example.com',       // the URL browsers use, checked against DPoP proofs
  allowedOrigins: ['https://app.example.com'],
  clientIp: (request) => request.headers.get('x-real-ip') ?? undefined,   // set by your trusted proxy
});
```

Express:

```ts
import { expressAuth } from '@koshirepo/auth-server/express';

const { router, requireAuth, requirePermission } = expressAuth(auth, {
  basePath: '/auth',
  publicOrigin: 'https://api.example.com',
  allowedOrigins: ['https://app.example.com'],
  clientIp: (req) => req.ip,                     // honours Express "trust proxy"
});

app.use(router);

app.get('/invoices/:id', requireAuth(), requirePermission('invoice:read'), showInvoice);

app.delete('/invoices/:id', requireAuth({ assurance: 'aal2', maxAuthAgeSec: 300 }), async (req, res) => {
  const invoice = await invoices.get(req.params.id);
  auth.authorizer.assert(req.auth.subject, 'invoice:delete', invoice, { auth: req.auth.context, now: Date.now() / 1000 });
  await invoices.remove(invoice.id);
  res.status(204).end();
});
```

`requireAuth` verifies the token and the DPoP proof and sets `req.auth` to a `VerifiedToken`. If the session's assurance or age falls short of the options, it throws `STEP_UP_REQUIRED`.

Next.js, for comparison:

```ts
// app/auth/[...path]/route.ts
import { handler } from '@/lib/auth';
export { handler as GET, handler as POST, handler as DELETE };

// app/.well-known/jwks.json/route.ts
import { handler } from '@/lib/auth';
export { handler as GET };
```

## 6. `client`

```ts
import { createAuthClient } from '@koshirepo/auth-client';

export const authClient = createAuthClient({
  baseUrl: 'https://api.example.com/auth',
  access: { rbac, policies },    // optional: the definitions the server uses, for interface gating
});
```

```ts
interface AuthClient {
  // state
  getState(): AuthState;
  subscribe(listener: (state: AuthState) => void): () => void;
  ready(): Promise<AuthState>;                    // settles once the initial session restore has finished

  // sign-in and sign-out
  loginWithPassword(input: { identifier: string; password: string }): Promise<AuthState>;
  loginWithPasskey(input?: { identifier?: string }): Promise<AuthState>;
  submitMfa(input: { method: 'totp' | 'recovery_code'; code: string }): Promise<AuthState>;
  reauthenticate(factor: ReauthFactor): Promise<AuthState>;
  logout(options?: { allSessions?: boolean }): Promise<void>;

  // tokens
  getAccessToken(options?: { forceRefresh?: boolean }): Promise<string | null>;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;

  // account security
  mfa: {
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
  sessions: { list(): Promise<SessionInfo[]>; revoke(id: string): Promise<void> };

  // guards
  check(requirement: GuardRequirement): GuardResult;
  can(action: string, resource?: unknown): boolean;
}

type AuthState =
  | { status: 'loading' }
  | { status: 'unauthenticated' }
  | { status: 'mfa_required'; methods: ('totp' | 'recovery_code')[]; reason: 'enrolled' | 'risk'; expiresAt: number }
  | { status: 'authenticated'; user: PublicUser; session: SessionInfo };
```

Actions resolve with the new state and reject with an `AuthError`.

**Token handling**

- The access token is held in a closure. It is not a property of the client, is never written to `localStorage`, `sessionStorage`, IndexedDB or a cookie, and is not sent to other tabs.
- `getAccessToken()` returns the cached token until 30 seconds before it expires, then refreshes. Callers that arrive during a refresh share the one request in flight.
- A Web Lock serialises refreshes across tabs, so two tabs never present the same refresh token and trip reuse detection. A `BroadcastChannel` tells other tabs about sign-in and sign-out.
- `fetch()` adds `Authorization: DPoP <token>` and a fresh proof. On a 401 carrying a token error it refreshes once and retries once.
- On load, the client makes one refresh attempt to restore the session from the cookie, moving from `loading` to `authenticated` or `unauthenticated`.
- The client never parses the JWT. The user, session and expiry arrive in the response body.

**Route guards**

```ts
interface GuardRequirement {
  roles?: readonly string[];          // any of
  permissions?: readonly string[];    // all of, resolved through the shared role map
  assurance?: 'aal2';
  maxAuthAgeSec?: number;             // recent authentication, otherwise step-up
}

type GuardResult =
  | { status: 'allow' }
  | { status: 'pending' }                                                      // still loading
  | { status: 'deny'; action: 'login' | 'mfa' | 'step_up' | 'forbidden'; reason: string };
```

A guard returns a result and performs no navigation. Your router decides what `action` means. Guards are an interface convenience, and the server remains the place where access is enforced.

**React**

```tsx
import { AuthProvider, AuthGuard, useAuth, useLogin, useGuard, useCan } from '@koshirepo/auth-client/react';

<AuthProvider client={authClient}>{children}</AuthProvider>

const { state, logout } = useAuth();
const { loginWithPassword, loginWithPasskey, submitMfa, pending, error } = useLogin();
const guard = useGuard({ permissions: ['invoice:write'] });
const canDelete = useCan('invoice:delete', invoice);

<AuthGuard require={{ assurance: 'aal2', maxAuthAgeSec: 300 }} fallback={(result) => <YourRedirect result={result} />}>
  <DangerZone />
</AuthGuard>
```

There is no markup, class name or style anywhere in the package. `AuthGuard` renders its children or whatever `fallback` returns.

## 7. Login flow end to end

```text
Browser                                          Server
1. Load or create the DPoP key
2. POST /auth/login/password + DPoP proof  --->  Throttle check, find user, verify Argon2id hash
                                                 Validate proof, derive the device key thumbprint
                                                 Run risk signals: allow, step-up or deny
3.                                         <---  { status: "mfa_required", ticket, methods }
                                                 (only if a factor is enrolled or risk asks for step-up)
4. POST /auth/mfa/verify + DPoP proof      --->  Consume ticket, rate-limit, check TOTP code and replay
   (ticket, code)
5.                                         <---  Set-Cookie: __Host-rt=<refresh token>
                                                 Body: { accessToken, accessTokenExpiresAt, user, session }
                                                 Session created and bound to the device key
6. API call, Authorization: DPoP <token>   --->  Verify signature, algorithm, issuer, audience, expiry
   + DPoP proof                                  Verify proof and key binding, then authorize
```

## 8. Security properties and known limits

The full threat model is a later deliverable. These are the properties the design commits to, each backed by tests.

1. An access token is accepted only if its algorithm is on the allowlist, its key is known and not retired, and `iss`, `aud`, `typ` and `exp` all check out.
2. A refresh token exists in plaintext only in the cookie. The database holds its hash, and it never appears in a response body, a log line or an audit event.
3. Every one-time value (refresh token, MFA ticket, WebAuthn challenge, recovery code, TOTP time step, DPoP proof id) is consumed atomically, so two concurrent uses cannot both succeed.
4. Using a refresh token twice revokes its whole session.
5. With DPoP required, a stolen refresh cookie or access token is unusable without the device's private key, which cannot be exported from the browser.
6. Login responses do not reveal whether an account exists.
7. Error responses contain a code, a fixed message and whitelisted details, with no stack trace or internal message.
8. Audit events contain no secrets or tokens.
9. The access token is never written to browser storage.

Known limits:

- Script injected into the page can act as the user while the page is open: it can call the client and have proofs signed. It cannot export the refresh token or the device key. A content security policy remains the application's job.
- An access token outlives revocation by up to 15 minutes unless the route opts in to the session check. Role changes take effect at the next refresh.
- TOTP seeds have to be decryptable, so anyone holding both the database and a data key can generate codes.
- The DPoP replay cache and rate-limit counters must live in a shared store when more than one server instance runs. The Postgres adapter provides that. The memory adapter does not.
- Risk signals are heuristics, and IP-based signals are only as trustworthy as the `clientIp` function.
- Signing keys are held in process memory. Keys held in a KMS or HSM are not supported in v1.

## 9. Test plan

Vitest, with an injected clock so nothing sleeps. Each module has functional tests plus the security cases below.

| Module | Security cases |
|---|---|
| `tokens` | Expired. Not yet valid. Wrong algorithm. `alg: none`. HMAC signed with the public key. Tampered payload. Wrong issuer, audience or `typ`. Unknown `kid`. Retired key. |
| `keys` | Old tokens stay valid through a rotation until they expire. JWKS never contains private fields. Concurrent rotation leaves one pending key. |
| `sessions` | Refresh reuse revokes the session. Concurrent rotation has exactly one winner. Expired, idle and revoked sessions. Cookie attributes. |
| `password` | Unknown account and wrong password are indistinguishable. Throttling. Rehash when parameters change. |
| `mfa` | RFC 6238 vectors. Replay of an accepted code. Window edges. Rate limit. Ticket single use and expiry. Recovery code single use. |
| `passkeys` | Wrong challenge, origin or RP ID. Reused challenge. Counter regression. Uses a software authenticator written for the tests. |
| `dpop` | Wrong method or URL. Stale `iat`. Replayed proof id. Key mismatch. Missing or wrong token hash. Disallowed algorithm. |
| `risk` | Each signal. Both thresholds. Step-up with no factor enrolled. |
| `audit` | Every flow emits its events. The no-secrets test from section 4.4. |
| `core` access control | Inheritance, cycles, wildcards. Deny overrides allow. Default deny. |
| `core` errors | Snapshot of all codes to catch accidental changes. No stack or cause in JSON. |
| `adapters` | One contract suite against memory and Postgres, including concurrent consumption. |
| `http`, `express` | Origin check. Error mapping. Refresh token never in a body. |
| `client` | Many concurrent `getAccessToken()` calls make one request. A 401 leads to one refresh and one retry. Cross-tab lock. Token never written to storage. |

## 10. Build order

Each step lands with its tests passing before the next begins.

1. Workspace scaffold and git repository. `core` complete.
2. `server`: keys, tokens, DPoP proof validation, standalone verifier.
3. Adapter interfaces, memory and Postgres adapters, contract suite. Sessions and refresh rotation.
4. Password login, rate limiting, audit emitter and sinks.
5. TOTP and recovery codes.
6. Passkeys.
7. Risk scoring.
8. HTTP handler and Express adapter.
9. `client` and React hooks.
10. Documentation: threat model, API reference, configuration reference, integration guide.

## 11. Out of scope

From the spec: social login, SAML and SSO, UI styling.

Added by this proposal, any of which can move into scope if you want it:

- Sign-up, email verification and password reset flows
- Magic links
- Forcing MFA enrolment at login
- DPoP server nonces
- Signing keys held in a KMS or HSM
- Acting as an OAuth authorization server for third-party clients
- Non-browser clients, since the refresh cookie is a browser mechanism
