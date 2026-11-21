# API reference

The public API of the three packages, by import path. Options and defaults are in the [configuration reference](configuration.md). Every exported symbol also carries a doc comment that your editor shows.

| Import path | Section |
|---|---|
| `@koshirepo/auth-core` | [1](#1-koshirepoauth-core) |
| `@koshirepo/auth-server` | [2](#2-koshirepoauth-server) |
| `@koshirepo/auth-server/verifier` | [3](#3-koshirepoauth-serververifier) |
| `@koshirepo/auth-server/http` | [4](#4-koshirepoauth-serverhttp) |
| `@koshirepo/auth-server/express`, `@koshirepo/auth-server/hono` | [5](#5-framework-adapters) |
| `@koshirepo/auth-server/adapters/*`, `/password/argon2`, `/testing` | [6](#6-adapters-hasher-and-testing) |
| `@koshirepo/auth-client` | [7](#7-koshirepoauth-client) |
| `@koshirepo/auth-client/react` | [8](#8-koshirepoauth-clientreact) |

Conventions used throughout:

- Failures are thrown as `AuthError` subclasses with a stable `code`. Outcomes that are not failures, such as "MFA required", are returned.
- Times in tokens, HTTP bodies and client state are epoch seconds. Times in adapter records are `Date` objects.
- Every server method that serves a request takes an optional `RequestContext` as its last argument.

## 1. `@koshirepo/auth-core`

No dependencies. Runs on the server, in the browser and on edge runtimes.

### 1.1 Errors

```ts
class AuthError extends Error {
  readonly code: ErrorCode;     // stable
  readonly kind: ErrorKind;
  readonly status: number;      // suggested HTTP status
  readonly details?: Readonly<Record<string, JsonValue>>;   // safe to send to clients
  readonly debug?: string;      // for server logs, never serialised
  toJSON(): { code: string; message: string; details?: Record<string, JsonValue> };
}
```

`message` is the fixed public text for the code, so it is always safe to display. Anything specific to one failure is in `details` (public) or in `debug` and `cause` (never serialised).

| Function | Purpose |
|---|---|
| `isAuthError(value)` | True for any error created by this library. Works across duplicate copies of the package, unlike `instanceof`. |
| `errorFromBody(body)` | Rebuilds a typed error from a response body, with or without the `{ error }` envelope. An unknown code becomes `INTERNAL_ERROR`. |
| `isErrorCode(value)`, `listErrorCodes()`, `describeErrorCode(code)` | Introspection. |
| `ErrorCodes` | `ErrorCodes.TOKEN_EXPIRED === 'TOKEN_EXPIRED'`, for those who prefer constants. |

Codes are never renamed, removed or reused within a major version.

| Class | Code | HTTP | Meaning |
|---|---|---|---|
| `AuthenticationError` | `INVALID_CREDENTIALS` | 401 | Unknown account or wrong password. Deliberately the same for both. |
| | `ACCOUNT_DISABLED` | 403 | Reported only after the correct credentials. |
| `AccountError` | `IDENTIFIER_TAKEN` | 409 | |
| | `PASSWORD_POLICY_VIOLATION` | 400 | `details.reason`: `too_short`, `too_long`, `rejected` or `not_a_string`. |
| | `USER_NOT_FOUND` | 404 | |
| `TokenError` | `TOKEN_MISSING` | 401 | |
| | `TOKEN_MALFORMED` | 401 | |
| | `TOKEN_EXPIRED` | 401 | |
| | `TOKEN_SIGNATURE_INVALID` | 401 | |
| | `TOKEN_ALGORITHM_NOT_ALLOWED` | 401 | The header's `alg` is not on the allowlist, or does not match the key. |
| | `TOKEN_KEY_UNKNOWN` | 401 | Unknown or retired key id. |
| | `TOKEN_CLAIMS_INVALID` | 401 | Wrong issuer, audience or type, not yet valid, or a claim missing or mistyped. |
| `SessionError` | `REFRESH_TOKEN_MISSING` | 401 | |
| | `REFRESH_TOKEN_INVALID` | 401 | |
| | `REFRESH_TOKEN_EXPIRED` | 401 | Also the idle limit. |
| | `REFRESH_TOKEN_REUSED` | 401 | An already used token was presented. The session has been revoked. |
| | `SESSION_REVOKED` | 401 | |
| | `SESSION_EXPIRED` | 401 | The absolute limit. |
| `MfaError` | `MFA_TICKET_INVALID` | 401 | Unknown, expired, used, or too many wrong codes. Also used for enrolment ids. |
| | `MFA_CODE_INVALID` | 401 | Wrong, expired or replayed. Deliberately the same for all three. |
| | `MFA_NOT_ENROLLED` | 409 | |
| | `MFA_ALREADY_ENROLLED` | 409 | |
| | `STEP_UP_REQUIRED` | 403 | `details.required`: `aal2` or `recent_authentication`. |
| `PasskeyError` | `PASSKEY_CHALLENGE_INVALID` | 400 | Unknown, expired or already used. |
| | `PASSKEY_VERIFICATION_FAILED` | 401 | |
| | `PASSKEY_NOT_FOUND` | 404 | |
| `DpopError` | `DPOP_PROOF_REQUIRED` | 401 | |
| | `DPOP_PROOF_INVALID` | 401 | When the cause is the timestamp, `details` is `{ reason: 'iat_out_of_window', serverTime }`. |
| | `DPOP_PROOF_REPLAYED` | 401 | |
| | `DPOP_KEY_MISMATCH` | 401 | Signed by a key other than the one the session or token is bound to. |
| `RiskError` | `RISK_DENIED` | 403 | |
| `RateLimitError` | `RATE_LIMITED` | 429 | `details.retryAfterSec`. |
| `AuthorizationError` | `FORBIDDEN` | 403 | `details`: `reason`, `policy`, `action`. |
| `RequestError` | `REQUEST_INVALID` | 400 | `details.field` or `details.reason`. |
| | `ORIGIN_NOT_ALLOWED` | 403 | |
| | `NOT_FOUND` | 404 | |
| `ConfigurationError` | `CONFIGURATION_INVALID` | | Thrown at startup. Its message names the problem. Never sent to a client. |
| `InternalError` | `INTERNAL_ERROR` | 500 | Anything unexpected. |
| `NetworkError` | `NETWORK_ERROR` | | Thrown by the browser client when the server cannot be reached. |

### 1.2 Access control

```ts
const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write', 'invoice:delete'],
  roles: {
    viewer: { grants: ['invoice:read'] },
    editor: { inherits: ['viewer'], grants: ['invoice:write'] },
    admin:  { grants: ['invoice:*'] },
  },
});
```

`defineRbac(definition)` returns:

| Member | Purpose |
|---|---|
| `permissions`, `roles` | The declared names. |
| `permissionsFor(roles)` | The union of permissions held by the roles. Unknown role names are ignored. |
| `grants(roles, permission)` | True when at least one role grants the permission. |
| `isPermission(value)`, `isRole(value)` | Type guards. |

Role and permission names are inferred as literal types, so a misspelt name does not compile. A grant may be a declared permission, `resource:*` or `*`. Wildcards expand over the declared permissions only. Unknown permissions, unknown parent roles and inheritance cycles throw a `ConfigurationError`.

```ts
const ownInvoiceOnly = definePolicy('own-invoice-only', (subject, action, resource: Invoice, context) => {
  if (action !== 'invoice:write') return;                // does not apply
  if (resource.ownerId !== subject.id) return deny('invoice belongs to another user');
});

const authorizer = createAuthorizer({ rbac, policies: [ownInvoiceOnly] });
```

| Function | Purpose |
|---|---|
| `definePolicy(name, fn)` | Names a policy. `fn(subject, action, resource, context)` returns `allow(reason)`, `deny(reason)` or nothing. It must be synchronous and free of side effects. |
| `allow(reason)`, `deny(reason)` | Build a verdict. |
| `createAuthorizer({ rbac?, policies? })` | Returns `{ evaluate, can, assert }`. |

`evaluate(subject, action, resource?, context?)` returns `{ effect, reason, policy }`:

1. If any policy denies, the decision is deny. The first denying policy in list order supplies the reason.
2. Otherwise, if a role grants the permission, the decision is allow with `policy: 'rbac'`. Failing that, if a policy allows, the decision is allow with that policy's name.
3. Otherwise the decision is deny with `policy: 'default'`.

A policy that throws or returns a promise counts as a deny. `can(...)` returns the effect as a boolean. `assert(...)` throws `FORBIDDEN`.

`context` is a `PolicyContext`: `{ auth?: AuthContext; now?: number; ip?: string; ...your own fields }`.

### 1.3 Identity types

| Type | Shape |
|---|---|
| `Subject` | `{ id; roles; attributes? }` |
| `AuthContext` | `{ sessionId; methods; assurance; authenticatedAt; deviceBound }` |
| `AuthMethod` | `'pwd' \| 'otp' \| 'recovery' \| 'passkey'` |
| `AssuranceLevel` | `'aal1' \| 'aal2'`. `aal2` means two different kinds of factor, or a passkey with user verification. |
| `AccessTokenClaims` | `iss`, `aud`, `sub`, `iat`, `exp`, `jti`, `sid`, `roles`, `amr`, `acr`, `auth_time`, optional `cnf.jkt`, plus custom claims |
| `PublicUser` | `{ id; identifier; roles }` |
| `SessionInfo` | `{ id; createdAt; lastUsedAt; expiresAt; authenticatedAt; methods; assurance; deviceBound; ip?; userAgent?; current? }` |
| `PasskeyInfo` | `{ id; name; createdAt; lastUsedAt; deviceType; backedUp; transports }` |
| `AccountSecurity` | `{ totp: boolean; recoveryCodes: number; passkeys: number }` |

`identityFromClaims(claims)` builds `{ subject, context }` from verified claims.

### 1.4 Audit events

Every event has `id`, `type`, `at` (ISO 8601), `outcome` (`success` or `failure`) and `data`, and may have `userId`, `sessionId`, `ip`, `userAgent` and `reason`. `AuditEvent` is a union discriminated by `type`. `AUDIT_EVENT_TYPES` lists every type.

| Type | `data` |
|---|---|
| `login.succeeded` | `{ method: 'pwd' \| 'passkey'; riskScore; mfa: boolean }` |
| `login.failed` | `{ method; identifierHash? }`. `reason` is an error code, or `counter_regression`. |
| `risk.evaluated` | `{ score; decision: 'allow' \| 'step_up' \| 'deny'; signals: { name; score }[] }` |
| `mfa.challenged` | `{ reason: 'enrolled' \| 'risk'; methods }` |
| `mfa.verified`, `mfa.failed` | `{ method: 'totp' \| 'recovery_code'; purpose: 'login' \| 'reauthentication' \| 'enrolment' }`. On failure, `reason` is `invalid` or `replayed`. |
| `mfa.totp.enrolled`, `mfa.totp.removed` | `{}` |
| `mfa.recovery_codes.generated` | `{ count }` |
| `mfa.recovery_code.used` | `{ remaining }` |
| `passkey.registered` | `{ passkeyId; deviceType; backedUp }` |
| `passkey.removed` | `{ passkeyId }` |
| `session.created` | `{ methods; assurance; deviceBound }` |
| `session.refreshed` | `{ refreshTokenId }` |
| `session.reauthenticated` | `{ method; assurance }` |
| `session.revoked` | `{ revokeReason; count }` |
| `session.refresh_reuse_detected` | `{ refreshTokenId }` |
| `token.rejected` | `{}`. Only for anomalies: a disallowed algorithm, a bad signature or an unknown key. |
| `dpop.rejected` | `{ during: 'login' \| 'mfa' \| 'refresh' \| 'request' }` |
| `user.created`, `user.disabled` | `{}` |
| `password.changed` | `{ by: 'user' \| 'admin' }` |
| `key.created` | `{ kid; algorithm }` |
| `key.activated`, `key.retired` | `{ kid }` |
| `rate_limit.exceeded` | `{ scope: 'login' \| 'mfa' \| 'password' }` |
| `access.denied` | `{ action; policy; decisionReason }` |

`refreshTokenId` is the id of a database row, not the token. `identifierHash` is a keyed hash of what was typed into the identifier field. No event carries a password, token, code, seed or key.

### 1.5 Wire types

Request and response bodies of the HTTP endpoints, shared by the server handler and the browser client: `ErrorResponse`, `LoginResponse`, `AccessGrantResponse`, `MfaRequiredResponse`, `PasswordLoginRequest`, `MfaVerifyRequest`, `ReauthenticateRequest`, `PasskeyOptionsResponse`, `PasskeyLoginRequest`, `PasskeyRegisterRequest`, `SessionResponse`, `SessionListResponse`, `PasskeyListResponse`, `TotpEnrollmentResponse`, `TotpConfirmRequest`, `RecoveryCodesResponse`, `PasswordChangeRequest`. Section 4.2 shows which endpoint uses which.

## 2. `@koshirepo/auth-server`

### 2.1 `createAuth(config): Auth`

Validates the configuration, wires the services and returns the API below. It does no I/O itself. The first signing key is created on first use.

```ts
interface RequestContext {
  ip?: string;
  userAgent?: string;
  dpop?: { proof: string; method: string; url: string };   // url: what the browser used, without query string
}
```

The HTTP layer builds this for you. Build it yourself only when calling services directly.

### 2.2 `auth.login`

| Method | Returns | Throws |
|---|---|---|
| `withPassword({ identifier, password }, ctx?)` | `LoginResult` | `INVALID_CREDENTIALS`, `ACCOUNT_DISABLED`, `RATE_LIMITED`, `RISK_DENIED`, `DPOP_*`, `REQUEST_INVALID` |
| `passkeyOptions({ identifier? }?, ctx?)` | `{ challengeId, options }` | `REQUEST_INVALID` |
| `withPasskey({ challengeId, response }, ctx?)` | `LoginResult` | `PASSKEY_CHALLENGE_INVALID`, `PASSKEY_VERIFICATION_FAILED`, `ACCOUNT_DISABLED`, `RISK_DENIED`, `DPOP_*` |

```ts
type LoginResult = Authenticated | MfaRequired;

type Authenticated = {
  status: 'authenticated';
  accessToken: string;
  accessTokenExpiresAt: number;
  refreshToken: string;            // put it in the cookie, never in a body or a log
  refreshTokenExpiresAt: number;
  user: PublicUser;
  session: SessionInfo;
};

type MfaRequired = {
  status: 'mfa_required';
  ticket: string;                  // opaque, single-use, 5 minutes
  methods: ('totp' | 'recovery_code')[];
  reason: 'enrolled' | 'risk';
  expiresAt: number;
};
```

`passkeyOptions` ignores the identifier unless `passkeys.identifierHints` is on. A passkey sign-in with user verification is `aal2` and never returns `mfa_required`.

### 2.3 `auth.mfa`

| Method | Returns | Notes |
|---|---|---|
| `verify({ ticket, method, code }, ctx?)` | `Authenticated` | Completes a login. Throws `MFA_TICKET_INVALID`, `MFA_CODE_INVALID`, `RATE_LIMITED`, `DPOP_*`. |
| `beginTotpEnrollment(userId)` | `{ enrollmentId, secret, otpauthUri }` | Nothing changes on the account yet. Throws `MFA_ALREADY_ENROLLED`. |
| `confirmTotpEnrollment(userId, { enrollmentId, code }, ctx?)` | `{ recoveryCodes }` | Activates TOTP. The only time the recovery codes are available in plain text. |
| `removeTotp(userId, ctx?)` | | Also deletes the recovery codes. |
| `regenerateRecoveryCodes(userId, ctx?)` | `string[]` | The old codes stop working. |
| `status(userId)` | `AccountSecurity` | |

### 2.4 `auth.passkeys`

| Method | Returns | Notes |
|---|---|---|
| `registrationOptions(userId)` | `{ challengeId, options }` | Pass `options` to `startRegistration` in the browser. |
| `register(userId, { challengeId, response, name? }, ctx?)` | `PasskeyInfo` | Throws `PASSKEY_CHALLENGE_INVALID`, `PASSKEY_VERIFICATION_FAILED`. |
| `list(userId)` | `PasskeyInfo[]` | |
| `remove(userId, passkeyId, ctx?)` | | Throws `PASSKEY_NOT_FOUND`. Refuses, with `REQUEST_INVALID` and `details.reason: 'last_credential'`, to remove the only way a user has left to sign in. |

### 2.5 `auth.sessions`

| Method | Returns | Notes |
|---|---|---|
| `refresh(refreshToken, ctx?)` | `Authenticated` | Rotates the token. See the table below. |
| `reauthenticate(sessionId, factor, ctx?)` | `AccessGrant` | Step-up. Returns a new access token with updated `auth_time`, `amr` and `acr`. The refresh token is not rotated. |
| `get(sessionId)` | `SessionInfo \| null` | |
| `list(userId, currentSessionId?)` | `SessionInfo[]` | Live sessions, newest first. |
| `revoke(sessionId, reason?, ctx?)` | | |
| `revokeAll(userId, { except?, reason? }?, ctx?)` | `number` | |
| `logout(refreshToken, { all? }?, ctx?)` | | Never throws for a bad or missing token. |

```ts
type ReauthFactor =
  | { method: 'password'; password: string }
  | { method: 'totp' | 'recovery_code'; code: string }
  | { method: 'passkey'; challengeId: string; response: AuthenticationResponseJSON };
```

What `refresh` does with the token it is given:

| Token | Result |
|---|---|
| Unknown | `REFRESH_TOKEN_INVALID` |
| Current, session healthy, proof from the bound key | New refresh token and access token |
| Current, proof missing or from another key | `DPOP_PROOF_REQUIRED` or `DPOP_KEY_MISMATCH`. The token is not consumed. |
| Already used | The session is revoked. `REFRESH_TOKEN_REUSED`. |
| Expired, or session revoked or past its limit | `REFRESH_TOKEN_EXPIRED`, `SESSION_REVOKED`, `SESSION_EXPIRED` |
| User disabled | The session is revoked. `ACCOUNT_DISABLED`. |

### 2.6 `auth.tokens`

`verify(accessToken, ctx?, { checkSession? }?)` returns `{ subject, context, claims }`.

It checks, in order: the algorithm allowlist, the token type, the key, the signature, issuer, audience, expiry and required claims, and then, for a token bound to a key, the DPoP proof in `ctx.dpop`. With `dpop.mode: 'required'`, a token that is not bound to a key is rejected. `checkSession` adds a store read and rejects tokens of revoked sessions.

### 2.7 `auth.keys`

| Method | Returns | Notes |
|---|---|---|
| `jwks()` | `{ keys }` | Public keys of every key that may still verify a token. |
| `rotate()` | `{ kid }` | Publishes a new key. It starts signing after the publication lead time. |

### 2.8 `auth.users`

| Method | Returns | Notes |
|---|---|---|
| `create({ identifier, password?, roles?, attributes? }, ctx?)` | `User` | Throws `IDENTIFIER_TAKEN`, `PASSWORD_POLICY_VIOLATION`. |
| `get(userId)` | `User \| null` | |
| `setPassword(userId, password, ctx?)` | | For administrators and reset flows. Ends every session of the user. |
| `changePassword(userId, current, next, { keepSessionId? }?, ctx?)` | | Ends the user's other sessions. Throttled like login. |
| `disable(userId, ctx?)` | | Blocks sign-in and ends every session. |

Sign-up pages, email verification and password reset are not part of the library. Build them on these.

### 2.9 Authorization and maintenance

| Member | Purpose |
|---|---|
| `auth.authorizer` | The pure evaluator from section 1.2, built from `access` in the config. |
| `auth.authorize(token, action, resource?, { context?, request? }?)` | Evaluates with the token's authentication context and the current time filled in. On deny it writes `access.denied` and throws `FORBIDDEN`. |
| `auth.maintenance.purgeExpired({ sessionRetentionDays? }?)` | Returns `{ ephemeral, sessions }`. Run it on a schedule. |
| `auth.config` | The configuration with defaults filled in. |
| `auth.clock` | `{ nowMs(), nowSec() }`. |

### 2.10 Audit sinks

```ts
interface AuditSink { write(event: AuditEvent): void | Promise<void> }
```

| Function | Purpose |
|---|---|
| `storeSink(adapter.audit)` | Writes to the adapter. The default. |
| `consoleSink({ write? }?)` | One JSON object per line, to standard output by default. |
| `memorySink()` | Collects events in `.events`, with `.ofType(type)` and `.clear()`. For tests. |

### 2.11 Risk signals

`newDevice`, `newNetwork`, `newLocation` and `failedAttempts`, described in the [configuration reference](configuration.md#risk). A custom signal has this shape:

```ts
type RiskSignal = (input: RiskInput) => { name: string; score: number } | null | Promise<...>;

interface RiskInput {
  user: User;
  ip: string | undefined;
  userAgent: string | undefined;
  deviceKey: string | undefined;      // thumbprint of the DPoP key
  location: GeoLocation | null;       // from the locator of a newLocation signal
  now: Date;
  devices: readonly DeviceRecord[];   // empty on the account's first login
  failures: { account: number; ip: number };
}
```

### 2.12 Adapter interfaces

`AuthAdapter` has seven stores: `users`, `credentials`, `sessions`, `audit`, `keys`, `devices` and `ephemeral`. The interfaces are exported from `@koshirepo/auth-server` and documented in `packages/server/src/adapters/types.ts`. The methods that carry security guarantees are these, and each must be atomic:

| Method | Guarantee |
|---|---|
| `users.create(user)` | Returns null if the identifier is taken. Of concurrent calls for one identifier, one succeeds. |
| `sessions.rotate(tokenId, next, now)` | Marks the token used and inserts its successor only if it is still unused. Of concurrent calls, exactly one returns true. |
| `credentials.advanceTotpStep(userId, step)` | Succeeds only if `step` is later than the last accepted one. |
| `credentials.consumeRecoveryCode(userId, hash, now)` | Removes the code. True once. |
| `credentials.savePasskey(credential)` | False if the credential id is already registered. |
| `keys.insertPending(key, expectedActiveKid)` | Inserts only if no key is pending and the active key is still the expected one. |
| `keys.activate(kid, now)` | Promotes a pending key and demotes the active one together. True once. |
| `ephemeral.take(key)` | Read-and-delete. At most one caller gets the value. |
| `ephemeral.setIfAbsent(key, ttlSec)` | True only for the first caller until the entry expires. |
| `ephemeral.increment(key, ttlSec)` | No lost updates. The expiry is set by the first call. |

To write an adapter, implement the interfaces and run `runAdapterContractTests` (section 6.4) against it.

## 3. `@koshirepo/auth-server/verifier`

For services that only need to check access tokens. No database, no auth configuration, WebCrypto and `fetch` only.

```ts
import { createAccessTokenVerifier } from '@koshirepo/auth-server/verifier';

const verify = createAccessTokenVerifier({
  issuer: 'https://api.example.com',
  audience: 'https://files.example.com',
  jwksUri: 'https://api.example.com/.well-known/jwks.json',
});

const { subject, context, claims } = await verify(token, { method, url, dpopProof });
```

`verify(token, { method?, url?, dpopProof? }?)` applies the same checks as `auth.tokens.verify` and throws the same errors. `url` is the URL the browser used. `memoryReplayStore()` is the default replay store.

## 4. `@koshirepo/auth-server/http`

### 4.1 Functions

| Function | Purpose |
|---|---|
| `createAuthHandler(auth, options)` | Returns `(request: Request) => Promise<Response>`, serving every endpoint below and the JWKS document. |
| `createHttpAuthContext(auth, options)` | Returns `{ requestContext, authenticate, errorResponse }`, for protecting your own routes in any framework built on Fetch types. |
| `JWKS_PATH` | `'/.well-known/jwks.json'` |

`authenticate(request, { assurance?, maxAuthAgeSec?, checkSession? }?)` verifies the token and proof of a request and returns the verified token. It throws `TOKEN_MISSING`, any token or DPoP error, or `STEP_UP_REQUIRED`. `errorResponse(error, request)` turns any error into the JSON response described below.

### 4.2 Endpoints

All paths are under `basePath`, by default `/auth`. Bodies are JSON.

| Method and path | Authenticated by | Request body | Success |
|---|---|---|---|
| `POST /login/password` | | `{ identifier, password }` | 200 `LoginResponse`, sets the cookie when complete |
| `POST /login/passkey/options` | | `{ identifier? }` | 200 `{ challengeId, options }` |
| `POST /login/passkey` | | `{ challengeId, response }` | 200 `LoginResponse`, sets the cookie when complete |
| `POST /mfa/verify` | MFA ticket | `{ ticket, method, code }` | 200 `AccessGrantResponse`, sets the cookie |
| `POST /refresh` | Cookie | | 200 `AccessGrantResponse`, sets a new cookie |
| `POST /logout` | Cookie | | 204, clears the cookie |
| `POST /logout/all` | Cookie | | 204, clears the cookie |
| `GET /session` | Access token | | 200 `{ user, session, security }` |
| `GET /sessions` | Access token | | 200 `{ sessions }` |
| `DELETE /sessions/:id` | Access token | | 204. 404 for a session that is not the caller's. |
| `POST /reauthenticate` | Access token | A `ReauthenticateRequest` | 200 `AccessGrantResponse` |
| `POST /password` | Access token | `{ currentPassword, newPassword }` | 204 |
| `POST /mfa/totp/enroll` | Access token, recent | | 200 `{ enrollmentId, secret, otpauthUri }` |
| `POST /mfa/totp/confirm` | Access token, recent | `{ enrollmentId, code }` | 200 `{ recoveryCodes }` |
| `DELETE /mfa/totp` | Access token, recent | | 204 |
| `POST /mfa/recovery-codes` | Access token, recent | | 200 `{ recoveryCodes }` |
| `POST /passkeys/options` | Access token, recent | | 200 `{ challengeId, options }` |
| `POST /passkeys` | Access token, recent | `{ challengeId, response, name? }` | 201 `PasskeyInfo` |
| `GET /passkeys` | Access token | | 200 `{ passkeys }` |
| `DELETE /passkeys/:id` | Access token, recent | | 204 |
| `GET /.well-known/jwks.json` | | | 200 `{ keys }`. Not under `basePath`. |

"Recent" means an interactive authentication within `sessions.recentAuthSec`. Otherwise the answer is 403 `STEP_UP_REQUIRED`, and `POST /reauthenticate` resolves it.

```ts
type LoginResponse =
  | { status: 'authenticated'; accessToken; accessTokenExpiresAt; user; session }
  | { status: 'mfa_required'; ticket; methods; reason; expiresAt };
```

The refresh token is never in a body. It travels only in the cookie.

### 4.3 Requests

- Send `Authorization: DPoP <access token>` on authenticated endpoints. `Bearer` is accepted for tokens that are not bound to a key.
- Send a `DPoP` header with a fresh proof on every request, unless device binding is off.
- Send `Content-Type: application/json` with any body. Other content types are rejected.
- On the cookie endpoints the `Origin` header is required and must be in `allowedOrigins`. On every endpoint, an `Origin` header that is present must be in `allowedOrigins`.

### 4.4 Responses

Errors use one envelope:

```json
{ "error": { "code": "RATE_LIMITED", "message": "Too many attempts. Try again later.", "details": { "retryAfterSec": 30 } } }
```

| Header | When |
|---|---|
| `Cache-Control: no-store` | Every auth response |
| `Retry-After` | With `RATE_LIMITED` |
| `WWW-Authenticate: DPoP error="...", algs="..."` | With 401 token and DPoP errors |
| `Access-Control-Allow-Origin`, `-Allow-Credentials: true` | When the request's origin is allowed |
| `Set-Cookie` clearing the cookie | When a cookie endpoint fails with a session error |
| `Cache-Control: public, max-age=...`, `Access-Control-Allow-Origin: *` | The JWKS document |

Anything that is not an `AuthError`, and any internal or configuration error, becomes a 500 with `INTERNAL_ERROR` and is passed to `onError`.

## 5. Framework adapters

Both adapters are thin wrappers over section 4 and take the same options, except that `clientIp` and `onError` receive the framework's own request object.

### 5.1 `@koshirepo/auth-server/express`

```ts
const { router, requireAuth, requirePermission, errorHandler } = expressAuth(auth, options);
```

| Member | Purpose |
|---|---|
| `router` | Middleware that serves the endpoints of section 4 and passes every other request on. It works whether or not a JSON body parser runs before it. |
| `requireAuth({ assurance?, maxAuthAgeSec?, checkSession? }?)` | Verifies the token and proof and sets `req.auth` to `{ subject, context, claims }`. Otherwise responds with the error. |
| `requirePermission(permission, { resource? }?)` | Checks the permission through `auth.authorize`. `resource(req)` loads the object the policies should see and may be async. Use it after `requireAuth`. |
| `errorHandler` | Error middleware that formats `AuthError`s thrown in your handlers and passes everything else on. Mount it after your routes. |

The module also exports `getAuth(req)`, which returns the verified token of a request and throws `TOKEN_MISSING` if `requireAuth` did not run. `req.auth` is typed as optional, because Express cannot know which routes are protected, so `getAuth(req)` is the way to read it without a non-null assertion.

`clientIp` receives the Express request and defaults to `req.ip`.

### 5.2 `@koshirepo/auth-server/hono`

```ts
const { routes, requireAuth, requirePermission, onError } = honoAuth(auth, options);
```

Only types are imported from Hono, so the adapter adds no runtime dependency and runs wherever Hono does. It needs Hono 4.2 or later. Hono 5 is not supported yet: its release candidate calls error handlers differently, so `onError` does not work with it.

| Member | Purpose |
|---|---|
| `routes` | Middleware that serves the endpoints of section 4 and passes every other request on. Mount it with `app.use(routes)`, before your own routes. It still works if an earlier middleware has read the body through Hono. |
| `requireAuth({ assurance?, maxAuthAgeSec?, checkSession? }?)` | Verifies the token and proof and sets `c.get('auth')` to `{ subject, context, claims }`. Otherwise responds with the error. It does not read the body. |
| `requirePermission(permission, { resource? }?)` | Checks the permission through `auth.authorize`. `resource(c)` loads the object the policies should see and may be async. Its context does not carry the route's path type, so `c.req.param('id')` is `string \| undefined` there. Use it after `requireAuth`. |
| `onError` | For `app.onError(onError)`. Formats `AuthError`s thrown in your handlers. Any other error is reported to the `onError` option and answered with a generic 500 in the same format. To keep your own handling for other errors, call it only when `isAuthError(error)` is true. |

The module also exports `getAuth(c)`, which throws `TOKEN_MISSING` if `requireAuth` did not run, and the type `AuthEnv`. Routes behind `requireAuth()` see `c.get('auth')` typed without further work. Add `AuthEnv` to your app's environment type only if you read it elsewhere.

`clientIp` receives the Hono context and has no default.

## 6. Adapters, hasher and testing

### 6.1 `@koshirepo/auth-server/adapters/memory`

`memoryAdapter({ clock? }?)` returns an `AuthAdapter` with an extra `reset()`.

### 6.2 `@koshirepo/auth-server/adapters/postgres`

| Export | Purpose |
|---|---|
| `postgresAdapter({ db, schema?, clock?, stores? })` | The adapter. Every method is a single SQL statement, so `db` only needs `query(text, params)`. |
| `migrate(db, { schema? }?)` | Creates the schema and applies pending migrations. Returns the ids it applied. Safe on every start. Statements run one at a time without a wrapping transaction. |
| `migrations(schema?)` | The migrations as `{ id, statements }[]`, for your own migration tool. |
| `SqlExecutor` | `{ query(text, params?): Promise<{ rows }> }` |

Tables: `users`, `password_credentials`, `totp_credentials`, `recovery_codes`, `passkeys`, `sessions`, `refresh_tokens`, `devices`, `signing_keys`, `audit_events`, `ephemeral`, `schema_migrations`.

### 6.3 `@koshirepo/auth-server/adapters/d1`

| Export | Purpose |
|---|---|
| `d1Adapter({ db, tablePrefix?, clock?, stores? })` | The adapter. `db` is the D1 binding, not a `withSession()` session. Methods that change several rows use `db.batch()`, which D1 runs as a transaction. |
| `migrate(db, { tablePrefix? }?)` | Applies pending migrations, each in one batch. Returns the ids it applied. Run it from a deploy step, not on every request. |
| `migrations(tablePrefix?)` | The migrations as `{ id, statements }[]`. |
| `migrationSql(tablePrefix?)` | The whole schema as one SQL file. The default prefix's file ships as `migrations/d1/0001_auth.sql`, for `wrangler d1 migrations apply`. |
| `D1DatabaseLike` | The part of a D1 binding the adapter uses. `env.DB` fits as is. |

Tables are the Postgres ones with the prefix, default `auth_`.

### 6.4 `@koshirepo/auth-server/password/scrypt`

`scrypt({ logN?, r?, p?, pepper? }?)` returns a `PasswordHasher` built on the platform's `node:crypto`, for runtimes where the `argon2` addon cannot load. On Cloudflare Workers it needs the `nodejs_compat` flag. The defaults (N = 2^14, r = 8, p = 5) are an OWASP-recommended setting, and weaker ones are refused.

### 6.5 `@koshirepo/auth-server/password/argon2`

`argon2id(options?)` returns a `PasswordHasher`:

```ts
interface PasswordHasher {
  hash(password: string): Promise<string>;                  // PHC string
  verify(hash: string, password: string): Promise<boolean>; // never throws for a malformed hash
  needsRehash(hash: string): boolean;
}
```

Implement the interface yourself to use another library or runtime.

### 6.6 `@koshirepo/auth-server/testing`

Requires Vitest.

| Export | Purpose |
|---|---|
| `createFakeClock(startMs?)` | A clock that moves only through `.advance(ms)`, `.advanceSec(s)` and `.set(ms)`. Pass it as `clock` to `createAuth` and to the adapter. |
| `runAdapterContractTests(name, create)` | Runs the adapter contract, including the concurrent cases, against the adapter that `create()` returns before each test. |

## 7. `@koshirepo/auth-client`

### 7.1 `createAuthClient(options): AuthClient`

The access token is held in a closure inside the client. It is not a property, is never written to any browser storage and is not sent to other tabs.

**State**

```ts
type AuthState =
  | { status: 'loading' }            // restoring the session from the cookie
  | { status: 'unauthenticated' }
  | { status: 'mfa_required'; methods; reason; expiresAt }
  | { status: 'authenticated'; user: PublicUser; session: SessionInfo };
```

| Method | Purpose |
|---|---|
| `getState()` | The current state. |
| `subscribe(listener)` | Calls the listener on every change. Returns the unsubscribe function. |
| `ready()` | Settles once the initial restore has finished. Never rejects. |

**Signing in and out.** Each resolves with the new state and rejects with an `AuthError`.

| Method | Notes |
|---|---|
| `loginWithPassword({ identifier, password })` | Resolves with `authenticated` or `mfa_required`. |
| `loginWithPasskey({ identifier? }?)` | Runs the browser ceremony. |
| `submitMfa({ method, code })` | The ticket is kept inside the client. After `MFA_CODE_INVALID` the state stays `mfa_required`. After `MFA_TICKET_INVALID` it returns to `unauthenticated`. |
| `cancelMfa()` | Abandons a login that is waiting for its second factor. |
| `reauthenticate(factor)` | `{ method: 'password', password }`, `{ method: 'totp' \| 'recovery_code', code }` or `{ method: 'passkey' }`. |
| `logout({ allSessions? }?)` | Always signs this tab and the other tabs out. Rejects afterwards if the server could not be reached. |

**Tokens**

| Method | Notes |
|---|---|
| `getAccessToken({ forceRefresh? }?)` | The cached token until 30 seconds before it expires, then a refreshed one. Null when signed out. Concurrent callers share one refresh request. Rejects on network and server errors without changing the state. |
| `fetch(input, init?)` | `fetch` with `Authorization` and a DPoP proof attached. On a 401 it refreshes once and retries once. The refresh cookie is not sent to your API. |

**Account security.** These need an authenticated state.

| Method | Returns |
|---|---|
| `mfa.status()` | `AccountSecurity` |
| `mfa.beginTotpEnrollment()` | `{ enrollmentId, secret, otpauthUri }` |
| `mfa.confirmTotpEnrollment({ enrollmentId, code })` | `{ recoveryCodes }` |
| `mfa.removeTotp()`, `mfa.regenerateRecoveryCodes()` | |
| `passkeys.register({ name? }?)`, `passkeys.list()`, `passkeys.remove(id)` | |
| `sessions.list()`, `sessions.revoke(id)` | Revoking the current session signs this tab out. |
| `changePassword({ currentPassword, newPassword })` | |

A 403 `STEP_UP_REQUIRED` from any of these means the user has to `reauthenticate` first.

**Guards**

| Method | Purpose |
|---|---|
| `check(requirement?)` | Returns a `GuardResult`. |
| `can(action, resource?, context?)` | Evaluates the roles and policies given in `access`. False when signed out. |

```ts
interface GuardRequirement {
  roles?: readonly string[];          // any of
  permissions?: readonly string[];    // all of
  assurance?: 'aal2';
  maxAuthAgeSec?: number;
}

type GuardResult =
  | { status: 'allow' }
  | { status: 'pending' }
  | { status: 'deny'; action: 'login' | 'mfa' | 'step_up' | 'forbidden'; reason: string };
```

Guards decide what to show and perform no navigation. The server decides what is allowed.

`dispose()` stops the client listening to other tabs.

### 7.2 Other exports

| Export | Purpose |
|---|---|
| `evaluateGuard(state, requirement, { rbac?, nowSec })` | The pure function behind `check`. |
| `indexedDbKeyStore({ databaseName? }?)`, `memoryKeyStore()`, `defaultKeyStore()` | Where the device key lives. A `DpopKeyStore` has `load`, `save` and `clear`. |
| `DpopSigner` | Creates the key and signs proofs. Used internally, exported for custom transports. |
| `defaultLocks()`, `inPageLocks` | The lock used to serialise refreshes. |
| `broadcastChannel(name)` | The channel used between tabs. |

## 8. `@koshirepo/auth-client/react`

There is no markup, class name or style in this entry point.

| Export | Purpose |
|---|---|
| `<AuthProvider client>` | Makes a client available to the hooks. Renders only its children. |
| `useAuthClient()` | The client. |
| `useAuthState()` | The state. The component re-renders when it changes. |
| `useAuth()` | `{ state, isLoading, isAuthenticated, user, session, logout, client }` |
| `useLogin()` | `{ state, loginWithPassword, loginWithPasskey, submitMfa, cancelMfa, pending, error, reset }`. The actions resolve with the new state, or with `undefined` after a failure, which is reported through `error` instead of thrown. |
| `useGuard(requirement?)` | A `GuardResult`, re-evaluated when the state changes. |
| `useCan(action, resource?, context?)` | A boolean, re-evaluated when the state changes. |
| `<AuthGuard require fallback pending>` | Renders its children when the requirement is met, `pending` while loading, and `fallback` otherwise. `fallback` may be a node or a function of the deny result. |
