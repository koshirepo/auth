# Configuration reference

Every option, its default and what it does. Options are grouped by the function they are passed to.

- [`createAuth`](#createauth) — the server
- [`createAuthHandler`, `expressAuth` and `honoAuth`](#http-layer) — the HTTP layer
- [`createAccessTokenVerifier`](#createaccesstokenverifier) — resource servers
- [`postgresAdapter`, `memoryAdapter`](#adapters)
- [`argon2id`](#argon2id)
- [`createAuthClient`](#createauthclient) — the browser
- [Operations](#operations) — keys, rotation, scheduled jobs

`createAuth` checks the whole configuration when it is called and throws a `ConfigurationError` whose message names the first problem.

## `createAuth`

### Required

| Option | Type | Purpose |
|---|---|---|
| `issuer` | `string` | The `iss` claim of access tokens. Usually the origin of the auth server. |
| `audience` | `string` or `string[]` | The `aud` claim of access tokens. Verifiers accept a token if it names their audience. |
| `adapter` | `AuthAdapter` | Where everything is stored. See [Adapters](#adapters). |
| `dataKeys` | `{ id: string; key: string \| Uint8Array }[]` | AES-256 keys for secrets at rest: TOTP seeds and private signing keys. Each `key` is 32 bytes, as bytes or as base64 or base64url text. The first entry encrypts. Every entry can decrypt. See [Data keys](#data-keys). |

At least one of `password` and `passkeys` must also be given.

### `tokens`

| Option | Default | Purpose |
|---|---|---|
| `algorithm` | `'EdDSA'` | Algorithm for signing access tokens: `'EdDSA'`, `'Ed25519'` or `'ES256'`. `'EdDSA'` and `'Ed25519'` use the same Ed25519 keys and differ only in the name written to the token header. RFC 9864 prefers the fully specified `'Ed25519'`. `'EdDSA'` is the default because older verifiers and API gateways expect it. |
| `allowedAlgorithms` | `[algorithm]` | The verification allowlist. A token whose header names another algorithm is rejected before any key is looked up. When you change `algorithm`, list the old one here too until the old keys have retired. |
| `accessTtlSec` | `900` | Access token lifetime. Between 30 and 3600. |
| `clockToleranceSec` | `5` | Allowed clock difference when checking `exp` and `nbf`. |
| `claims` | none | `(user, session) => Record<string, JsonValue>`. Extra claims for the token. Returning a standard claim (`sub`, `roles`, `exp`, `cnf` and so on) is an error. |

### `keys`

| Option | Default | Purpose |
|---|---|---|
| `rotateEveryDays` | `90` | Age at which the signing key is replaced automatically. `0` disables automatic rotation. |
| `jwksMaxAgeSec` | `600` | `max-age` of the JWKS response. |
| `publishLeadSec` | `jwksMaxAgeSec` | How long a new key is published before it starts signing, so verifier caches learn it first. |
| `cacheTtlSec` | `30` | How long an instance trusts its in-memory copy of the key list. A rotation is picked up within this time. |

A key stays published after it stops signing for `accessTtlSec + clockToleranceSec + jwksMaxAgeSec`, which is long enough for every token it signed to expire.

### `sessions`

| Option | Default | Purpose |
|---|---|---|
| `ttlSec` | 30 days | Absolute session lifetime. Refreshing does not extend it. |
| `idleTtlSec` | 7 days | A session that is not refreshed for this long ends. This is also the lifetime of each refresh token. |
| `recentAuthSec` | `600` | How recent the last interactive authentication must be for the endpoints that change how an account is secured. |
| `cookie.name` | `'__Host-rt'` | Name of the refresh cookie. A `__Host-` name requires `path: '/'` and no `domain`. Use a `__Secure-` name to scope the cookie. |
| `cookie.sameSite` | `'strict'` | `'strict'` or `'lax'`. `'lax'` also sends the cookie on top-level navigations from other sites. `'none'` is not accepted. |
| `cookie.path` | `'/'` | |
| `cookie.domain` | none | |

`HttpOnly` and `Secure` are always set and cannot be turned off.

### `password`

Present to enable password login.

| Option | Default | Purpose |
|---|---|---|
| `hasher` | required | A `PasswordHasher`. Use `argon2id()` from `@acme/auth-server/password/argon2`. |
| `minLength` | `12` | In characters. Between 8 and 128. |
| `maxLength` | `256` | Bounds the cost of hashing. Longer passwords are rejected without being hashed. |
| `check` | none | `(password, { identifier }) => string \| null`. Return a short reason to reject, for example after a breached-password lookup. May be async. |

### `passkeys`

Present to enable passkey registration and sign-in.

| Option | Default | Purpose |
|---|---|---|
| `rpId` | required | The WebAuthn relying party id: your registrable domain, for example `example.com`. Passkeys are bound to it permanently. |
| `rpName` | required | Shown by the browser during registration. |
| `origins` | required | Origins of the pages that run the ceremony, for example `['https://app.example.com']`. Must be `https`, except for `localhost`. |
| `userVerification` | `'required'` | `'required'` makes the authenticator check a PIN or biometric, and makes a passkey sign-in count as two factors. With `'preferred'`, a sign-in without that check is one factor and TOTP is still asked for. |
| `identifierHints` | `false` | When `true`, starting a sign-in with an identifier returns that account's credential ids. This lets credentials that are not discoverable sign in, and it reveals whether the account exists and has passkeys. |
| `residentKey` | `'required'` | Whether registration demands a discoverable credential. Values other than `'required'` are only accepted with `identifierHints: true`, because without the hint only discoverable credentials can sign in. |
| `challengeTtlSec` | `300` | Lifetime of a registration or sign-in challenge. |

### `mfa`

| Option | Default | Purpose |
|---|---|---|
| `totp.issuer` | host of `issuer` | Name shown in authenticator apps. |
| `totp.digits` | `6` | `6` or `8`. |
| `totp.period` | `30` | Seconds per code. |
| `totp.window` | `1` | Time steps accepted either side of the current one. |
| `totp.algorithm` | `'SHA-1'` | `'SHA-1'`, `'SHA-256'` or `'SHA-512'`. Several widely used authenticator apps only support SHA-1. |
| `recoveryCodes.count` | `10` | Codes generated per user. |
| `rateLimit.maxFailures` | `5` | Wrong codes allowed per user per window, across TOTP and recovery codes. |
| `rateLimit.windowSec` | `900` | |
| `ticketTtlSec` | `300` | Lifetime of the ticket issued after the first factor. |
| `ticketMaxAttempts` | `5` | Wrong codes allowed against one ticket before it is destroyed. |

### `dpop`

| Option | Default | Purpose |
|---|---|---|
| `mode` | `'required'` | `'required'`: every login must carry a proof, sessions and tokens are bound to its key, and unbound tokens are rejected. `'optional'`: bind when a proof is sent. `'off'`: ignore proofs. |
| `algorithms` | `['ES256']` | Proof signature algorithms accepted: `'ES256'`, `'EdDSA'`, `'Ed25519'`. The browser client signs with ES256. |
| `iatToleranceSec` | `60` | How far a proof's timestamp may be from the server clock. |

### `risk`

| Option | Default | Purpose |
|---|---|---|
| `signals` | `[newDevice(), newNetwork(), failedAttempts()]` | Functions that each contribute a score. See below. |
| `stepUpAt` | `40` | Score from which MFA is required. |
| `denyAt` | `90` | Score from which the login is refused with `RISK_DENIED`. Scores are capped at 100. |
| `whenStepUpUnavailable` | `'allow'` | What to do when step-up is called for and the user has no second factor to step up to. `'allow'` lets the login through. `'deny'` refuses it. See below. |

Built-in signals, all imported from `@acme/auth-server`:

| Signal | Options and defaults | Fires when |
|---|---|---|
| `newDevice` | `score: 30` | The DPoP key has not been seen for this user. Needs device binding. |
| `newNetwork` | `score: 15`, `withinDays: 90` | The IP is outside the /24 (IPv4) or /48 (IPv6) networks of the user's recent logins. |
| `newLocation` | `locate` (required), `score: 25`, `withinDays: 90`, `maxSpeedKmh: 900` | The country differs from recent logins, or the distance from the last login could not have been travelled in the time since. `locate(ip)` returns `{ country?, latitude?, longitude? }` or null. The library does not bundle a GeoIP database. |
| `failedAttempts` | `scorePerFailure: 10`, `max: 40` | There are recent failed logins for the account or the IP. |

None of the history-based signals fire on an account's first login. A custom signal is a function `(input: RiskInput) => { name, score } | null`, sync or async.

**What the defaults do.** A new device alone (30) or a new network alone (15) is allowed. A new device on a new network (45) requires MFA. Four failed attempts alone (40) require MFA, and so does one failed attempt on a new device. Denial outright needs a combination such as a new device, network and country plus two failures (90).

**Accounts without a second factor.** Step-up needs a factor to step up to. For a user who has none, the default `whenStepUpUnavailable: 'allow'` lets the login through, so for those accounts only `denyAt` stops a risky login. The `risk.evaluated` audit event still records `decision: 'step_up'`, which you can alert on.

Set `whenStepUpUnavailable: 'deny'` once every user has a second factor or a passkey. Before that it locks real people out: with the default weights, a user without a second factor would be refused after one mistyped password on a new device, or four on a known one, until the failures age out after 15 minutes.

### `rateLimits`

| Option | Default | Purpose |
|---|---|---|
| `login.freeAttempts` | `5` | Failed password attempts per identifier before delays start. An IP address gets four times as many, because many people can share one. |
| `login.windowSec` | `900` | Failures older than this are forgotten. |
| `login.baseDelaySec` | `30` | The first delay. Each further failure doubles it. |
| `login.maxDelaySec` | `900` | The longest delay. |

The same policy throttles wrong passwords on `changePassword` and on re-authentication.

### `audit`

| Option | Default | Purpose |
|---|---|---|
| `sinks` | the adapter's audit store | Where events go. Any number of `AuditSink`s: `storeSink(adapter.audit)`, `consoleSink()`, `memorySink()`, or your own `{ write(event) }`. Giving `sinks` replaces the default, so include `storeSink` yourself if you still want it. |
| `failClosed` | `false` | When `true`, a sink failure fails the operation being logged. |
| `onError` | logs to stderr | `(error, event) => void`. Called when a sink fails and `failClosed` is false. |

### `access`

| Option | Purpose |
|---|---|
| `rbac` | The result of `defineRbac`. |
| `policies` | An array of policies from `definePolicy`. |

These build `auth.authorizer` and are used by `auth.authorize` and the Express `requirePermission`.

### Other

| Option | Default | Purpose |
|---|---|---|
| `clock` | `Date.now` | Epoch milliseconds. Inject a fake clock in tests, and give the same one to the adapter. |
| `normalizeIdentifier` | trim and lower-case | Maps a submitted identifier to its stored form. |

## HTTP layer

Options of `createAuthHandler(auth, options)`, `createHttpAuthContext(auth, options)`, `expressAuth(auth, options)` and `honoAuth(auth, options)`.

| Option | Default | Purpose |
|---|---|---|
| `publicOrigin` | required | The origin browsers use to reach this server, for example `https://api.example.com`. No path, no trailing slash. DPoP proofs are checked against it, so behind a proxy it is the external origin, not the internal one. |
| `basePath` | `'/auth'` | Where the endpoints are mounted. |
| `allowedOrigins` | `[publicOrigin]` | Origins of the pages allowed to call the endpoints. Used for CORS and for rejecting cross-site requests. Exact matches only. |
| `clientIp` | none | Returns the client IP for risk scoring, throttling and the audit log. With `createAuthHandler` it receives the Fetch `Request`. With `expressAuth` it receives the Express request and defaults to `req.ip`. With `honoAuth` it receives the Hono context and has no default. |
| `maxBodyBytes` | `65536` | Largest request body accepted. |
| `onError` | none | Called with unexpected errors before a generic 500 is sent. Log them here. |

## `createAccessTokenVerifier`

| Option | Default | Purpose |
|---|---|---|
| `issuer` | required | Must equal the auth server's `issuer`. |
| `audience` | required | The audience this service accepts. |
| `algorithms` | `['EdDSA']` | The allowlist. Symmetric algorithms and `none` are refused when the verifier is created. |
| `jwksUri` | | URL of the JWKS, usually `<publicOrigin>/.well-known/jwks.json`. Keys are cached and refetched when an unknown key id appears. |
| `jwks` | | A fixed key set, instead of `jwksUri`. |
| `getKey` | | A custom key resolver, instead of both. Exactly one of the three is required. |
| `clockToleranceSec` | `5` | |
| `dpop.mode` | `'required'` | `'required'` rejects unbound tokens. `'optional'` accepts them and checks proofs for bound ones. `'off'` skips proof checks, which makes a stolen bound token usable at this service. |
| `dpop.algorithms` | `['ES256']` | |
| `dpop.iatToleranceSec` | `60` | |
| `dpop.replayStore` | in memory | Where proof ids are remembered. The default is only correct for a single instance. With several, pass a shared store that implements `setIfAbsent(key, ttlSec)`. |
| `now` | `Date.now` | |

## Adapters

### `memoryAdapter(options?)`

| Option | Default | Purpose |
|---|---|---|
| `clock` | `Date.now` | Used for the expiry of short-lived state. |

For tests and local development. One process only, and nothing survives a restart.

### `postgresAdapter(options)`

| Option | Default | Purpose |
|---|---|---|
| `db` | required | Anything with `query(text, params)` returning `{ rows }`. A `pg` `Pool` or `Client` fits as is. |
| `schema` | `'auth'` | Schema that holds the tables. Lower-case letters, digits and underscores. |
| `clock` | `Date.now` | Used for the expiry of short-lived state. |
| `stores` | none | Replaces individual stores, for example `{ users: myUserStore }` to keep users in a table you already have. |

Create the tables with `migrate(db, { schema })`, which is safe to call on every start, or run the statements from `migrations(schema)` through your own migration tool.

## `argon2id`

From `@acme/auth-server/password/argon2`. Requires the `argon2` package.

| Option | Default | Purpose |
|---|---|---|
| `memoryKiB` | `19456` | Memory per hash. The default of 19 MiB with 2 iterations is the OWASP minimum. Values below 7168 are refused. |
| `iterations` | `2` | |
| `parallelism` | `1` | |
| `pepper` | none | A secret mixed into every hash and kept outside the database. Changing or losing it invalidates every stored password. |
| `unsafeAllowWeakParameters` | `false` | Lets tests use tiny parameters. Never set it in production. |

Raising the parameters later is safe: each user's hash is replaced the next time they sign in.

## `createAuthClient`

| Option | Default | Purpose |
|---|---|---|
| `baseUrl` | required | Where the auth endpoints live, for example `https://api.example.com/auth`. A path such as `/auth` is resolved against the page's origin. |
| `fetch` | global `fetch` | |
| `dpop` | `true` | Device binding. `true` creates a non-extractable ES256 key in IndexedDB. `{ keyStore }` controls where the key lives. `false` sends no proofs and is only for a server with `dpop.mode: 'off'`. |
| `access` | none | `{ rbac, policies }`: the definitions the server uses, for `check`, `can` and the React guards. |
| `refreshSkewSec` | `30` | Refresh this long before the access token expires. |
| `restoreOnStart` | `true` | Try to restore the session from the cookie when the client is created. |
| `locks` | Web Locks API | Serialises refreshes across tabs. `null` disables it, after which two tabs refreshing at once will trip reuse detection and end the session. |
| `channel` | `BroadcastChannel` | Tells other tabs about sign-in and sign-out. `null` disables it. |
| `webauthn` | `@simplewebauthn/browser` | The browser half of the passkey ceremonies. Loaded on first use. |
| `now` | `Date.now` | |

## Operations

### Data keys

Generate a key:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Store it in a secret manager and pass it in through the environment:

```ts
dataKeys: [{ id: '2026-11', key: process.env.AUTH_DATA_KEY }]
```

To rotate, put a new key first and keep the old one in the list:

```ts
dataKeys: [
  { id: '2027-05', key: process.env.AUTH_DATA_KEY_NEW },
  { id: '2026-11', key: process.env.AUTH_DATA_KEY },
]
```

New secrets are encrypted with the first key. Existing ones stay readable through the key id recorded with each ciphertext. An old key can be dropped once no stored TOTP seed or signing key was encrypted with it: signing keys turn over with key rotation, and TOTP seeds only when users re-enrol.

If every data key is lost, stored signing keys and TOTP seeds are unreadable. The library creates new signing keys on its own, which invalidates outstanding access tokens, and users have to enrol TOTP again.

### Signing key rotation

Rotation is automatic every `keys.rotateEveryDays`. To rotate by hand, for example after a suspected leak:

```ts
await auth.keys.rotate();
```

The new key is published at once and starts signing after `publishLeadSec`. The old key keeps verifying until every token it signed has expired. To take a key out of service immediately, set its status to `retired` in the `signing_keys` table. Tokens signed with it are then rejected within `cacheTtlSec`.

### Scheduled maintenance

Run this from a scheduled job, for example once an hour:

```ts
await auth.maintenance.purgeExpired();            // { ephemeral: number, sessions: number }
await auth.maintenance.purgeExpired({ sessionRetentionDays: 90 });
```

It deletes expired short-lived state, and sessions that expired or were revoked more than `sessionRetentionDays` ago (default 30). Audit events are never deleted by the library.

### Several server instances

- Use the Postgres adapter, or another adapter whose `EphemeralStore` is shared. Rate limits, MFA tickets, WebAuthn challenges and the DPoP replay cache all live there.
- Give resource servers a shared `dpop.replayStore` if a proof could reach more than one of their instances.
- Signing keys are shared through the adapter. Each instance picks up a rotation within `keys.cacheTtlSec`.
