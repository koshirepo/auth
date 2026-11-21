# @koshi-repo/auth-server

The server side of the auth library: signing keys and JWKS, access tokens, sessions with refresh rotation, password login, TOTP and recovery codes, passkeys, device binding (DPoP), risk scoring, audit logging and persistence adapters. Requires Node 22.12 or later.

| Import | Contents |
|---|---|
| `@koshi-repo/auth-server` | `createAuth`, configuration and result types, adapter interfaces, audit sinks, risk signals |
| `@koshi-repo/auth-server/verifier` | `createAccessTokenVerifier`, for services that only check tokens |
| `@koshi-repo/auth-server/http` | `createAuthHandler`: a `(Request) => Promise<Response>` handler |
| `@koshi-repo/auth-server/express` | `expressAuth`: router and middleware |
| `@koshi-repo/auth-server/hono` | `honoAuth`: routes and middleware |
| `@koshi-repo/auth-server/adapters/memory` | In-memory adapter, for tests |
| `@koshi-repo/auth-server/adapters/postgres` | Postgres adapter and migrations |
| `@koshi-repo/auth-server/password/argon2` | Argon2id hasher. Needs the `argon2` package. |
| `@koshi-repo/auth-server/testing` | Fake clock and the adapter contract test suite. Needs Vitest. |

Optional peer dependencies: `argon2` for password hashing, `pg` or any driver with `query(text, params)` for Postgres, `express` 5 for the Express adapter, `hono` 4.2 or later for the Hono adapter. Hono 5 is not supported yet.

Start with the [integration guide](../../docs/integration-express.md), which covers Express, Hono on Bun and Next.js. The [configuration reference](../../docs/configuration.md), [API reference](../../docs/api-reference.md) and [threat model](../../docs/threat-model.md) cover the rest.
