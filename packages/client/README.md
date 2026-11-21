# @koshirepo/auth-client

The browser side of the auth library. Headless: it has logic and state, and no markup or styling.

- Session state as a small state machine: `loading`, `unauthenticated`, `mfa_required`, `authenticated`.
- The access token is kept in memory only. The refresh token stays in its `HttpOnly` cookie and never reaches script.
- Automatic refresh, with one request shared between concurrent callers and a lock so tabs take turns.
- Device binding: a non-extractable key in IndexedDB signs a proof for every request.
- Password, second-factor and passkey flows, and step-up.
- Route guards and permission checks that use the same roles and policies as the server.

| Import | Contents |
|---|---|
| `@koshirepo/auth-client` | `createAuthClient` and its types. Works with any framework, or none. |
| `@koshirepo/auth-client/react` | `AuthProvider`, `useAuth`, `useLogin`, `useGuard`, `useCan`, `AuthGuard` |

Optional peer dependencies: `@simplewebauthn/browser` for passkeys, `react` 18 or later for the hooks.

## Installation

```sh
npm install @koshirepo/auth-client
```

Install the optional peer dependencies only for the features you use:

```sh
# Passkeys
npm install @simplewebauthn/browser

# React hooks
npm install react react-dom
```

```ts
import { createAuthClient } from '@koshirepo/auth-client';

const authClient = createAuthClient({ baseUrl: 'https://api.example.com/auth' });
await authClient.loginWithPassword({ identifier, password });
const response = await authClient.fetch('https://api.example.com/invoices');
```

See the [integration guide](../../docs/integration-express.md#6-the-browser-client) and the [API reference](../../docs/api-reference.md#7-koshirepoauth-client).
