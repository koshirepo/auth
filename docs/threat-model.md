# Threat model

This document says what the library defends against, how, where each defence is tested, and what is left for you. Section 6 lists the risks that remain. Section 7 is the checklist of things a deployment has to get right for the rest to hold.

## 1. System in scope

```text
Browser (app origin)                     Server (API origin, same site)             Storage
┌──────────────────────────┐  HTTPS     ┌───────────────────────────────┐          ┌──────────┐
│ your app                 │◀──────────▶│ @acme/auth-server             │◀────────▶│ Postgres │
│ @acme/auth-client        │            │   HTTP handler / Express      │          └──────────┘
│  access token: memory    │            │   services, adapters          │
│  refresh token: cookie   │            └───────────────────────────────┘
│  device key: IndexedDB   │  HTTPS     ┌───────────────────────────────┐
│                          │◀──────────▶│ resource servers              │  fetch the JWKS
└──────────────────────────┘            │   @acme/auth-server/verifier  │  from the auth server
                                        └───────────────────────────────┘
```

Trust boundaries: the browser is untrusted input to the server. The database is trusted for integrity but treated as possibly readable by an attacker, so nothing in it is usable on its own. Resource servers trust only signatures they verify against the published keys.

## 2. Assumptions

The library relies on these and cannot enforce them.

1. All traffic between browser and servers uses TLS.
2. The app and the auth endpoints share a registrable domain, for example `app.example.com` and `api.example.com`.
3. `dataKeys` are stored outside the database, in an environment variable or a secret manager.
4. Only the server can reach the database.
5. `clientIp` returns an address set by infrastructure you control.
6. Your pages do not run attacker-supplied script. Preventing cross-site scripting, with a content security policy and correct output encoding, is the application's job.
7. Server clocks are kept accurate.
8. Dependencies are kept up to date: `jose`, `@simplewebauthn/server`, `argon2`.

## 3. Assets

| Asset | Where it lives | How it is protected |
|---|---|---|
| Passwords | Database | Argon2id hash in PHC format, optional pepper kept outside the database |
| Refresh tokens | Browser cookie, database | Cookie is `HttpOnly; Secure; SameSite=Strict` with the `__Host-` prefix. The database holds only a SHA-256 hash of the 256-bit token. |
| Access tokens | Browser memory | Signed, 15-minute lifetime, bound to the device key |
| Device key (DPoP) | Browser IndexedDB | Generated as a non-extractable `CryptoKey`. The private half never exists as readable bytes. |
| Token signing keys | Database, server memory | Private half encrypted with AES-256-GCM under `dataKeys`. Public half published as JWKS. |
| TOTP seeds | Database | Encrypted with AES-256-GCM under `dataKeys` |
| Recovery codes | Database | SHA-256 hash of an 80-bit code, mixed with the user id |
| Passkey credentials | Database | Public keys only |
| MFA tickets, WebAuthn challenges | Short-lived store | Random, single-use, expire in 5 minutes. Tickets are stored by hash. |
| Data keys | Your configuration | Not stored by the library |
| Audit log | Your sink | Contains no secrets or tokens |

## 4. Adversaries

| | Adversary | Starting position |
|---|---|---|
| A1 | Remote attacker | No credentials. Can send any request. |
| A2 | Password thief | Knows a victim's password, from phishing or reuse on another site |
| A3 | Token thief | Has copied a refresh cookie or an access token, for example from a proxy log or with malware that reads cookie files |
| A4 | Script in the page | Runs JavaScript in your origin through a cross-site scripting bug |
| A5 | Malicious website | The victim visits a site the attacker controls while signed in to yours |
| A6 | Database reader | Has a copy of the database: a leaked backup or a SQL injection elsewhere |
| A7 | Token forger | Crafts tokens and hopes verification is sloppy |
| A8 | Log reader | An operator or attacker who can read application and audit logs |

Out of scope: an attacker who executes code on the server, a compromised browser or operating system, and a malicious dependency.

## 5. Threats and mitigations

### 5.1 Passwords and login

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Online guessing and credential stuffing | A1 | Throttling per identifier and per IP: five free failures, then a delay that doubles from 30 seconds to at most 15 minutes. Failed attempts also raise the risk score. | `login.test.ts`, `risk.test.ts` |
| Finding out which accounts exist | A1 | Unknown account and wrong password return the same error and do the same hashing work, against a dummy hash. A disabled account is only reported after the correct password. Passkey sign-in ignores a submitted identifier by default. | `login.test.ts`, `passkeys.test.ts` |
| Offline cracking after a database leak | A6 | Argon2id with 19 MiB and 2 iterations by default. Hashes made with weaker parameters are replaced at the next login. An optional pepper keeps a database copy alone from being attackable. | `argon2.test.ts`, `login.test.ts` |
| Exhausting the server with expensive hashes | A1 | The throttle is checked before any hashing. Passwords longer than 256 characters are rejected without hashing. Request bodies are limited to 64 KiB. | `login.test.ts`, `http.test.ts` |
| Locking a victim out | A1 | There is no permanent lockout. Delays are bounded and expire. | `login.test.ts` |
| Password typed into the username box ending up in logs | A8 | The submitted identifier is never stored or logged. Audit events and throttle keys use a keyed hash of it. | `login.test.ts`, `audit.test.ts` |

### 5.2 Access tokens

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Forged token with `alg: none` | A7 | The algorithm allowlist is checked before any key is looked up. | `tokens.test.ts` |
| HMAC token signed with the public key as the secret | A7 | Symmetric algorithms cannot be configured or allowlisted. The allowlist rejects the header. | `tokens.test.ts`, `config.test.ts` |
| A valid key used with a different algorithm | A7 | Each key is usable only with the algorithm stored beside it. | `tokens.test.ts` |
| Token from another issuer, for another audience, or of another type | A7 | Exact `iss`, `aud` and `typ: at+jwt` checks. Required claims are type-checked. | `tokens.test.ts`, `verifier.test.ts` |
| Tampered payload or signature | A7 | Signature verification by `jose` | `tokens.test.ts` |
| Token signed with an old key | A7 | A retired key is removed from the key set and tokens naming it are rejected. | `keys.test.ts` |
| Stolen access token | A3 | The token is bound to the device key through `cnf.jkt`. Every use needs a fresh proof signed by that key over the method, URL and token hash. | `tokens.test.ts`, `http.test.ts`, `express.test.ts` |
| Token used after logout | A3 | Lifetime is 15 minutes. The auth endpoints always check the session. Your routes can opt in with `checkSession`. | `tokens.test.ts`, `http.test.ts` |

### 5.3 Refresh tokens and sessions

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Stolen refresh cookie | A3 | The session is bound to the device key, so the cookie alone cannot be refreshed. The failed attempt does not consume the token and is logged as `dpop.rejected`. | `sessions.test.ts`, `http.test.ts`, client `client.test.ts` |
| Stolen cookie together with the ability to sign | A3, A4 | Rotation on every use. Presenting a used token revokes the whole session, so thief and owner cannot both keep using it. | `sessions.test.ts` |
| Two requests racing with the same token | A1 | Rotation is one atomic compare-and-set. Exactly one request wins. | `sessions.test.ts`, `adapters.test.ts` |
| Reading refresh tokens from the database | A6 | Only SHA-256 hashes are stored. The tokens have 256 bits of entropy. | `sessions.test.ts` |
| Refresh token appearing in a response body or log | A8 | Response bodies are built field by field. | `http.test.ts`, `audit.test.ts`, client `client.test.ts` |
| Sessions that never end | A3 | Idle limit of 7 days and absolute limit of 30 days | `sessions.test.ts` |

### 5.4 MFA

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Guessing a TOTP code | A2 | Five failures per user per 15 minutes, across TOTP and recovery codes. A ticket is destroyed after five wrong codes. | `mfa.test.ts` |
| Replaying an observed code | A2 | Each time step is accepted once, through an atomic compare-and-set. After a newer step is used, older ones are refused. | `mfa.test.ts`, `adapters.test.ts` |
| Reading TOTP seeds from the database | A6 | Seeds are encrypted under `dataKeys`. | `mfa.test.ts` |
| Guessing or reusing a recovery code | A2 | 80 bits of entropy, stored hashed, single use, covered by the same rate limit | `mfa.test.ts`, `totp.test.ts` |
| Stealing an MFA ticket | A3 | The ticket is bound to the device key that passed the first factor, expires in 5 minutes and works once. | `mfa.test.ts` |
| Skipping the second factor by removing it | A3 | Changing factors needs a valid token and an interactive authentication within the last 10 minutes. | `http.test.ts` |
| Wrong TOTP arithmetic | | Checked against the RFC 4226 and RFC 6238 test vectors, and against an independent implementation in the client tests | `totp.test.ts` |

### 5.5 Passkeys

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Phishing: a ceremony run on a look-alike site | A5 | Origin and relying-party checks in `@simplewebauthn/server` | `passkeys.test.ts`, client `account.test.ts` |
| Replaying a captured response | A3 | Challenges are single-use, are consumed even when verification fails, and expire in 5 minutes. | `passkeys.test.ts` |
| Cloned authenticator | A3 | A signature counter that goes backwards rejects the sign-in and is logged. | `passkeys.test.ts` |
| Adding the attacker's passkey to a victim's account | A3 | Registration needs a valid token and a recent authentication. | `http.test.ts` |
| Using someone else's passkey to step up a session | A3 | The passkey must belong to the session's user. | `passkeys.test.ts` |
| Removing the last way to sign in | | Refused. | `passkeys.test.ts` |

### 5.6 Device binding

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Replaying a proof | A3 | Proof ids are remembered for as long as the proof could be accepted. | `dpop.test.ts` |
| Using a proof for another request | A3 | The proof names the method, the URL and, with a token, the token hash. | `dpop.test.ts` |
| Old or future-dated proofs | A3, A4 | Accepted only within 60 seconds of server time | `dpop.test.ts` |
| Symmetric or unsigned proofs, or an embedded private key | A7 | Rejected even if someone allowlists the algorithm | `dpop.test.ts` |
| Exporting the device key | A4 | The key is non-extractable. | client `client.test.ts`, `stores.test.ts` |

### 5.7 Browser client

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Reading tokens from browser storage | A4 | The access token is held in a closure and written nowhere. The refresh token is `HttpOnly`. | client `client.test.ts` |
| Tokens leaking between tabs | A4 | Tabs exchange only "signed in" and "signed out". Unknown messages are ignored. | client `client.test.ts`, `stores.test.ts` |
| Two tabs presenting the same refresh token | | A lock serialises refreshes across tabs. | client `client.test.ts` |
| Retry loops hammering the server | | One refresh and one retry per failed request | client `client.test.ts` |

### 5.8 HTTP layer

| Threat | Adversary | Mitigation | Tested in |
|---|---|---|---|
| Cross-site request forgery on refresh or logout | A5 | `SameSite=Strict`, an `Origin` header that must be on the allowlist, JSON-only bodies, and on refresh a proof from the device key | `http.test.ts` |
| Another origin reading responses | A5 | CORS headers only for allowlisted origins. Never a wildcard together with credentials. | `http.test.ts` |
| Internal details in error responses | A1 | Errors carry a code, a fixed message and whitelisted details. Unexpected failures become a generic 500 and go to your `onError` hook. | `http.test.ts`, core `errors.test.ts` |
| Caching of auth responses | A3 | `Cache-Control: no-store` | `http.test.ts` |
| Forged client address | A1 | The library never reads `X-Forwarded-For`. | By construction |
| SQL injection | A1 | Parameterised statements only. The schema name is validated against a strict pattern. | `adapters.test.ts` |

### 5.9 Authorization

| Threat | Mitigation | Tested in |
|---|---|---|
| A policy mistake granting access | Deny wins over allow. With nothing allowing, the answer is deny. A policy that throws or returns a promise counts as deny. | core `policy.test.ts` |
| A wildcard granting more than intended | Wildcards expand only over permissions that were declared. | core `rbac.test.ts` |
| Misspelt role or permission names | Compile errors, and run-time errors when the map is defined | core `rbac.test.ts` |
| Trusting the interface | Client-side guards only decide what to show. The server checks every request again. | Documented |

### 5.10 Audit log

| Threat | Mitigation | Tested in |
|---|---|---|
| Secrets or tokens in the log | Event types have no field that can hold one. One typed function builds every event. A test drives every flow, collects every secret issued or submitted, and asserts none appears in any event. | `audit.test.ts` |
| Log injection | `reason` is an error code or a fixed value. The user agent, which is attacker text, is truncated to 256 characters. Events are JSON. | `audit.test.ts` |
| Missing events | The same test asserts that every event type is emitted by some flow. | `audit.test.ts` |

## 6. Risks that remain

1. **Script in your page can act as the user while the page is open.** It can call the client and have proofs signed. It cannot read the refresh token or export the device key, so the access ends when the page closes. Preventing script injection is the only real defence.
2. **An access token outlives revocation by up to 15 minutes** on routes that do not use `checkSession`. Role changes take effect at the next refresh.
3. **TOTP does not stop real-time phishing.** A site that relays the password and the code as the victim types them gets a session. Passkeys do stop this, because the browser ties them to the origin.
4. **Whoever holds the database and a data key can read TOTP seeds and signing keys.** Keep the two apart.
5. **Signing keys are in server memory.** Keys held in a KMS or HSM are not supported in this version.
6. **Device binding has no server nonces.** A proof is accepted within 60 seconds of server time, so script with momentary access could mint proofs usable for that long.
7. **The replay cache and rate limits need a shared store.** With several server instances, use the Postgres adapter or an equivalent shared `EphemeralStore`. The memory adapter is for one process.
8. **Throttling can be used against a victim.** An attacker who keeps failing can keep an account's password login delayed, by up to 15 minutes at a time. Passkey login is unaffected.
9. **Risk-based step-up only protects accounts that have a second factor.** Otherwise there is nothing to step up to. With the default `risk.whenStepUpUnavailable: 'allow'`, a risky login to an account without a second factor goes through, and only the outright deny threshold stops it. The `risk.evaluated` audit event records that step-up was called for. Setting `'deny'` closes this at the price of refusing real users: with the default weights, anyone without a second factor is refused after four wrong passwords, or after one wrong password on a new device, until the failures age out after 15 minutes. Use `'deny'` once every user has a second factor or a passkey.
10. **Risk signals are heuristics.** IP-based signals are only as good as `clientIp`, and a determined attacker can use a nearby network. A signal or locator that throws is ignored rather than blocking logins.
11. **A lost response on refresh logs the user out.** Reuse detection has no grace period, by design.
12. **A failing audit sink does not block sign-in by default.** Set `audit.failClosed` if an unlogged action must not happen.
13. **Synced passkeys always report a counter of zero**, so cloning cannot be detected for them.
14. **Constant-time comparison is implemented in JavaScript.** It avoids early exit, but a JavaScript engine gives no hard timing guarantee. The compared values are short-lived and rate-limited.
15. **Your sign-up flow can reveal which identifiers exist.** `users.create` reports a taken identifier. How to present that is up to you.
16. **Audit integrity is the sink's job.** The library does not sign or chain events.
17. **Not verified:** the Postgres adapter under true multi-connection concurrency (the tests run it in PGlite, on one connection), browsers other than Chromium, the browser's own passkey dialog, and runtimes other than Node and Bun. The Chromium and Bun checks were done by hand and are not part of the automated suite. The README lists exactly what was checked.

## 7. Deployment checklist

- [ ] Serve everything over HTTPS. The refresh cookie is `Secure` and will not be set otherwise.
- [ ] Put the app and the auth endpoints on the same registrable domain.
- [ ] Generate `dataKeys` with a cryptographic random source, store them in a secret manager, and keep them out of the database and out of version control.
- [ ] Set `publicOrigin` to the exact origin browsers use. Behind a proxy it is not the internal address.
- [ ] List only your own app origins in `allowedOrigins`.
- [ ] Implement `clientIp` from a header your proxy sets and strips from incoming requests. With Express, configure `trust proxy`. With Hono there is no default: until you set `clientIp`, no address reaches risk scoring, throttling or the audit log.
- [ ] Use the Postgres adapter, or another shared store, as soon as you run more than one instance.
- [ ] Call `auth.maintenance.purgeExpired()` from a scheduled job.
- [ ] Set `risk.whenStepUpUnavailable: 'deny'` once every user has a second factor or a passkey (risk 9 above).
- [ ] Send a content security policy from your app that forbids inline and third-party script.
- [ ] Give your own API routes CORS headers that allow `Authorization` and `DPoP`.
- [ ] Route `onError` and `audit.onError` to your error tracker.
- [ ] Send the audit log to append-only storage.
- [ ] Use `checkSession` on routes where 15 minutes of access after revocation is too long.
- [ ] Offer passkeys, and prefer them over TOTP where phishing is a concern.
