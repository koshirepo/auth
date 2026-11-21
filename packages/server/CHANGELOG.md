# @koshirepo/auth-server

## 0.2.1

### Patch Changes

- Fix the 0.2.0 packages, which were published from a stale build and lacked `@koshirepo/auth-server/adapters/d1` and `@koshirepo/auth-server/password/scrypt`. Packages are now rebuilt whenever they are packed.
- Updated dependencies
  - @koshirepo/auth-core@0.2.1

## 0.2.0

### Minor Changes

- Add Cloudflare Workers support: a D1 adapter (`@koshirepo/auth-server/adapters/d1`) with a shipped migration, and a scrypt password hasher (`@koshirepo/auth-server/password/scrypt`) for runtimes where the `argon2` addon cannot load. Requests no longer wait on in-flight work started by another request on Workers.

### Patch Changes

- Updated dependencies
  - @koshirepo/auth-core@0.2.0
