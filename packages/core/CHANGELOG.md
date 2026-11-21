# @koshirepo/auth-core

## 0.2.0

### Minor Changes

- Add Cloudflare Workers support: a D1 adapter (`@koshirepo/auth-server/adapters/d1`) with a shipped migration, and a scrypt password hasher (`@koshirepo/auth-server/password/scrypt`) for runtimes where the `argon2` addon cannot load. Requests no longer wait on in-flight work started by another request on Workers.
