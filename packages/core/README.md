# @koshirepo/auth-core

Shared building blocks of the auth library. No dependencies, and no Node or DOM globals, so it runs on the server, in the browser and on edge runtimes.

- Typed errors with stable codes: `AuthError` and its subclasses, `isAuthError`, `errorFromBody`.
- RBAC: `defineRbac`, with role and permission names checked at compile time.
- ABAC: `definePolicy`, `allow`, `deny` and `createAuthorizer`. Policies are functions of subject, action, resource and context. Deny wins, and the default is deny.
- Audit event types, identity types and the HTTP wire types shared by server and client.

```ts
import { createAuthorizer, defineRbac, definePolicy, deny } from '@koshirepo/auth-core';

const rbac = defineRbac({
  permissions: ['invoice:read', 'invoice:write'],
  roles: { viewer: { grants: ['invoice:read'] }, editor: { inherits: ['viewer'], grants: ['invoice:write'] } },
});

const authorizer = createAuthorizer({ rbac });
authorizer.can({ id: 'u1', roles: ['viewer'] }, 'invoice:write');   // false
```

See the [API reference](../../docs/api-reference.md#1-koshirepoauth-core).
