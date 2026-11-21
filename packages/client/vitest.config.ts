import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const resolve = (path: string) => fileURLToPath(new URL(path, import.meta.url));

export default defineConfig({
  resolve: {
    // Tests run against the source of the sibling packages, so nothing needs building first.
    alias: [
      { find: /^@acme\/auth-core$/, replacement: resolve('../core/src/index.ts') },
      { find: /^@acme\/auth-server$/, replacement: resolve('../server/src/index.ts') },
      { find: /^@acme\/auth-server\/http$/, replacement: resolve('../server/src/http/index.ts') },
      { find: /^@acme\/auth-server\/adapters\/memory$/, replacement: resolve('../server/src/adapters/memory.ts') },
      { find: /^@acme\/auth-server\/password\/argon2$/, replacement: resolve('../server/src/password/argon2.ts') },
      { find: /^@acme\/auth-server\/testing$/, replacement: resolve('../server/src/testing/index.ts') },
    ],
  },
  test: {
    name: 'client',
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    environment: 'node',
    testTimeout: 20_000,
  },
});
