import { PGlite } from '@electric-sql/pglite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { memoryAdapter } from '../src/adapters/memory.js';
import { migrate, migrations, postgresAdapter, type SqlExecutor } from '../src/adapters/postgres/index.js';
import { createFakeClock, runAdapterContractTests } from '../src/testing/index.js';

runAdapterContractTests('memory', () => {
  const clock = createFakeClock();
  return { clock, adapter: memoryAdapter({ clock }) };
});

// PGlite is Postgres compiled to WebAssembly, running in this process. It executes the same SQL a
// server would, so the atomic statements are tested for real. Set DATABASE_URL-style testing up in
// your own project by passing a `pg` Pool to the same contract suite.
let pglite: PGlite;
let schemaCounter = 0;

beforeAll(async () => {
  pglite = new PGlite();
  await pglite.waitReady;
}, 60_000);

afterAll(async () => {
  await pglite.close();
});

runAdapterContractTests('postgres (PGlite)', async () => {
  const clock = createFakeClock();
  const schema = `auth_test_${++schemaCounter}`;
  await migrate(pglite, { schema });
  return {
    clock,
    adapter: postgresAdapter({ db: pglite, schema, clock }),
    dispose: async () => {
      await pglite.query(`DROP SCHEMA "${schema}" CASCADE`);
    },
  };
});

// The same suite against a real server, when one is provided:
//   DATABASE_URL=postgres://user:password@localhost:5432/auth_test pnpm test
// PGlite runs every statement on one connection, so this is the run that exercises the atomic
// statements under true concurrency, with several connections racing.
const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 10 });
  let serverSchemaCounter = 0;
  const runId = Date.now().toString(36);

  afterAll(async () => {
    await pool.end();
  });

  runAdapterContractTests('postgres (DATABASE_URL)', async () => {
    const clock = createFakeClock();
    const schema = `auth_test_${runId}_${++serverSchemaCounter}`;
    await migrate(pool, { schema });
    return {
      clock,
      adapter: postgresAdapter({ db: pool, schema, clock }),
      dispose: async () => {
        await pool.query(`DROP SCHEMA "${schema}" CASCADE`);
      },
    };
  });
}

describe('postgres migrations', () => {
  it('applies each migration once', async () => {
    const schema = 'auth_migrate_once';
    expect(await migrate(pglite, { schema })).toEqual(['0001_initial']);
    expect(await migrate(pglite, { schema })).toEqual([]);
    const { rows } = await pglite.query<{ id: string }>(`SELECT id FROM "${schema}".schema_migrations`);
    expect(rows.map((row) => row.id)).toEqual(['0001_initial']);
    await pglite.query(`DROP SCHEMA "${schema}" CASCADE`);
  });

  it('uses the schema it is given and defaults to "auth"', () => {
    expect(migrations()[0]!.statements[0]).toContain('"auth".users');
    expect(migrations('tenant_a')[0]!.statements[0]).toContain('"tenant_a".users');
  });

  it('rejects schema names that could carry SQL', () => {
    for (const schema of ['auth"; DROP TABLE users; --', 'Auth', '1auth', 'a-b', '', 'a b', 'a.b']) {
      expect(() => migrations(schema)).toThrow(/schema name/);
      expect(() => postgresAdapter({ db: pglite, schema })).toThrow(/schema name/);
    }
  });

  it('sends one statement per query, so drivers without multi-statement support work', async () => {
    const seen: string[] = [];
    const recorder: SqlExecutor = {
      async query(text, params) {
        seen.push(text);
        return pglite.query(text, params);
      },
    };
    const schema = 'auth_single_statements';
    await migrate(recorder, { schema });
    for (const text of seen) expect(text.trim().replace(/;$/, '')).not.toContain(';');
    await pglite.query(`DROP SCHEMA "${schema}" CASCADE`);
  });

  it('lets one store be replaced, for example to keep users in an existing table', async () => {
    const schema = 'auth_custom_store';
    await migrate(pglite, { schema });
    const users = memoryAdapter().users;
    const adapter = postgresAdapter({ db: pglite, schema, stores: { users } });
    expect(adapter.users).toBe(users);
    expect(adapter.sessions).not.toBe(memoryAdapter().sessions);
    await pglite.query(`DROP SCHEMA "${schema}" CASCADE`);
  });
});
