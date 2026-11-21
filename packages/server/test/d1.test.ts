import { readFileSync } from 'node:fs';
import { Miniflare } from 'miniflare';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { d1Adapter, migrate, migrations, migrationSql, type D1DatabaseLike } from '../src/adapters/d1/index.js';
import { memoryAdapter } from '../src/adapters/memory.js';
import { createFakeClock, runAdapterContractTests } from '../src/testing/index.js';

// Miniflare runs Cloudflare's own runtime (workerd) with its local D1, so this is real D1 SQL and
// real D1 batches, not a mock. It is still one local database, not the hosted service.
let mf: Miniflare;
let db: D1DatabaseLike;
let counter = 0;

beforeAll(async () => {
  mf = new Miniflare({
    modules: true,
    script: 'export default { fetch() { return new Response("ok"); } };',
    compatibilityDate: '2025-09-01',
    d1Databases: { DB: 'auth-test' },
  });
  db = (await mf.getD1Database('DB')) as unknown as D1DatabaseLike;
}, 60_000);

afterAll(async () => {
  await mf.dispose();
});

runAdapterContractTests('d1 (workerd)', async () => {
  const clock = createFakeClock();
  const tablePrefix = `t${++counter}_`;
  await migrate(db, { tablePrefix });
  return { clock, adapter: d1Adapter({ db, tablePrefix, clock }) };
});

describe('d1 migrations', () => {
  it('applies each migration once', async () => {
    const tablePrefix = 'migrate_once_';
    expect(await migrate(db, { tablePrefix })).toEqual(['0001_initial']);
    expect(await migrate(db, { tablePrefix })).toEqual([]);
  });

  it('leaves nothing behind when a migration fails part-way', async () => {
    const tablePrefix = 'migrate_fail_';
    // Occupies a name the migration needs, late in its list of statements.
    await db.prepare(`CREATE TABLE ${tablePrefix}ephemeral (other TEXT)`).run();
    await expect(migrate(db, { tablePrefix })).rejects.toThrow();
    const { results } = await db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'migrate_fail_%' ORDER BY name`)
      .all();
    expect(results?.map((row) => row.name)).toEqual(['migrate_fail_ephemeral', 'migrate_fail_schema_migrations']);
  });

  it('the SQL file records itself, so migrate() does not apply it again', async () => {
    const tablePrefix = 'from_file_';
    const statements = migrationSql(tablePrefix).split(/;\n\n|;\n$/).filter((text) => text.trim().length > 0);
    await db.batch(statements.map((text) => db.prepare(text)));
    expect(await migrate(db, { tablePrefix })).toEqual([]);
    const adapter = d1Adapter({ db, tablePrefix });
    expect(await adapter.users.findById('nobody')).toBeNull();
  });

  it('ships the SQL file that migrationSql() generates', () => {
    const shipped = readFileSync(new URL('../migrations/d1/0001_auth.sql', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
    expect(shipped).toBe(migrationSql());
  });

  it('rejects table prefixes that could carry SQL', () => {
    for (const tablePrefix of ['auth"; DROP TABLE users; --', 'Auth_', '1auth', 'a-b', '', 'a b', 'a.b']) {
      expect(() => migrations(tablePrefix)).toThrow(/table prefix/);
      expect(() => d1Adapter({ db, tablePrefix })).toThrow(/table prefix/);
    }
  });

  it('lets one store be replaced', () => {
    const users = memoryAdapter().users;
    expect(d1Adapter({ db, stores: { users } }).users).toBe(users);
  });
});
