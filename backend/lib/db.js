import { Pool } from 'pg'
import { config } from './config.js'
import { INITIAL_POLICIES } from './defaults.js'

export const pool = new Pool({
  connectionString: config.databaseUrl,
})

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      github_id TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      display_name TEXT NOT NULL,
      avatar_url TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL DEFAULT 'guest',
      input_type TEXT NOT NULL CHECK (input_type IN ('snippet', 'repo')),
      input_value TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ NULL,
      finished_at TIMESTAMPTZ NULL,
      result JSONB NULL,
      error TEXT NULL
    );
  `)

  await pool.query(`
    ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT 'guest';
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS policies (
      user_id TEXT NOT NULL DEFAULT 'guest',
      id TEXT NOT NULL,
      category TEXT NOT NULL,
      name TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      "desc" TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, id)
    );
  `)

  await pool.query(`
    ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS user_id TEXT NOT NULL DEFAULT 'guest';
  `)

  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'policies_pkey'
          AND conrelid = 'policies'::regclass
      ) THEN
        ALTER TABLE policies DROP CONSTRAINT policies_pkey;
      END IF;
    EXCEPTION
      WHEN undefined_table THEN
        NULL;
    END $$;
  `)

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'policies_user_id_id_pkey'
          AND conrelid = 'policies'::regclass
      ) THEN
        ALTER TABLE policies ADD CONSTRAINT policies_user_id_id_pkey PRIMARY KEY (user_id, id);
      END IF;
    EXCEPTION
      WHEN duplicate_table THEN
        NULL;
    END $$;
  `)

  const { rows } = await pool.query("SELECT COUNT(*)::INT AS count FROM policies WHERE user_id = 'guest'")
  if ((rows[0]?.count || 0) === 0) {
    for (const p of INITIAL_POLICIES) {
      await pool.query(
        `
        INSERT INTO policies (user_id, id, category, name, active, "desc")
        VALUES ('guest', $1, $2, $3, $4, $5)
        `,
        [p.id, p.category, p.name, p.active, p.desc],
      )
    }
  }
}
