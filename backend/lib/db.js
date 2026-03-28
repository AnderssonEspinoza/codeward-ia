import { Pool } from 'pg'
import { config } from './config.js'
import { INITIAL_POLICIES } from './defaults.js'

export const pool = new Pool({
  connectionString: config.databaseUrl,
})

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
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
    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      category TEXT NOT NULL,
      name TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      "desc" TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `)

  const { rows } = await pool.query('SELECT COUNT(*)::INT AS count FROM policies')
  if ((rows[0]?.count || 0) === 0) {
    for (const p of INITIAL_POLICIES) {
      await pool.query(
        `
        INSERT INTO policies (id, category, name, active, "desc")
        VALUES ($1, $2, $3, $4, $5)
        `,
        [p.id, p.category, p.name, p.active, p.desc],
      )
    }
  }
}
