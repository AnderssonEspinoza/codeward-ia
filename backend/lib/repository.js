import { pool } from './db.js'
import { INITIAL_POLICIES } from './defaults.js'

function mapScanRow(row) {
  if (!row) return null
  return {
    id: row.id,
    userId: row.user_id,
    inputType: row.input_type,
    inputValue: row.input_value,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    result: row.result,
    error: row.error,
  }
}

function mapUserRow(row) {
  if (!row) return null
  return {
    id: row.id,
    githubId: row.github_id,
    username: row.username,
    displayName: row.display_name,
    avatarUrl: row.avatar_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

export async function createOrUpdateUser(profile) {
  const { rows } = await pool.query(
    `
    INSERT INTO users (id, github_id, username, display_name, avatar_url, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
    ON CONFLICT (github_id) DO UPDATE
      SET username = EXCLUDED.username,
          display_name = EXCLUDED.display_name,
          avatar_url = EXCLUDED.avatar_url,
          updated_at = NOW()
    RETURNING *
    `,
    [profile.id, profile.githubId, profile.username, profile.displayName, profile.avatarUrl ?? null],
  )
  return mapUserRow(rows[0])
}

export async function getUserById(userId) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [userId])
  return mapUserRow(rows[0])
}

export async function createScan(scan) {
  const { rows } = await pool.query(
    `
    INSERT INTO scans (id, user_id, input_type, input_value, status, result, error)
    VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *
    `,
    [
      scan.id,
      scan.userId || 'guest',
      scan.inputType,
      scan.inputValue,
      scan.status,
      scan.result ?? null,
      scan.error ?? null,
    ],
  )
  return mapScanRow(rows[0])
}

export async function getScan(scanId) {
  const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1 LIMIT 1', [scanId])
  return mapScanRow(rows[0])
}

export async function listScans(userId, limit = 100) {
  const targetUser = userId || 'guest'
  const { rows } = await pool.query(
    'SELECT * FROM scans WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
    [targetUser, limit],
  )
  return rows.map(mapScanRow)
}

export async function setScanRunning(scanId) {
  const { rows } = await pool.query(
    `
    UPDATE scans
    SET status = 'running', started_at = NOW(), updated_at = NOW()
    WHERE id = $1
    RETURNING *
    `,
    [scanId],
  )
  return mapScanRow(rows[0])
}

export async function setScanCompleted(scanId, result) {
  const { rows } = await pool.query(
    `
    UPDATE scans
    SET status = 'completed', result = $2::jsonb, error = NULL, finished_at = NOW(), updated_at = NOW()
    WHERE id = $1
    RETURNING *
    `,
    [scanId, JSON.stringify(result)],
  )
  return mapScanRow(rows[0])
}

export async function setScanFailed(scanId, error) {
  const { rows } = await pool.query(
    `
    UPDATE scans
    SET status = 'failed', error = $2, finished_at = NOW(), updated_at = NOW()
    WHERE id = $1
    RETURNING *
    `,
    [scanId, error],
  )
  return mapScanRow(rows[0])
}

async function ensureDefaultPoliciesForUser(userId) {
  const targetUser = userId || 'guest'
  const { rows } = await pool.query(
    "SELECT COUNT(*)::INT AS count FROM policies WHERE user_id = $1",
    [targetUser],
  )
  if ((rows[0]?.count || 0) > 0) return

  for (const p of INITIAL_POLICIES) {
    await pool.query(
      `
      INSERT INTO policies (user_id, id, category, name, active, "desc", updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      `,
      [targetUser, p.id, p.category, p.name, p.active, p.desc],
    )
  }
}

export async function getPolicies(userId) {
  const targetUser = userId || 'guest'
  await ensureDefaultPoliciesForUser(targetUser)
  const { rows } = await pool.query(
    'SELECT id, category, name, active, "desc" FROM policies WHERE user_id = $1 ORDER BY id',
    [targetUser],
  )
  return rows
}

export async function setPolicies(userId, nextPolicies) {
  const targetUser = userId || 'guest'
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    await client.query('DELETE FROM policies WHERE user_id = $1', [targetUser])
    for (const p of nextPolicies) {
      await client.query(
        `
        INSERT INTO policies (user_id, id, category, name, active, "desc", updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        `,
        [targetUser, p.id, p.category, p.name, p.active, p.desc],
      )
    }
    await client.query('COMMIT')
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }

  return getPolicies(targetUser)
}
