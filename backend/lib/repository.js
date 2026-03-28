import { pool } from './db.js'

function mapScanRow(row) {
  if (!row) return null
  return {
    id: row.id,
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

export async function createScan(scan) {
  const { rows } = await pool.query(
    `
    INSERT INTO scans (id, input_type, input_value, status, result, error)
    VALUES ($1, $2, $3, $4, $5, $6)
    RETURNING *
    `,
    [scan.id, scan.inputType, scan.inputValue, scan.status, scan.result ?? null, scan.error ?? null],
  )
  return mapScanRow(rows[0])
}

export async function getScan(scanId) {
  const { rows } = await pool.query('SELECT * FROM scans WHERE id = $1 LIMIT 1', [scanId])
  return mapScanRow(rows[0])
}

export async function listScans(limit = 100) {
  const { rows } = await pool.query('SELECT * FROM scans ORDER BY created_at DESC LIMIT $1', [limit])
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

export async function getPolicies() {
  const { rows } = await pool.query('SELECT id, category, name, active, "desc" FROM policies ORDER BY id')
  return rows
}

export async function setPolicies(nextPolicies) {
  const client = await pool.connect()
  try {
    await client.query('BEGIN')
    await client.query('DELETE FROM policies')
    for (const p of nextPolicies) {
      await client.query(
        `
        INSERT INTO policies (id, category, name, active, "desc", updated_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        `,
        [p.id, p.category, p.name, p.active, p.desc],
      )
    }
    await client.query('COMMIT')
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }

  return getPolicies()
}
