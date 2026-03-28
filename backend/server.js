import express from 'express'
import cors from 'cors'
import { nanoid } from 'nanoid'
import process from 'node:process'
import { config } from './lib/config.js'
import { initDb, pool } from './lib/db.js'
import {
  createScan,
  getPolicies,
  getScan,
  listScans,
  setPolicies,
} from './lib/repository.js'
import { enqueueScan, getQueueStats } from './lib/queue.js'

const app = express()
app.use(cors())
app.use(express.json({ limit: '2mb' }))

app.get('/api/health', async (req, res) => {
  let dbOk = false
  try {
    await pool.query('SELECT 1')
    dbOk = true
  } catch {
    dbOk = false
  }

  let queueStats = {
    waiting: 0,
    active: 0,
    completed: 0,
    failed: 0,
    delayed: 0,
  }
  try {
    queueStats = await getQueueStats()
  } catch {
    // ignore queue stats errors here
  }

  res.json({
    ok: dbOk,
    service: 'codeguard-backend',
    db: dbOk ? 'up' : 'down',
    queue: queueStats,
    now: new Date().toISOString(),
  })
})

app.get('/api/policies', async (req, res) => {
  const policies = await getPolicies()
  res.json({ policies })
})

app.put('/api/policies', async (req, res) => {
  const { policies } = req.body ?? {}
  if (!Array.isArray(policies)) {
    return res.status(400).json({ error: 'Invalid payload: policies must be an array' })
  }

  const sanitized = policies.map((p) => ({
    id: String(p.id || ''),
    category: String(p.category || 'general'),
    name: String(p.name || 'Policy'),
    active: Boolean(p.active),
    desc: String(p.desc || ''),
  }))

  const saved = await setPolicies(sanitized)
  return res.json({ policies: saved })
})

app.get('/api/history', async (req, res) => {
  const scans = await listScans(100)
  const history = scans.map((scan) => ({
    id: scan.id,
    target: scan.inputType === 'repo' ? scan.inputValue : 'Fragmento de codigo',
    type: scan.inputType,
    date: new Date(scan.createdAt).toLocaleDateString(),
    score: scan.result?.healthScore ?? 0,
    status:
      scan.status === 'completed'
        ? (scan.result?.healthScore ?? 0) > 75
          ? 'passed'
          : (scan.result?.healthScore ?? 0) > 40
            ? 'warning'
            : 'failed'
        : scan.status,
  }))

  res.json({ history })
})

app.post('/api/scans', async (req, res) => {
  const { inputType, inputValue } = req.body ?? {}

  if (!['snippet', 'repo'].includes(inputType)) {
    return res.status(400).json({ error: 'inputType must be snippet or repo' })
  }
  if (!inputValue || typeof inputValue !== 'string') {
    return res.status(400).json({ error: 'inputValue is required' })
  }

  const scan = await createScan({
    id: `SCN-${nanoid(8)}`,
    inputType,
    inputValue: inputValue.trim(),
    status: 'queued',
    result: null,
    error: null,
  })

  await enqueueScan(scan.id)

  return res.status(202).json({
    scanId: scan.id,
    status: scan.status,
  })
})

app.get('/api/scans/:scanId', async (req, res) => {
  const scan = await getScan(req.params.scanId)
  if (scan == null) return res.status(404).json({ error: 'Scan not found' })

  return res.json({
    scanId: scan.id,
    status: scan.status,
    result: scan.result,
    error: scan.error,
    createdAt: scan.createdAt,
    startedAt: scan.startedAt ?? null,
    finishedAt: scan.finishedAt ?? null,
  })
})

async function boot() {
  await initDb()
  app.listen(config.port, () => {
    console.log(`CodeGuard backend listening on http://localhost:${config.port}`)
  })
}

boot().catch((error) => {
  console.error('Failed to boot backend:', error)
  process.exit(1)
})
