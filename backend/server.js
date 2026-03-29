import express from 'express'
import cors from 'cors'
import session from 'express-session'
import connectPgSimple from 'connect-pg-simple'
import passport from 'passport'
import { Strategy as GitHubStrategy } from 'passport-github2'
import { nanoid } from 'nanoid'
import process from 'node:process'
import { z } from 'zod'
import pino from 'pino'
import pinoHttp from 'pino-http'
import { rateLimit } from 'express-rate-limit'
import IORedis from 'ioredis'
import { UnrecoverableError, Worker } from 'bullmq'
import { config } from './lib/config.js'
import { initDb, pool } from './lib/db.js'
import {
  createOrUpdateUser,
  createScan,
  getPolicies,
  getScan,
  getUserById,
  listScans,
  setPolicies,
  setScanCompleted,
  setScanFailed,
  setScanRunning,
} from './lib/repository.js'
import { analyzeInput } from './lib/scanner.js'
import { enqueueScan, getQueueStats } from './lib/queue.js'

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
})

const app = express()
app.set('trust proxy', 1)

const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean)

const isCrossSiteProd = allowedOrigins.some(
  (origin) =>
    origin.startsWith('https://') && !origin.includes('localhost') && !origin.includes('127.0.0.1'),
)

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true)
      return callback(new Error('CORS blocked'))
    },
    credentials: true,
  }),
)
app.use(express.json({ limit: '2mb' }))
app.use(
  pinoHttp({
    logger,
    customSuccessMessage(req, res) {
      return `${req.method} ${req.url} -> ${res.statusCode}`
    },
  }),
)

const PgStore = connectPgSimple(session)
app.use(
  session({
    store: new PgStore({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true,
    }),
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      sameSite: isCrossSiteProd ? 'none' : 'lax',
      secure: isCrossSiteProd,
      httpOnly: true,
    },
  }),
)
app.use(passport.initialize())
app.use(passport.session())

app.use(
  '/api',
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Rate limit exceeded. Try again in a minute.' },
  }),
)

const scanRequestSchema = z.object({
  inputType: z.enum(['snippet', 'repo']),
  inputValue: z.string().min(1).max(200_000),
})

const policySchema = z.object({
  id: z.string().min(1),
  category: z.string().min(1).max(64),
  name: z.string().min(1).max(200),
  active: z.boolean(),
  desc: z.string().min(1).max(500),
})

const policyPayloadSchema = z.object({
  policies: z.array(policySchema),
})

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const user = await getUserById(String(id))
    done(null, user || false)
  } catch (error) {
    done(error)
  }
})

if (config.githubClientId && config.githubClientSecret) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: config.githubClientId,
        clientSecret: config.githubClientSecret,
        callbackURL: config.githubCallbackUrl,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const user = await createOrUpdateUser({
            id: `usr_${nanoid(12)}`,
            githubId: profile.id,
            username: profile.username || `github_${profile.id}`,
            displayName: profile.displayName || profile.username || 'GitHub User',
            avatarUrl: profile.photos?.[0]?.value || null,
          })
          done(null, user)
        } catch (error) {
          done(error)
        }
      },
    ),
  )
}

function isAllowedRepoUrl(value) {
  try {
    const url = new URL(value)
    return ['github.com', 'www.github.com'].includes(url.hostname)
  } catch {
    return false
  }
}

function currentUserId(req) {
  return req.user?.id || 'guest'
}

function isAdmin(req) {
  return config.adminKey && req.header('x-admin-key') === config.adminKey
}

function canAccessScan(req, scan) {
  return isAdmin(req) || scan.userId === currentUserId(req)
}

function toHistoryItem(scan) {
  const score = scan.result?.healthScore ?? 0
  const status =
    scan.status === 'completed' ? (score > 75 ? 'passed' : score > 40 ? 'warning' : 'failed') : scan.status

  return {
    id: scan.id,
    target: scan.inputType === 'repo' ? scan.inputValue : 'Fragmento de codigo',
    type: scan.inputType,
    date: new Date(scan.createdAt).toLocaleDateString(),
    score,
    status,
  }
}

function buildSarif(scan) {
  const results = (scan.result?.vulnerabilities || []).map((vuln) => ({
    ruleId: vuln.id || 'CODEGUARD',
    level:
      vuln.severity === 'critical' || vuln.severity === 'high'
        ? 'error'
        : vuln.severity === 'medium'
          ? 'warning'
          : 'note',
    message: { text: vuln.title || 'Finding' },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: vuln.file || (scan.inputType === 'repo' ? scan.inputValue : 'snippet'),
          },
          region: { startLine: Number(vuln.line || 1) },
        },
      },
    ],
  }))

  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeGuard',
            informationUri: 'https://github.com/AnderssonEspinoza/codeward-ia',
            rules: [],
          },
        },
        results,
      },
    ],
  }
}

function buildMarkdown(scan) {
  const result = scan.result || {}
  const lines = []
  lines.push(`# CodeGuard Report - ${scan.id}`)
  lines.push('')
  lines.push(`- Status: ${scan.status}`)
  lines.push(`- Health Score: ${result.healthScore ?? 0}/100`)
  lines.push(`- Engine: ${result.meta?.engine || 'unknown'}`)
  lines.push(`- Tools: ${(result.meta?.tools || []).join(', ') || 'none'}`)
  lines.push('')
  lines.push('## Explanation')
  lines.push(result.explanation || 'No explanation available.')
  lines.push('')
  lines.push('## Vulnerabilities')
  const vulns = result.vulnerabilities || []
  if (vulns.length === 0) {
    lines.push('No vulnerabilities detected.')
  } else {
    for (const vuln of vulns) {
      lines.push(
        `- [${String(vuln.severity || 'low').toUpperCase()}] ${vuln.title} (${vuln.id || 'N/A'}) - tool: ${vuln.tool || 'unknown'} - line: ${vuln.line || 0}`,
      )
    }
  }
  lines.push('')
  lines.push('## Licenses')
  const licenses = result.licenses || []
  if (licenses.length === 0) {
    lines.push('No license findings.')
  } else {
    for (const lic of licenses) {
      lines.push(`- ${lic.name} (${lic.risk}) via ${lic.tool || 'unknown'}`)
    }
  }
  return `${lines.join('\n')}\n`
}

app.get('/auth/github', (req, res, next) => {
  if (!config.githubClientId || !config.githubClientSecret) {
    return res.status(501).json({
      error: 'GitHub OAuth not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.',
    })
  }
  return passport.authenticate('github', { scope: ['user:email'] })(req, res, next)
})

app.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    failureRedirect: `${config.frontendUrl}/?auth=failed`,
  }),
  (req, res) => {
    res.redirect(`${config.frontendUrl}/?auth=success`)
  },
)

app.post('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid')
      res.json({ ok: true })
    })
  })
})

app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ user: null, mode: 'guest' })
  return res.json({ user: req.user, mode: 'oauth' })
})

app.get('/api/auth-config', (req, res) => {
  return res.json({
    githubOAuthConfigured: Boolean(config.githubClientId && config.githubClientSecret),
  })
})

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
    // ignore queue stats errors
  }

  res.json({
    ok: dbOk,
    service: 'codeguard-backend',
    db: dbOk ? 'up' : 'down',
    queue: queueStats,
    workerMode: 'integrated',
    now: new Date().toISOString(),
  })
})

app.get('/api/policies', async (req, res) => {
  const policies = await getPolicies(currentUserId(req))
  res.json({ policies })
})

app.put('/api/policies', async (req, res) => {
  const actorId = currentUserId(req)
  if (actorId === 'guest' && !isAdmin(req)) {
    return res.status(403).json({
      error: 'Forbidden: login with GitHub or provide admin key to update policies',
    })
  }

  const parsed = policyPayloadSchema.safeParse(req.body ?? {})
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid payload for policies',
      details: parsed.error.flatten(),
    })
  }

  const targetUser = actorId === 'guest' ? 'guest' : actorId
  const saved = await setPolicies(targetUser, parsed.data.policies)
  return res.json({ policies: saved })
})

app.get('/api/history', async (req, res) => {
  const scans = await listScans(currentUserId(req), 100)
  res.json({ history: scans.map(toHistoryItem) })
})

app.post('/api/scans', async (req, res) => {
  const parsed = scanRequestSchema.safeParse(req.body ?? {})
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Invalid scan payload',
      details: parsed.error.flatten(),
    })
  }

  const { inputType, inputValue } = parsed.data
  if (inputType === 'repo' && !isAllowedRepoUrl(inputValue)) {
    return res.status(400).json({
      error: 'Only GitHub repository URLs are allowed in this MVP',
    })
  }

  const scan = await createScan({
    id: `SCN-${nanoid(8)}`,
    userId: currentUserId(req),
    inputType,
    inputValue: inputValue.trim(),
    status: 'queued',
    result: null,
    error: null,
  })

  await enqueueScan(scan.id)
  return res.status(202).json({ scanId: scan.id, status: scan.status })
})

app.get('/api/scans/:scanId', async (req, res) => {
  const scanId = String(req.params.scanId || '')
  const scan = await getScan(scanId)
  if (scan == null) return res.status(404).json({ error: 'Scan not found' })
  if (!canAccessScan(req, scan)) return res.status(403).json({ error: 'Forbidden' })

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

app.get('/api/scans/:scanId/export', async (req, res) => {
  const scanId = String(req.params.scanId || '')
  const format = String(req.query.format || 'json').toLowerCase()
  const scan = await getScan(scanId)
  if (scan == null) return res.status(404).json({ error: 'Scan not found' })
  if (!canAccessScan(req, scan)) return res.status(403).json({ error: 'Forbidden' })
  if (scan.status !== 'completed') return res.status(409).json({ error: 'Scan is not completed yet' })

  if (format === 'sarif') return res.json(buildSarif(scan))
  if (format === 'md' || format === 'markdown') {
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8')
    return res.send(buildMarkdown(scan))
  }

  return res.json({
    scanId: scan.id,
    exportedAt: new Date().toISOString(),
    report: scan.result,
  })
})

app.use((err, req, res) => {
  req.log?.error({ err }, 'Unhandled request error')
  if (String(err?.message || '').includes('CORS blocked')) {
    return res.status(403).json({ error: 'CORS origin not allowed' })
  }
  return res.status(500).json({ error: 'Internal server error' })
})

function startIntegratedWorker() {
  const redisConnection = new IORedis(config.redisUrl, {
    maxRetriesPerRequest: null,
    tls: config.redisUrl.startsWith('rediss://') ? {} : undefined,
  })

  const worker = new Worker(
    config.scanQueueName,
    async (job) => {
      const scanId = String(job.data?.scanId || '')
      if (!scanId) throw new UnrecoverableError('Missing scanId in job payload')

      const scan = await getScan(scanId)
      if (scan == null) throw new UnrecoverableError(`Scan ${scanId} not found`)

      await setScanRunning(scanId)

      try {
        const effectivePolicies = await getPolicies(scan.userId)
        const result = await analyzeInput({
          inputType: scan.inputType,
          inputValue: scan.inputValue,
          policies: effectivePolicies,
        })
        await setScanCompleted(scanId, result)
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown worker error'
        await setScanFailed(scanId, message)

        if (
          message.includes('invalid_repo_url') ||
          message.includes('repo_too_large') ||
          message.includes('Only GitHub repository URLs are allowed')
        ) {
          throw new UnrecoverableError(message)
        }
        throw error
      }
    },
    {
      connection: redisConnection,
      concurrency: 2,
    },
  )

  worker.on('ready', () => {
    logger.info(`[worker] Integrated BullMQ worker ready (queue: ${config.scanQueueName})`)
  })

  worker.on('completed', (job) => {
    logger.info(`[worker] Scan completed: ${job.data?.scanId}`)
  })

  worker.on('failed', (job, err) => {
    logger.error(`[worker] Scan failed: ${job?.data?.scanId} - ${err.message}`)
  })

  worker.on('error', (err) => {
    logger.error({ err }, '[worker] Worker connection error')
  })

  const shutdown = async (signal) => {
    logger.info(`[worker] Received ${signal}, closing worker...`)
    await worker.close()
    logger.info('[worker] Worker closed. Exiting.')
    process.exit(0)
  }

  process.on('SIGTERM', () => {
    shutdown('SIGTERM').catch((err) => logger.error({ err }, '[worker] Shutdown failed'))
  })
  process.on('SIGINT', () => {
    shutdown('SIGINT').catch((err) => logger.error({ err }, '[worker] Shutdown failed'))
  })

  return worker
}

async function boot() {
  await initDb()
  startIntegratedWorker()
  app.listen(config.port, () => {
    logger.info(`CodeGuard backend + worker listening on http://localhost:${config.port}`)
  })
}

boot().catch((error) => {
  logger.error(error, 'Failed to boot backend')
  process.exit(1)
})
