import 'dotenv/config'
import process from 'node:process'

export const config = {
  port: Number(process.env.PORT || 8787),
  isProduction: process.env.NODE_ENV === 'production',
  hasExplicitDatabaseUrl: Boolean(process.env.DATABASE_URL),
  hasExplicitRedisUrl: Boolean(process.env.REDIS_URL),
  hasExplicitSessionSecret: Boolean(process.env.SESSION_SECRET),
  databaseUrl:
    process.env.DATABASE_URL || 'postgres://postgres:postgres@127.0.0.1:55432/codeguard',
  redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  scanQueueName: process.env.SCAN_QUEUE_NAME || 'codeguard_scans',
  adminKey: process.env.ADMIN_KEY || 'codeguard-dev-admin',
  scanTimeoutMs: Number(process.env.SCAN_TIMEOUT_MS || 60000),
  maxRepoSizeKb: Number(process.env.MAX_REPO_SIZE_KB || 50000),
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:5173',
  sessionSecret: process.env.SESSION_SECRET || 'codeguard-dev-session-secret',
  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  githubCallbackUrl:
    process.env.GITHUB_CALLBACK_URL || 'http://localhost:8787/auth/github/callback',
}

export function validateRuntimeConfig() {
  const missing = []

  if (config.isProduction && !config.hasExplicitDatabaseUrl) {
    missing.push('DATABASE_URL')
  }

  if (config.isProduction && !config.hasExplicitRedisUrl) {
    missing.push('REDIS_URL')
  }

  if (config.isProduction && !config.hasExplicitSessionSecret) {
    missing.push('SESSION_SECRET')
  }

  if (missing.length > 0) {
    throw new Error(
      `Missing required production environment variables: ${missing.join(', ')}. ` +
        'Configure them in Render before deploying the API.',
    )
  }
}
