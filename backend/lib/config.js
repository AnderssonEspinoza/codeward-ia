import 'dotenv/config'
import process from 'node:process'

export const config = {
  port: Number(process.env.PORT || 8787),
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
