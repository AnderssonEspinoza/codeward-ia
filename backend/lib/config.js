import 'dotenv/config'
import process from 'node:process'

export const config = {
  port: Number(process.env.PORT || 8787),
  databaseUrl:
    process.env.DATABASE_URL || 'postgres://postgres:postgres@127.0.0.1:55432/codeguard',
  redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
  scanQueueName: process.env.SCAN_QUEUE_NAME || 'codeguard_scans',
}
