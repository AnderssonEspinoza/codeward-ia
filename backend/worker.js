import process from 'node:process'
import IORedis from 'ioredis'
import { Worker } from 'bullmq'
import { config } from './lib/config.js'
import { initDb } from './lib/db.js'
import { analyzeInput } from './lib/scanner.js'
import {
  getPolicies,
  getScan,
  setScanCompleted,
  setScanFailed,
  setScanRunning,
} from './lib/repository.js'

const redisConnection = new IORedis(config.redisUrl, {
  maxRetriesPerRequest: null,
})

async function processScanJob(scanId) {
  const scan = await getScan(scanId)
  if (scan == null) {
    throw new Error(`Scan ${scanId} not found`)
  }

  await setScanRunning(scanId)

  try {
    const policies = await getPolicies()
    const result = await analyzeInput({
      inputType: scan.inputType,
      inputValue: scan.inputValue,
      policies,
    })

    await setScanCompleted(scanId, result)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown worker error'
    await setScanFailed(scanId, message)
    throw error
  }
}

async function boot() {
  await initDb()

  const worker = new Worker(
    config.scanQueueName,
    async (job) => {
      const scanId = String(job.data?.scanId || '')
      if (!scanId) throw new Error('Missing scanId in job payload')
      await processScanJob(scanId)
    },
    {
      connection: redisConnection,
      concurrency: 2,
    },
  )

  worker.on('ready', () => {
    console.log(`CodeGuard worker connected (queue: ${config.scanQueueName})`)
  })

  worker.on('completed', (job) => {
    console.log(`Worker completed scan ${job.data?.scanId}`)
  })

  worker.on('failed', (job, err) => {
    console.error(`Worker failed scan ${job?.data?.scanId}:`, err.message)
  })
}

boot().catch((error) => {
  console.error('Failed to boot worker:', error)
  process.exit(1)
})
