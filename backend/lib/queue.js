import { Queue } from 'bullmq'
import IORedis from 'ioredis'
import { config } from './config.js'

const redisConnection = new IORedis(config.redisUrl, {
  maxRetriesPerRequest: null,
})

export const scanQueue = new Queue(config.scanQueueName, {
  connection: redisConnection,
})

export async function enqueueScan(scanId) {
  await scanQueue.add(
    'scan',
    { scanId },
    {
      removeOnComplete: true,
      attempts: 1,
    },
  )
}

export async function getQueueStats() {
  const counts = await scanQueue.getJobCounts(
    'waiting',
    'active',
    'completed',
    'failed',
    'delayed',
  )

  return counts
}
