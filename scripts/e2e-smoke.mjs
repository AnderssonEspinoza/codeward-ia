import process from 'node:process'

const baseUrl = (process.env.API_BASE_URL || '').trim().replace(/\/$/, '')

if (!baseUrl) {
  console.error('Missing API_BASE_URL. Example: API_BASE_URL=https://codeward-api.onrender.com')
  process.exit(1)
}

async function wait(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms))
}

async function run() {
  const healthRes = await fetch(`${baseUrl}/api/health`)
  if (!healthRes.ok) {
    throw new Error(`Health endpoint failed with status ${healthRes.status}`)
  }
  const health = await healthRes.json()
  console.log('health:', health.ok ? 'ok' : 'degraded', `workerMode=${health.workerMode || 'n/a'}`)

  const createRes = await fetch(`${baseUrl}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      inputType: 'snippet',
      inputValue: "const password='secret123456'; eval(userInput)",
    }),
  })
  if (!createRes.ok) {
    throw new Error(`Create scan failed with status ${createRes.status}`)
  }
  const create = await createRes.json()
  if (!create?.scanId) throw new Error('Scan ID missing from create response')
  console.log('scan created:', create.scanId)

  let status = 'queued'
  let result = null
  for (let i = 0; i < 40; i += 1) {
    await wait(1000)
    const pollRes = await fetch(`${baseUrl}/api/scans/${create.scanId}`)
    if (!pollRes.ok) continue
    const poll = await pollRes.json()
    status = poll.status
    if (status === 'completed') {
      result = poll.result
      break
    }
    if (status === 'failed') {
      throw new Error(`Scan failed: ${poll.error || 'unknown error'}`)
    }
  }

  if (status !== 'completed' || !result) {
    throw new Error('Scan did not complete in time')
  }
  console.log('scan completed:', `score=${result.healthScore}`, `vulns=${result.vulnerabilities?.length || 0}`)

  const exportRes = await fetch(`${baseUrl}/api/scans/${create.scanId}/export?format=markdown`)
  if (!exportRes.ok) {
    throw new Error(`Export markdown failed with status ${exportRes.status}`)
  }
  const exportText = await exportRes.text()
  if (!exportText.includes('CodeGuard Report')) {
    throw new Error('Export markdown content mismatch')
  }
  console.log('export markdown: ok')
}

run()
  .then(() => {
    console.log('e2e smoke: PASS')
  })
  .catch((error) => {
    console.error('e2e smoke: FAIL')
    console.error(error.message)
    process.exit(1)
  })
