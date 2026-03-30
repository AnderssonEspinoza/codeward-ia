import process from 'node:process'
import os from 'node:os'
import path from 'node:path'
import { Buffer } from 'node:buffer'
import { randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises'
import { config } from './config.js'

const VULN_PATTERNS = [
  {
    id: 'VULN-001',
    title: 'Posible Inyeccion SQL (OWASP A03)',
    severity: 'critical',
    regex: /(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,120}(\+|\$\{|%s|format\()/i,
    recommendation:
      'Usa consultas parametrizadas/prepared statements y evita concatenar input de usuario.',
  },
  {
    id: 'VULN-002',
    title: 'Secreto hardcodeado en codigo',
    severity: 'high',
    regex:
      /(api[_-]?key|secret|token|password|jwt)[\w\s:="']{0,40}["'][A-Za-z0-9_.-]{8,}["']/i,
    recommendation:
      'Mueve secretos a variables de entorno y usa un gestor de secretos.',
  },
  {
    id: 'VULN-003',
    title: 'Uso de eval (RCE risk)',
    severity: 'high',
    regex: /\beval\s*\(/i,
    recommendation:
      'Evita eval(). Reemplaza con parseo seguro, tablas de dispatch o expresiones controladas.',
  },
  {
    id: 'VULN-004',
    title: 'Ejecucion de comandos del sistema',
    severity: 'high',
    regex: /(child_process|exec\s*\(|spawn\s*\()/i,
    recommendation:
      'Valida/escapa input de usuario y considera listas blancas de comandos.',
  },
  {
    id: 'VULN-005',
    title: 'Hash criptografico debil',
    severity: 'medium',
    regex: /(md5|sha1)\s*\(/i,
    recommendation:
      'Usa algoritmos modernos (Argon2, bcrypt, scrypt, SHA-256/512 segun caso).',
  },
]

const LICENSE_PATTERNS = [
  {
    name: 'GPL-3.0',
    risk: 'high',
    status: 'Peligro legal',
    regex: /\bGPL(-|\s)?3(\.0)?\b|GNU\s+GENERAL\s+PUBLIC\s+LICENSE/i,
    description:
      'Copyleft fuerte: puede requerir publicar codigo derivado en ciertos escenarios.',
  },
  {
    name: 'AGPL-3.0',
    risk: 'high',
    status: 'Peligro legal',
    regex: /\bAGPL(-|\s)?3(\.0)?\b|AFFE?RO\s+GENERAL\s+PUBLIC\s+LICENSE/i,
    description:
      'Copyleft fuerte para uso por red; revisar con legal antes de integrar.',
  },
  {
    name: 'MIT',
    risk: 'low',
    status: 'Seguro',
    regex: /\bMIT\s+LICENSE\b/i,
    description: 'Licencia permisiva usualmente compatible con uso comercial.',
  },
]

const MAX_REPO_FILES = 25
const MAX_FILE_BYTES = 120_000
const DEFAULT_REQUIRED_SCANNERS = ['gitleaks', 'semgrep', 'osv-scanner']
const ALLOWED_CODE_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.go',
  '.rb',
  '.php',
  '.cs',
  '.rs',
  '.kt',
  '.swift',
  '.cpp',
  '.c',
  '.h',
  '.sql',
  '.sh',
  '.env',
  '.yml',
  '.yaml',
  '.json',
])

function countLinesUntil(text, index) {
  return text.slice(0, Math.max(0, index)).split('\n').length
}

function getFileExtension(filePath) {
  const lastDot = filePath.lastIndexOf('.')
  if (lastDot === -1) return ''
  return filePath.slice(lastDot).toLowerCase()
}

function isInterestingCodeFile(filePath) {
  const lowered = filePath.toLowerCase()
  if (
    lowered.includes('node_modules/') ||
    lowered.includes('dist/') ||
    lowered.includes('build/') ||
    lowered.includes('.git/')
  ) {
    return false
  }
  return ALLOWED_CODE_EXTENSIONS.has(getFileExtension(filePath))
}

function mapSeverity(raw) {
  const value = String(raw || '').toLowerCase()
  if (value.includes('critical')) return 'critical'
  if (value.includes('high') || value.includes('error')) return 'high'
  if (value.includes('medium') || value.includes('warning')) return 'medium'
  return 'low'
}

function scorePenaltyBySeverity(severity) {
  if (severity === 'critical') return 30
  if (severity === 'high') return 20
  if (severity === 'medium') return 10
  return 5
}

function scorePenalty(vulnerability) {
  const base = scorePenaltyBySeverity(vulnerability.severity)
  if (vulnerability.evidenceType === 'inferred') return Math.max(4, Math.round(base * 0.5))
  if (vulnerability.evidenceType === 'heuristic') return Math.max(6, Math.round(base * 0.7))
  return base
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value))
}

function parseRequiredScanners() {
  const raw = process.env.REQUIRED_SCANNERS
  if (!raw) return DEFAULT_REQUIRED_SCANNERS
  const parsed = raw
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
  return parsed.length > 0 ? parsed : DEFAULT_REQUIRED_SCANNERS
}

function buildFallbackSummary({ inputType, vulnCount, licenseCount, hasHighRiskLicense }) {
  const target = inputType === 'repo' ? 'repositorio' : 'fragmento de codigo'
  const riskLine =
    vulnCount === 0
      ? 'No se detectaron hallazgos criticos con reglas base.'
      : `Se detectaron ${vulnCount} posibles riesgos de seguridad.`
  const licenseLine = hasHighRiskLicense
    ? 'Se observaron indicios de licencias copyleft fuertes; revisar cumplimiento legal.'
    : licenseCount > 0
      ? 'Se identificaron licencias de bajo riesgo en el contenido analizado.'
      : 'No hubo suficiente evidencia para inferir licencias con certeza.'
  return `Analisis local de ${target}. ${riskLine} ${licenseLine}`
}

function safeJsonParse(raw) {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

async function commandExists(bin) {
  const result = await runCommand('which', [bin], { timeoutMs: 5000 })
  return result.code === 0
}

async function getToolAvailability(toolNames) {
  const pairs = await Promise.all(
    toolNames.map(async (tool) => {
      const exists = await commandExists(tool)
      return [tool, exists]
    }),
  )
  return Object.fromEntries(pairs)
}

function runCommand(cmd, args, { cwd = process.cwd(), timeoutMs = config.scanTimeoutMs } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    let killedByTimeout = false

    const timeout = setTimeout(() => {
      killedByTimeout = true
      child.kill('SIGKILL')
    }, timeoutMs)

    child.stdout.on('data', (chunk) => {
      stdout += String(chunk)
    })
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk)
    })

    child.on('close', (code) => {
      clearTimeout(timeout)
      resolve({
        code: typeof code === 'number' ? code : 1,
        stdout,
        stderr,
        killedByTimeout,
      })
    })
    child.on('error', (error) => {
      clearTimeout(timeout)
      resolve({
        code: 1,
        stdout,
        stderr: `${stderr}\n${error.message}`.trim(),
        killedByTimeout: false,
      })
    })
  })
}

async function fetchWithTimeout(url, options = {}, timeoutMs = config.scanTimeoutMs) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } finally {
    clearTimeout(timeout)
  }
}

function parseGithubRepoPath(repoUrl) {
  const match = repoUrl.match(/github\.com\/([^/]+\/[^/\s]+)/i)
  if (!match) return ''
  return match[1].replace(/\.git$/i, '')
}

function buildGithubHeaders() {
  const headers = { Accept: 'application/vnd.github+json' }
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  return headers
}

async function fetchGithubReadme(repoUrl) {
  const repoPath = parseGithubRepoPath(repoUrl)
  if (!repoPath) return ''
  const res = await fetchWithTimeout(`https://api.github.com/repos/${repoPath}/readme`, {
    headers: buildGithubHeaders(),
  })
  if (!res.ok) return ''
  const payload = await res.json()
  if (!payload?.content) return ''
  const content = Buffer.from(payload.content, 'base64').toString('utf8')
  return content.slice(0, 20000)
}

async function fetchRepoCodeSample(repoUrl) {
  const repoPath = parseGithubRepoPath(repoUrl)
  if (!repoPath) return { content: '', scannedFiles: 0, reason: 'invalid_repo_url' }

  const headers = buildGithubHeaders()
  const repoRes = await fetchWithTimeout(`https://api.github.com/repos/${repoPath}`, { headers })
  if (!repoRes.ok) return { content: '', scannedFiles: 0, reason: 'repo_metadata_unavailable' }

  const repoJson = await repoRes.json()
  const repoSizeKb = Number(repoJson?.size || 0)
  if (repoSizeKb > config.maxRepoSizeKb) {
    return { content: '', scannedFiles: 0, reason: `repo_too_large_${repoSizeKb}kb` }
  }

  const defaultBranch = repoJson?.default_branch || 'main'
  const treeRes = await fetchWithTimeout(
    `https://api.github.com/repos/${repoPath}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
    { headers },
  )
  if (!treeRes.ok) return { content: '', scannedFiles: 0, reason: 'repo_tree_unavailable' }

  const treeJson = await treeRes.json()
  const tree = Array.isArray(treeJson?.tree) ? treeJson.tree : []
  const candidates = tree
    .filter((entry) => entry.type === 'blob')
    .filter((entry) => isInterestingCodeFile(entry.path))
    .filter((entry) => Number(entry.size || 0) <= MAX_FILE_BYTES)
    .slice(0, MAX_REPO_FILES)

  if (candidates.length === 0) return { content: '', scannedFiles: 0, reason: 'no_candidate_files' }

  const chunks = []
  let scannedFiles = 0
  for (const entry of candidates) {
    if (!entry.url) continue
    try {
      const blobRes = await fetchWithTimeout(entry.url, { headers })
      if (!blobRes.ok) continue
      const blobJson = await blobRes.json()
      if (blobJson.encoding !== 'base64' || !blobJson.content) continue
      const decoded = Buffer.from(blobJson.content, 'base64').toString('utf8')
      if (!decoded.trim()) continue
      scannedFiles += 1
      chunks.push(`// FILE: ${entry.path}\n${decoded.slice(0, 3000)}\n`)
    } catch {
      // continue
    }
  }

  return {
    content: chunks.join('\n'),
    scannedFiles,
    reason: scannedFiles > 0 ? 'ok' : 'blob_fetch_failed',
  }
}

async function cloneRepoToTmp(repoUrl) {
  const repoPath = parseGithubRepoPath(repoUrl)
  if (!repoPath) return { dir: '', reason: 'invalid_repo_url' }
  const tmpBase = await mkdtemp(path.join(os.tmpdir(), 'codeguard-'))
  const cloneTarget = path.join(tmpBase, randomUUID())
  const remoteUrl = `https://github.com/${repoPath}.git`
  const result = await runCommand(
    'git',
    ['clone', '--depth=1', '--single-branch', '--no-tags', remoteUrl, cloneTarget],
    { timeoutMs: config.scanTimeoutMs },
  )
  if (result.code !== 0) {
    await rm(tmpBase, { recursive: true, force: true })
    return { dir: '', reason: result.killedByTimeout ? 'clone_timeout' : 'clone_failed' }
  }
  return { dir: cloneTarget, reason: 'ok', cleanupRoot: tmpBase }
}

async function collectRepoContextFromFiles(repoDir, maxFiles = MAX_REPO_FILES) {
  const queue = ['.']
  const chunks = []
  let scannedFiles = 0

  while (queue.length > 0 && scannedFiles < maxFiles) {
    const relative = queue.shift()
    const absolute = path.join(repoDir, relative)
    let entries = []
    try {
      entries = await readdir(absolute, { withFileTypes: true })
    } catch {
      continue
    }

    for (const entry of entries) {
      if (scannedFiles >= maxFiles) break
      const nextRelative = path.join(relative, entry.name)
      const normalized = nextRelative.replace(/\\/g, '/')

      if (entry.isDirectory()) {
        if (
          normalized.includes('/.git') ||
          normalized.includes('/node_modules') ||
          normalized.includes('/dist') ||
          normalized.includes('/build')
        ) {
          continue
        }
        queue.push(nextRelative)
        continue
      }

      if (!entry.isFile() || !isInterestingCodeFile(normalized)) continue
      const absoluteFile = path.join(repoDir, nextRelative)
      let fileStats
      try {
        fileStats = await stat(absoluteFile)
      } catch {
        continue
      }
      if (!fileStats || fileStats.size > MAX_FILE_BYTES) continue

      try {
        const content = await readFile(absoluteFile, 'utf8')
        if (!content.trim()) continue
        scannedFiles += 1
        chunks.push(`// FILE: ${normalized}\n${content.slice(0, 3000)}\n`)
      } catch {
        // continue
      }
    }
  }

  return { content: chunks.join('\n'), scannedFiles }
}

function inferArchitecturalRisks(contextText) {
  const findings = []
  const text = contextText || ''

  const looksLikeLaravel = /laravel|eloquent|artisan|php/i.test(text)
  const hasCreditOrPii = /credito|credit|cliente|customer|dni|ruc|financial|financiero|lead/i.test(text)
  const mentionsMultiBranch = /multi[-\s]?sucursal|branch_id|sucursal|tenant|multi[-\s]?tenant/i.test(text)
  const mentionsWebhookFlow = /manychat|webhook|whatsapp|meta api|wa api/i.test(text)

  if (looksLikeLaravel && hasCreditOrPii) {
    findings.push({
      id: 'INF-001',
      tool: 'heuristic-inference',
      title: 'Almacenamiento inseguro de PII y datos financieros',
      severity: 'high',
      line: 0,
      description:
        'Riesgo inferido por contexto del repositorio: el sistema parece manejar datos sensibles y podria no cifrar atributos criticos en base de datos.',
      recommendation:
        'En Laravel, cifra atributos sensibles con casts (encrypted) y protege secretos con variables de entorno/gestor de secretos.',
      evidenceType: 'inferred',
    })
  }

  if (mentionsMultiBranch) {
    findings.push({
      id: 'INF-002',
      tool: 'heuristic-inference',
      title: 'Riesgo de IDOR en entorno multi-sucursal',
      severity: 'medium',
      line: 0,
      description:
        'Riesgo inferido: en sistemas multi-sucursal es comun exponer registros de otra sucursal si no existe control de acceso por tenant/branch.',
      recommendation:
        'Aplica Policies/Guards + filtros por branch_id en cada query para asegurar aislamiento de datos por sucursal.',
      evidenceType: 'inferred',
    })
  }

  if (mentionsWebhookFlow) {
    findings.push({
      id: 'INF-003',
      tool: 'heuristic-inference',
      title: 'Falta de validacion de firma en Webhooks',
      severity: 'medium',
      line: 0,
      description:
        'Riesgo inferido: si hay recepcion de eventos externos (webhooks), sin firma/token se pueden inyectar eventos falsos.',
      recommendation:
        'Verifica firma HMAC o token secreto en cada webhook y registra rechazos en auditoria.',
      evidenceType: 'inferred',
    })
  }

  return findings
}

function runHeuristicVulns(sourceText) {
  const vulnerabilities = []
  for (const rule of VULN_PATTERNS) {
    const match = sourceText.match(rule.regex)
    if (!match) continue
    vulnerabilities.push({
      id: rule.id,
      tool: 'heuristic-regex',
      title: rule.title,
      severity: rule.severity,
      line: countLinesUntil(sourceText, match.index ?? 0),
      description: `Patron detectado por regla local: ${rule.title}.`,
      recommendation: rule.recommendation,
      evidenceType: 'heuristic',
    })
  }
  return vulnerabilities
}

function runHeuristicLicenses(sourceText) {
  const licenses = []
  for (const l of LICENSE_PATTERNS) {
    if (!l.regex.test(sourceText)) continue
    licenses.push({
      name: l.name,
      risk: l.risk,
      status: l.status,
      description: l.description,
      tool: 'heuristic-regex',
    })
  }
  return licenses
}

async function runGitleaksScan(repoDir) {
  if (!(await commandExists('gitleaks'))) return []
  const result = await runCommand(
    'gitleaks',
    ['detect', '--source', repoDir, '--report-format', 'json', '--redact', '--exit-code', '0'],
    { cwd: repoDir, timeoutMs: config.scanTimeoutMs },
  )
  if (result.code !== 0 && !result.stdout) return []
  const parsed = safeJsonParse(result.stdout)
  if (!Array.isArray(parsed)) return []

  return parsed.map((item, index) => ({
    id: `GL-${index + 1}`,
    tool: 'gitleaks',
    title: item?.RuleID || 'Hardcoded secret detected',
    severity: 'high',
    line: Number(item?.StartLine || 0),
    file: item?.File || '',
    description: item?.Description || 'Secret pattern detected by gitleaks.',
    recommendation:
      'Rotar el secreto comprometido y moverlo a variables de entorno / gestor de secretos.',
    evidenceType: 'direct',
  }))
}

async function runSemgrepScan(repoDir) {
  if (!(await commandExists('semgrep'))) return []
  const result = await runCommand('semgrep', ['--config=auto', '--json', repoDir], {
    cwd: repoDir,
    timeoutMs: config.scanTimeoutMs,
  })
  if (!result.stdout) return []
  const parsed = safeJsonParse(result.stdout)
  if (!parsed || !Array.isArray(parsed.results)) return []

  return parsed.results.map((item, index) => ({
    id: item?.check_id || `SEMGREP-${index + 1}`,
    tool: 'semgrep',
    title: item?.extra?.message || item?.check_id || 'Semgrep finding',
    severity: mapSeverity(item?.extra?.severity),
    line: Number(item?.start?.line || 0),
    file: item?.path || '',
    description: item?.extra?.message || 'Potential vulnerability detected by Semgrep.',
    recommendation: 'Revisa el finding de Semgrep y aplica mitigacion especifica al flujo afectado.',
    evidenceType: 'direct',
  }))
}

async function runOsvScan(repoDir) {
  if (!(await commandExists('osv-scanner'))) return []
  const result = await runCommand('osv-scanner', ['scan', '--recursive', '--format', 'json', repoDir], {
    cwd: repoDir,
    timeoutMs: config.scanTimeoutMs,
  })
  if (!result.stdout) return []
  const parsed = safeJsonParse(result.stdout)
  if (!parsed) return []

  const findings = []
  const grouped = Array.isArray(parsed.results) ? parsed.results : []
  for (const pkg of grouped) {
    const vulns = Array.isArray(pkg?.packages?.[0]?.vulnerabilities)
      ? pkg.packages[0].vulnerabilities
      : []
    for (const vuln of vulns) {
      findings.push({
        id: vuln?.id || `OSV-${findings.length + 1}`,
        tool: 'osv-scanner',
        title: `Vulnerabilidad en dependencia ${pkg?.packages?.[0]?.package?.name || ''}`.trim(),
        severity: 'high',
        line: 0,
        file: pkg?.source?.path || '',
        description: `Dependencia vulnerable detectada por OSV: ${vuln?.id || 'unknown'}.`,
        recommendation: 'Actualiza la dependencia afectada y revisa advisories relacionados.',
        evidenceType: 'direct',
      })
    }
  }

  return findings
}

async function runTrivyScan(repoDir) {
  if (!(await commandExists('trivy'))) return { vulnerabilities: [], licenses: [] }
  const result = await runCommand(
    'trivy',
    ['fs', '--format', 'json', '--scanners', 'vuln,misconfig,secret,license', '--quiet', repoDir],
    { cwd: repoDir, timeoutMs: config.scanTimeoutMs },
  )
  if (!result.stdout) return { vulnerabilities: [], licenses: [] }
  const parsed = safeJsonParse(result.stdout)
  if (!parsed || !Array.isArray(parsed.Results)) return { vulnerabilities: [], licenses: [] }

  const vulnerabilities = []
  const licenses = []

  for (const res of parsed.Results) {
    if (Array.isArray(res.Vulnerabilities)) {
      for (const vuln of res.Vulnerabilities) {
        vulnerabilities.push({
          id: vuln?.VulnerabilityID || `TRIVY-${vulnerabilities.length + 1}`,
          tool: 'trivy',
          title: vuln?.Title || vuln?.PkgName || 'Dependency vulnerability',
          severity: mapSeverity(vuln?.Severity),
          line: 0,
          file: res?.Target || '',
          description: vuln?.Description || 'Vulnerability detected by Trivy.',
          recommendation: `Actualiza ${vuln?.PkgName || 'la dependencia'} a una version segura.`,
          evidenceType: 'direct',
        })
      }
    }
    if (Array.isArray(res.Licenses)) {
      for (const lic of res.Licenses) {
        const name = String(lic?.License || '').toUpperCase()
        licenses.push({
          name: lic?.License || 'Unknown',
          risk: name.includes('GPL') || name.includes('AGPL') ? 'high' : 'low',
          status: name.includes('GPL') || name.includes('AGPL') ? 'Peligro legal' : 'Seguro',
          description: `Licencia detectada por Trivy en ${res?.Target || 'artefacto escaneado'}.`,
          tool: 'trivy',
        })
      }
    }
  }

  return { vulnerabilities, licenses }
}

async function summarizeWithOllama(context) {
  const ollamaUrl = process.env.OLLAMA_URL || 'http://127.0.0.1:11434'
  const model = process.env.OLLAMA_MODEL || ''
  if (!model) return null

  const prompt = [
    'Eres un auditor DevSecOps. Resume en 2 lineas en espanol:',
    `Tipo de entrada: ${context.inputType}`,
    `Vulnerabilidades: ${context.vulnerabilities.length}`,
    `Licencias detectadas: ${context.licenses.length}`,
    `Health score: ${context.healthScore}/100`,
  ].join('\n')

  const res = await fetchWithTimeout(`${ollamaUrl}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, prompt, stream: false }),
  })
  if (!res.ok) return null
  const data = await res.json()
  return data?.response?.trim() || null
}

function dedupeById(items) {
  const seen = new Set()
  const output = []
  for (const item of items) {
    const key = `${item.tool || 'na'}:${item.id || item.title}`
    if (seen.has(key)) continue
    seen.add(key)
    output.push(item)
  }
  return output
}

function dedupeLicenses(items) {
  const seen = new Set()
  const output = []
  for (const lic of items) {
    const key = `${lic.name}:${lic.tool || 'na'}`
    if (seen.has(key)) continue
    seen.add(key)
    output.push(lic)
  }
  return output
}

export async function analyzeInput({ inputType, inputValue, policies }) {
  let sourceText = inputValue
  let repoReadmeText = ''
  let scannedFiles = 0
  let repoReason = 'n/a'
  let repoDir = ''
  let cleanupRoot = ''

  const toolsUsed = ['heuristic-regex', 'heuristic-inference']
  const requiredScanners = parseRequiredScanners()
  const toolAvailability = await getToolAvailability(requiredScanners)
  const missingRequiredTools = requiredScanners.filter((tool) => !toolAvailability[tool])

  try {
    if (inputType === 'repo') {
      const clone = await cloneRepoToTmp(inputValue)
      repoReason = clone.reason
      if (clone.dir) {
        repoDir = clone.dir
        cleanupRoot = clone.cleanupRoot || ''
        const localSample = await collectRepoContextFromFiles(repoDir, MAX_REPO_FILES)
        if (localSample.content) {
          sourceText = localSample.content
          scannedFiles = localSample.scannedFiles
          repoReason = 'ok_local_clone'
        }
      } else {
        const repoSample = await fetchRepoCodeSample(inputValue)
        scannedFiles = repoSample.scannedFiles
        repoReason = repoSample.reason
        if (repoSample.content) sourceText = repoSample.content
      }

      repoReadmeText = await fetchGithubReadme(inputValue)
      if (!sourceText && repoReadmeText) {
        sourceText = repoReadmeText
        repoReason = `${repoReason}_fallback_readme`
      }
    }

    let vulnerabilities = runHeuristicVulns(sourceText)
    let licenses = runHeuristicLicenses(sourceText)

    if (inputType === 'repo') {
      const inferred = inferArchitecturalRisks(`${repoReadmeText}\n${sourceText}`)
      vulnerabilities = vulnerabilities.concat(inferred)
    }

    if (repoDir) {
      const [gitleaksFindings, semgrepFindings, osvFindings, trivyResult] = await Promise.all([
        runGitleaksScan(repoDir),
        runSemgrepScan(repoDir),
        runOsvScan(repoDir),
        runTrivyScan(repoDir),
      ])

      if (gitleaksFindings.length > 0) toolsUsed.push('gitleaks')
      if (semgrepFindings.length > 0) toolsUsed.push('semgrep')
      if (osvFindings.length > 0) toolsUsed.push('osv-scanner')
      if (trivyResult.vulnerabilities.length > 0 || trivyResult.licenses.length > 0) {
        toolsUsed.push('trivy')
      }

      vulnerabilities = vulnerabilities
        .concat(gitleaksFindings)
        .concat(semgrepFindings)
        .concat(osvFindings)
        .concat(trivyResult.vulnerabilities)
      licenses = licenses.concat(trivyResult.licenses)
    }

    if (inputType === 'repo' && missingRequiredTools.length > 0) {
      for (const missing of missingRequiredTools) {
        vulnerabilities.push({
          id: `COVERAGE-${missing.toUpperCase()}`,
          tool: 'engine-coverage',
          title: `Cobertura incompleta: falta ${missing}`,
          severity: 'medium',
          line: 0,
          description:
            `El entorno no tiene ${missing} instalado; la auditoria de seguridad/supply-chain queda parcialmente cubierta.`,
          recommendation:
            `Instala ${missing} en el runtime de escaneo para habilitar deteccion completa y reducir falsos negativos.`,
          evidenceType: 'heuristic',
        })
      }
    }

    vulnerabilities = dedupeById(vulnerabilities)
    licenses = dedupeLicenses(licenses)

    let rawHealthScore = 100
    for (const vuln of vulnerabilities) rawHealthScore -= scorePenalty(vuln)
    if (licenses.some((l) => l.risk === 'high')) rawHealthScore -= 15
    if (inputType === 'repo' && scannedFiles === 0 && vulnerabilities.length === 0) {
      rawHealthScore = Math.min(rawHealthScore, 70)
    }
    rawHealthScore = clamp(rawHealthScore, 0, 100)

    const directCount = vulnerabilities.filter((v) => v.evidenceType === 'direct').length
    const totalFindings = vulnerabilities.length
    const coverageRatio = inputType === 'repo' ? clamp(scannedFiles / MAX_REPO_FILES, 0, 1) : 1
    const toolCoverageRatio =
      requiredScanners.length > 0
        ? clamp((requiredScanners.length - missingRequiredTools.length) / requiredScanners.length, 0, 1)
        : 1
    const directEvidenceRatio =
      totalFindings > 0 ? clamp(directCount / totalFindings, 0, 1) : toolCoverageRatio
    const confidence = clamp(
      0.2 + 0.4 * toolCoverageRatio + 0.25 * coverageRatio + 0.15 * directEvidenceRatio,
      0,
      1,
    )
    const confidenceAdjustedScore = clamp(Math.round(rawHealthScore * (0.7 + 0.3 * confidence)), 0, 100)
    const healthScore = confidenceAdjustedScore

    const context = { inputType, vulnerabilities, licenses, healthScore }
    let explanation = buildFallbackSummary({
      inputType,
      vulnCount: vulnerabilities.length,
      licenseCount: licenses.length,
      hasHighRiskLicense: licenses.some((l) => l.risk === 'high'),
    })

    try {
      const aiSummary = await summarizeWithOllama(context)
      if (aiSummary) explanation = aiSummary
    } catch {
      // keep deterministic explanation
    }

    if (inputType === 'repo' && scannedFiles === 0) {
      explanation = `${explanation} Advertencia: no se pudieron leer archivos fuente del repo (${repoReason}).`
    } else if (inputType === 'repo') {
      explanation = `${explanation} Se analizaron ${scannedFiles} archivos del repositorio.`
    }
    if (missingRequiredTools.length > 0) {
      explanation = `${explanation} Cobertura parcial: faltan scanners requeridos (${missingRequiredTools.join(', ')}).`
    }

    const policyWarnings = []
    const hardcodedPolicy = policies.find((p) => p.id === 'pol_1' && p.active)
    if (hardcodedPolicy && vulnerabilities.some((v) => v.id === 'VULN-002' || v.tool === 'gitleaks')) {
      policyWarnings.push('Violacion de politica: secretos hardcodeados detectados.')
    }
    const owaspPolicy = policies.find((p) => p.id === 'pol_2' && p.active)
    if (
      owaspPolicy &&
      vulnerabilities.some((v) => ['high', 'critical'].includes(String(v.severity).toLowerCase()))
    ) {
      policyWarnings.push('Violacion de politica: existen vulnerabilidades high/critical.')
    }
    const licensePolicy = policies.find((p) => p.id === 'pol_3' && p.active)
    if (licensePolicy && licenses.some((l) => l.risk === 'high')) {
      policyWarnings.push('Violacion de politica: licencia copyleft fuerte detectada.')
    }
    if (missingRequiredTools.length > 0) {
      policyWarnings.push(
        `Cobertura incompleta: faltan scanners requeridos (${missingRequiredTools.join(', ')}).`,
      )
    }

    return {
      healthScore,
      explanation,
      vulnerabilities,
      licenses,
      meta: {
        engine: 'local-oss-orchestrator',
        llm: process.env.OLLAMA_MODEL ? `ollama:${process.env.OLLAMA_MODEL}` : 'none',
        tools: Array.from(new Set(toolsUsed)),
        requiredScanners,
        missingRequiredTools,
        scoreBreakdown: {
          rawHealthScore,
          confidenceAdjustedScore,
          confidence,
          coverageRatio,
          toolCoverageRatio,
          directEvidenceRatio,
        },
        policyWarnings,
        scannedFiles,
        repoReason,
      },
    }
  } finally {
    if (cleanupRoot) {
      await rm(cleanupRoot, { recursive: true, force: true }).catch(() => {})
    }
  }
}
