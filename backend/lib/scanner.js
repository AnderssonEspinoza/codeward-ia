import process from 'node:process'
import { Buffer } from 'node:buffer'

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
  if (lowered.includes('node_modules/') || lowered.includes('dist/') || lowered.includes('build/')) {
    return false
  }
  return ALLOWED_CODE_EXTENSIONS.has(getFileExtension(filePath))
}

function scorePenaltyBySeverity(severity) {
  if (severity === 'critical') return 30
  if (severity === 'high') return 20
  if (severity === 'medium') return 10
  return 5
}

function scorePenalty(vulnerability) {
  const base = scorePenaltyBySeverity(vulnerability.severity)
  if (vulnerability.evidenceType === 'inferred') {
    return Math.max(4, Math.round(base * 0.5))
  }
  return base
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

  const res = await fetch(`${ollamaUrl}/api/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      prompt,
      stream: false,
    }),
  })

  if (!res.ok) return null

  const data = await res.json()
  return data?.response?.trim() || null
}

async function fetchGithubReadme(repoUrl) {
  const repoPath = parseGithubRepoPath(repoUrl)
  if (!repoPath) return ''
  const res = await fetch(`https://api.github.com/repos/${repoPath}/readme`, {
    headers: buildGithubHeaders(),
  })
  if (!res.ok) return ''

  const payload = await res.json()
  if (!payload?.content) return ''

  const content = Buffer.from(payload.content, 'base64').toString('utf8')
  return content.slice(0, 20000)
}

function parseGithubRepoPath(repoUrl) {
  const match = repoUrl.match(/github\.com\/([^/]+\/[^/\s]+)/i)
  if (!match) return ''
  return match[1].replace(/\.git$/i, '')
}

function buildGithubHeaders() {
  const headers = {
    Accept: 'application/vnd.github+json',
  }

  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  }

  return headers
}

async function fetchRepoCodeSample(repoUrl) {
  const repoPath = parseGithubRepoPath(repoUrl)
  if (!repoPath) {
    return { content: '', scannedFiles: 0, reason: 'invalid_repo_url' }
  }

  const headers = buildGithubHeaders()

  const repoRes = await fetch(`https://api.github.com/repos/${repoPath}`, { headers })
  if (!repoRes.ok) {
    return { content: '', scannedFiles: 0, reason: 'repo_metadata_unavailable' }
  }

  const repoJson = await repoRes.json()
  const defaultBranch = repoJson?.default_branch || 'main'

  const treeRes = await fetch(
    `https://api.github.com/repos/${repoPath}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`,
    { headers },
  )
  if (!treeRes.ok) {
    return { content: '', scannedFiles: 0, reason: 'repo_tree_unavailable' }
  }

  const treeJson = await treeRes.json()
  const tree = Array.isArray(treeJson?.tree) ? treeJson.tree : []

  const candidates = tree
    .filter((entry) => entry.type === 'blob')
    .filter((entry) => isInterestingCodeFile(entry.path))
    .filter((entry) => Number(entry.size || 0) <= MAX_FILE_BYTES)
    .slice(0, MAX_REPO_FILES)

  if (candidates.length === 0) {
    return { content: '', scannedFiles: 0, reason: 'no_candidate_files' }
  }

  const chunks = []
  let scannedFiles = 0

  for (const entry of candidates) {
    if (!entry.url) continue
    try {
      const blobRes = await fetch(entry.url, { headers })
      if (!blobRes.ok) continue
      const blobJson = await blobRes.json()
      if (blobJson.encoding !== 'base64' || !blobJson.content) continue
      const decoded = Buffer.from(blobJson.content, 'base64').toString('utf8')
      if (!decoded.trim()) continue

      scannedFiles += 1
      chunks.push(`// FILE: ${entry.path}\n${decoded.slice(0, 3000)}\n`)
    } catch {
      // Skip unreadable blobs and continue with others.
    }
  }

  return {
    content: chunks.join('\n'),
    scannedFiles,
    reason: scannedFiles > 0 ? 'ok' : 'blob_fetch_failed',
  }
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
      title: 'Almacenamiento inseguro de PII y datos financieros',
      severity: 'high',
      line: 0,
      description:
        'Riesgo inferido por contexto del repositorio: el sistema parece manejar datos sensibles y podria no cifrar atributos criticos en base de datos.',
      recommendation:
        "En Laravel, cifra atributos sensibles con casts (encrypted) y protege secretos con variables de entorno/gestor de secretos.",
      evidenceType: 'inferred',
    })
  }

  if (mentionsMultiBranch) {
    findings.push({
      id: 'INF-002',
      title: 'Riesgo de IDOR en entorno multi-sucursal',
      severity: 'medium',
      line: 0,
      description:
        'Riesgo inferido: en sistemas multi-sucursal es comun exponer registros de otra sucursal si no existe control de acceso por tenant/branch.',
      recommendation:
        "Aplica Policies/Guards + filtros por branch_id en cada query para asegurar aislamiento de datos por sucursal.",
      evidenceType: 'inferred',
    })
  }

  if (mentionsWebhookFlow) {
    findings.push({
      id: 'INF-003',
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

export async function analyzeInput({ inputType, inputValue, policies }) {
  let sourceText = inputValue
  let repoReadmeText = ''
  let scannedFiles = 0
  let repoReason = 'n/a'

  if (inputType === 'repo') {
    try {
      const repoSample = await fetchRepoCodeSample(inputValue)
      scannedFiles = repoSample.scannedFiles
      repoReason = repoSample.reason
      if (repoSample.content) {
        sourceText = repoSample.content
        repoReadmeText = await fetchGithubReadme(inputValue)
      } else {
        const readme = await fetchGithubReadme(inputValue)
        if (readme) {
          sourceText = readme
          repoReadmeText = readme
          repoReason = `${repoReason}_fallback_readme`
        }
      }
    } catch {
      // Keep original URL as text fallback
      repoReason = 'repo_fetch_exception'
    }
  }

  const vulnerabilities = []

  for (const rule of VULN_PATTERNS) {
    const match = sourceText.match(rule.regex)
    if (!match) continue

    const line = countLinesUntil(sourceText, match.index ?? 0)

    vulnerabilities.push({
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      line,
      description: `Patron detectado por regla local: ${rule.title}.`,
      recommendation: rule.recommendation,
      evidenceType: 'direct',
    })
  }

  if (inputType === 'repo') {
    const inferred = inferArchitecturalRisks(`${repoReadmeText}\n${sourceText}`)
    const existingIds = new Set(vulnerabilities.map((v) => v.id))
    for (const f of inferred) {
      if (!existingIds.has(f.id)) vulnerabilities.push(f)
    }
  }

  const licenses = []
  for (const l of LICENSE_PATTERNS) {
    if (!l.regex.test(sourceText)) continue
    licenses.push({
      name: l.name,
      risk: l.risk,
      status: l.status,
      description: l.description,
    })
  }

  let healthScore = 100
  for (const vuln of vulnerabilities) {
    healthScore -= scorePenalty(vuln)
  }
  if (licenses.some((l) => l.risk === 'high')) healthScore -= 15
  if (inputType === 'repo' && scannedFiles === 0 && vulnerabilities.length === 0) {
    // Avoid false "100 green" when we could not read real repository code.
    healthScore = Math.min(healthScore, 70)
  }
  healthScore = Math.max(0, Math.min(100, healthScore))

  const context = {
    inputType,
    vulnerabilities,
    licenses,
    healthScore,
  }

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
    // Keep deterministic explanation when local LLM is unavailable
  }

  if (inputType === 'repo' && scannedFiles === 0) {
    explanation = `${explanation} Advertencia: no se pudieron leer archivos fuente del repo (${repoReason}).`
  } else if (inputType === 'repo') {
    explanation = `${explanation} Se analizaron ${scannedFiles} archivos del repositorio.`
  }

  const policyWarnings = []

  const hardcodedPolicy = policies.find((p) => p.id === 'pol_1' && p.active)
  if (hardcodedPolicy) {
    const hasSecret = vulnerabilities.some((v) => v.id === 'VULN-002')
    if (hasSecret) policyWarnings.push('Violacion de politica: secretos hardcodeados detectados.')
  }

  const owaspPolicy = policies.find((p) => p.id === 'pol_2' && p.active)
  if (owaspPolicy) {
    const hasHighOrCritical = vulnerabilities.some((v) => ['high', 'critical'].includes(v.severity))
    if (hasHighOrCritical) policyWarnings.push('Violacion de politica: existen vulnerabilidades high/critical.')
  }

  const licensePolicy = policies.find((p) => p.id === 'pol_3' && p.active)
  if (licensePolicy) {
    const hasCopyleft = licenses.some((l) => l.risk === 'high')
    if (hasCopyleft) policyWarnings.push('Violacion de politica: licencia copyleft fuerte detectada.')
  }

  return {
    healthScore,
    explanation,
    vulnerabilities,
    licenses,
    meta: {
      engine: 'local-oss-rules',
      llm: process.env.OLLAMA_MODEL ? `ollama:${process.env.OLLAMA_MODEL}` : 'none',
      policyWarnings,
      scannedFiles,
      repoReason,
    },
  }
}
