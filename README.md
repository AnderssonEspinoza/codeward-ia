# CodeGuard AI

Asistente de code review orientado a seguridad y compliance, con arquitectura real:
API + worker + cola + PostgreSQL + Redis.

## Stack

- Frontend: React + Vite + Tailwind
- Backend: Node.js + Express
- Worker: BullMQ
- DB: PostgreSQL
- Cola: Redis
- Explicacion opcional: Ollama local
- Auth: GitHub OAuth + session server-side

## Estado del analisis (honesto)

- `direct`: hallazgos confirmados por scanner/tool.
- `heuristic`: hallazgos por reglas locales regex.
- `inferred`: riesgos arquitectonicos inferidos por contexto.

Si un escaneo real falla, la UI muestra error. El modo demo con datos simulados es manual.
Si inicias sesión con GitHub, historial y políticas quedan aislados por usuario.

## Deteccion actual

- Heuristico local (siempre disponible)
- Gitleaks (si esta instalado en el host)
- Semgrep (si esta instalado en el host)
- OSV-Scanner (si esta instalado en el host)
- Trivy (si esta instalado en el host)

## Instalacion

```bash
pnpm install
cp .env.example .env
```

## Infra local

```bash
docker compose up -d
```

## Ejecutar

```bash
pnpm run dev:full
```

Comandos separados:

```bash
pnpm run api
pnpm run worker
pnpm run dev
```

## GitHub OAuth (real)

1. Crea una OAuth App en GitHub.
2. Configura callback URL: `http://localhost:8787/auth/github/callback`
3. Completa en `.env`:

```bash
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GITHUB_CALLBACK_URL=http://localhost:8787/auth/github/callback
FRONTEND_URL=http://localhost:5173
SESSION_SECRET=un-secreto-largo
```

Si no defines `GITHUB_CLIENT_ID` y `GITHUB_CLIENT_SECRET`, la app funciona en modo invitado.

## Variables de entorno

- `ADMIN_KEY`: opcional para editar políticas en modo invitado (`x-admin-key`)
- `SCAN_TIMEOUT_MS`: timeout para tareas externas/scanners
- `MAX_REPO_SIZE_KB`: limite de tamano de repo para escaneo
- `VITE_ADMIN_KEY`: key usada por UI para editar políticas en modo invitado local
- `CORS_ORIGINS`: orígenes permitidos para API
- `FRONTEND_URL`: URL del frontend para redirects OAuth
- `SESSION_SECRET`: secreto para cookies de sesión
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`: OAuth
- `GITHUB_TOKEN` (opcional): reduce limites de GitHub API
- `OLLAMA_MODEL`, `OLLAMA_URL` (opcionales)

## Endpoints

- `GET /api/health`
- `GET /api/me`
- `GET /auth/github`
- `GET /auth/github/callback`
- `POST /auth/logout`
- `POST /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/scans/:scanId/export?format=json|sarif|markdown`
- `GET /api/history`
- `GET /api/policies`
- `PUT /api/policies` (sesión GitHub o `x-admin-key` en modo invitado)

## Exportes

- JSON
- SARIF 2.1.0
- Markdown

## Licencia

MIT. Ver [LICENSE](./LICENSE).
