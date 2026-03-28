# CodeGuard AI (Frontend + Backend OSS)

Proyecto de portafolio orientado a auditoria de codigo con enfoque DevSecOps.

## Stack

- Frontend: React + Vite + Tailwind
- Backend: Node.js + Express (API) + BullMQ (worker)
- Persistencia: PostgreSQL
- Cola de trabajos: Redis
- Analisis: reglas locales OSS (sin API paga)
- IA opcional: Ollama local (`OLLAMA_MODEL`)

## Requisitos

- Node.js 20+
- pnpm

## Instalacion

```bash
pnpm install
cp .env.example .env
```

Por defecto usa Postgres en `localhost:55432` para evitar conflicto con instalaciones locales en `5432`.

## Levantar infraestructura (PostgreSQL + Redis)

```bash
docker compose up -d
```

## Ejecutar app completa

Frontend + API + worker en paralelo:

```bash
pnpm run dev:full
```

Comandos por separado:

```bash
pnpm run api      # backend en http://localhost:8787
pnpm run worker   # worker de escaneo
pnpm run dev      # frontend en http://localhost:5173
```

## Variables opcionales (Ollama local)

Si tienes Ollama instalado y quieres resumen IA local:

```bash
export OLLAMA_MODEL=qwen2.5-coder:7b
export OLLAMA_URL=http://127.0.0.1:11434
pnpm run api
pnpm run worker
```

Si no configuras estas variables, el backend usa resumen deterministico local.

## Endpoints backend

- `GET /api/health`
- `GET /api/policies`
- `PUT /api/policies`
- `GET /api/history`
- `POST /api/scans`
- `GET /api/scans/:scanId`

## Nota

Este MVP evita costos de APIs pagas y demuestra arquitectura backend real (API + worker + cola + base de datos + analisis).
