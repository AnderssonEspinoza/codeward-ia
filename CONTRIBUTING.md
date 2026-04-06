# Contributing to CodeWard IA

Gracias por querer contribuir.

## Requisitos

- Node.js 20+
- pnpm 9/10
- PostgreSQL y Redis (local con `docker compose up -d` o servicios remotos)

## Setup local

```bash
pnpm install
cp .env.example .env
docker compose up -d
pnpm run dev:full
```

## Flujo recomendado

1. Crea una rama desde `main`:
   - `feat/nombre-cambio`
   - `fix/nombre-bug`
2. Haz cambios pequeños y claros.
3. Ejecuta validaciones:
   - `pnpm run lint`
   - `pnpm run build`
4. Abre PR con:
   - contexto del problema
   - qué cambió
   - cómo se probó

## Estilo de commits

Usa mensajes tipo Conventional-ish:

- `feat: ...`
- `fix: ...`
- `docs: ...`
- `chore: ...`

## Áreas prioritarias para contribuir

- Reglas y adapters de scanners OSS
- Mejora de score de confianza/cobertura
- Tests E2E y observabilidad
- UX de reportes y exportes

## Seguridad

Si encuentras una vulnerabilidad real, no publiques exploit en issues.
Reporta de forma privada al owner del repo.
