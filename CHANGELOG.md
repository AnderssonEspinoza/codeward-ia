# Changelog

## v1.0.0 - 2026-04-05

### Added
- API + worker integrado con BullMQ sobre Redis.
- Persistencia en PostgreSQL para scans, políticas y sesiones.
- OAuth GitHub con sesión server-side.
- Exportes de reportes en JSON, SARIF y Markdown.
- Integración OSS en motor de análisis (heurística + Gitleaks + Semgrep + OSV + Trivy opcional).
- Proxy same-origin en Vercel para `/api/*` y `/auth/*`.
- Docker runtime para Render con scanners instalados.
- Smoke test E2E remoto (`pnpm run test:e2e:remote`).

### Changed
- Score de salud ajustado por confianza y cobertura de herramientas.
- Reportes con señalización explícita cuando falta cobertura mínima de scanners.
- README unificado con demo pública y guía de despliegue actualizada.
