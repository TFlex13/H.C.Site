# Highline Connect Platform

Local-only backend foundation for the Highline Connect representative and administration portals. The existing Jekyll public website remains independent.

## Prerequisites
- Node.js 22+
- pnpm 9.x
- Docker Desktop with Docker Compose

## First run (PowerShell)
From the repository root:

```powershell
Set-Location .\platform
Copy-Item .env.example .env
pnpm.cmd install
docker compose up -d
pnpm.cmd typecheck
pnpm.cmd dev
```

Visit http://127.0.0.1:3002/health and http://127.0.0.1:3002/health/db. The API binds to loopback only. PostgreSQL is exposed on 127.0.0.1:5434, to avoid conflicts with other local projects.

## Current scope
- Fastify API skeleton with /health and /health/db
- Local PostgreSQL via Docker Compose
- No authentication, user accounts, orders, migrations, or admin UI yet

## Security and deployment
The .env file is ignored by Git. The example database password is for isolated local development only; never reuse it in production. Before deploying, implement authentication, authorization, schema migrations, secrets management, TLS, audit logs, and backups. Do not expose the development API to the internet.
