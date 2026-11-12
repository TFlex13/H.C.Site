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

## Invitation authentication (local development only)
- Apply SQL: `Get-Content .\\migrations\\001_auth.sql -Raw | docker exec -i highline-postgres psql -U highline -d highline -v ON_ERROR_STOP=1`
- Bootstrap first admin: `pnpm.cmd --filter @highline/api bootstrap-admin` (password input is visible; use a private terminal).
- POST /auth/login with email/password -> bearer token valid for 12 hours.
- GET /auth/me and POST /auth/logout require Authorization: Bearer token.
- POST /admin/invitations requires admin bearer token; accepts email and returns a 48-hour invitation token for **local manual testing only**.
- POST /auth/accept-invitation accepts token, displayName, password (12+ characters).
- No public registration, email delivery, or dashboard UI yet.

## Security and deployment
The .env file is ignored by Git. The example database password is for isolated local development only; never reuse it in production. Before deploying, implement authentication, authorization, schema migrations, secrets management, TLS, audit logs, and backups. Do not expose the development API to the internet.
