# RMF Forge

**Air-gapped DoD RMF compliance scan consolidation tool.**

Ingests Fortify (.fpr), OWASP ZAP, CSV, and Excel scan outputs — consolidates them into an eMASS-ready Excel workbook, generates ASD STIG checklists (.ckl + XCCDF), and maps ZAP findings to CCIs for eMASS bulk upload.

**Zero network egress. CUI-safe by architecture. No API calls.**

---

## Features

| Module | Description |
|--------|-------------|
| Scan Consolidation | Merge .fpr, .csv, .xlsx across tools with fuzzy column matching |
| ASD STIG Export | Generate STIG Viewer .ckl and XCCDF XML from findings |
| ZAP → CCI Mapper | Map OWASP ZAP CWE/CVEs to CCIs for eMASS bulk upload |
| Persistent Projects | SQLite-backed workspaces — justification comments survive re-imports |

---

## Quick Start (Dev)

```bash
git clone https://github.com/yourusername/rmf-forge.git
cd rmf-forge

# Add DoD reference data (see below)
cp /path/to/ASD_STIG.xml backend/data/stig/
cp /path/to/U_CCI_List.xml backend/data/cci/

# Start everything
docker compose up --build
```

Frontend: http://localhost:3000  
API docs: http://localhost:8000/api/docs

---

## Production (Docker Hub images)

```bash
cp .env.example .env
# Edit .env with your SECRET_KEY and DOCKERHUB_USERNAME

docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## Required DoD Reference Data

These files are not bundled due to DoD distribution requirements.
Download from [DoD Cyber Exchange](https://public.cyber.mil/stigs/):

| File | Destination | Source |
|------|-------------|--------|
| ASD STIG XCCDF | `backend/data/stig/ASD_STIG.xml` | STIGS > Application Security and Development |
| CCI List | `backend/data/cci/U_CCI_List.xml` | STIGS > CCI |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker network: rmf-internal (no internet egress)  │
│                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌───────┐  │
│  │   Frontend   │───▶│   Backend    │───▶│  DB   │  │
│  │  React/TS    │    │  FastAPI     │    │  PG   │  │
│  │  Nginx :80   │    │  Python :8000│    │ :5432 │  │
│  └──────────────┘    └──────────────┘    └───────┘  │
│                             │                        │
│                    ┌────────┴────────┐               │
│                    │ Bundled assets  │               │
│                    │ ASD STIG XCCDF  │               │
│                    │ CCI List XML    │               │
│                    │ CWE→CCI index   │               │
│                    └─────────────────┘               │
└─────────────────────────────────────────────────────┘
```

---

## GitHub Actions

- **CI** — runs on every push/PR: backend pytest, frontend lint
- **Release** — push a `vX.Y.Z` tag to build and push images to Docker Hub

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## Secrets (GitHub → Settings → Secrets)

| Secret | Value |
|--------|-------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token (not your password) |

---

## Tech Stack

- **Frontend:** React 18 + TypeScript + Vite, served by Nginx
- **Backend:** Python 3.12 + FastAPI + SQLAlchemy
- **Database:** PostgreSQL 16
- **Container:** Docker + Docker Compose
- **CI/CD:** GitHub Actions → Docker Hub
