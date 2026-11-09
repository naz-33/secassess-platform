# AI-Assisted Security Assessment and Vulnerability Analysis Platform (SecAssess)

> **University Capstone / Security Engineering Project**  
> A modular platform combining automated reconnaissance, web vulnerability assessment, human-in-the-loop assessor review, and AI-assisted vulnerability analysis.

---

## Ethical & Authorized Use Warning

> [!WARNING]
> **Ethical & Authorized Testing Only:**  
> This platform contains and orchestrates security testing tools (Nmap, OWASP ZAP, network probes). It is strictly intended for educational and research usage against instructor-approved local targets (such as the included OWASP Juice Shop container). Testing against any unauthorized third-party target without written consent is illegal and strictly prohibited.

---

## 1. Architectural Overview

SecAssess is built as a **modular monolith**:
- **Single Deployable Backend**: A single FastAPI service with strict internal module isolation under `backend/app/modules/`.
- **Public API Encapsulation**: Modules communicate strictly through public services (`service.py` / `__init__.py`). Direct imports of another module's `models.py`, `repository.py`, or `router.py` are strictly prohibited and enforced via automated AST boundary tests (`tests/test_module_boundaries.py`).
- **Database Boundary Rules**: Cross-module database relationships use plain foreign keys without cross-module SQLAlchemy `relationship()` couplings.
- **Enforced Target Scope**: All scanning and reconnaissance tools must invoke `ScopeManager.assert_in_scope()` from the `targets` module before initiating network traffic.
- **Decoupled Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Recharts, and React Router with feature-based architecture mirroring backend modules.

See [`backend/ARCHITECTURE.md`](backend/ARCHITECTURE.md) for full module boundaries, table ownership details, and an ASCII dependency diagram.

---

## 2. Target Repository Layout

```text
secassess/
├── backend/
│   ├── alembic/                # Database migrations (env.py auto-discovers all 12 tables)
│   ├── alembic.ini
│   ├── app/
│   │   ├── core/               # Domain-agnostic config, DB engine, security, logging, deps
│   │   ├── main.py             # FastAPI app factory mounting all routers under /api/v1
│   │   └── modules/            # 12 Self-contained domain modules
│   │       ├── auth/           # Users, credentials, roles (admin / assessor)
│   │       ├── audit/          # Audit trail logging
│   │       ├── targets/        # Target definition + ScopeManager (mandatory boundary enforcement)
│   │       ├── assessments/    # Assessment cycles
│   │       ├── scans/          # Automated tool execution jobs and raw outputs
│   │       ├── recon/          # Nmap and DNS runners & parsers -> assets
│   │       ├── web_assessment/ # OWASP ZAP, curl, and TLS check runners & parsers
│   │       ├── findings/       # Vulnerabilities and evidence records
│   │       ├── ai_analysis/    # Redacted LLM prompting, prompts/, and analysis records
│   │       ├── verification/   # Assessor decision workflow (confirmed, false-positive)
│   │       ├── reporting/      # Document generators (PDF/DOCX stubs) and HTML templates
│   │       └── dashboard/      # Read-only aggregation metrics for frontend charts
│   ├── scripts/
│   │   └── seed.py             # Idempotent database seeder (admin, assessor, OWASP Juice Shop)
│   ├── tests/
│   │   ├── test_health.py      # Health & DB connectivity check, OpenAPI docs validation
│   │   └── test_module_boundaries.py  # Static AST import boundary enforcement test
│   ├── ARCHITECTURE.md
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/                # Layout (AppShell + API status indicator), router, providers
│   │   ├── features/           # Feature slices with pages/, components/, api.ts, index.ts
│   │   │   ├── auth/           # Login screen
│   │   │   ├── dashboard/      # Recharts vulnerability severity visualization
│   │   │   ├── targets/        # Target and in-scope / out-of-scope asset tables
│   │   │   ├── assessments/    # Assessment cycle management
│   │   │   ├── scans/          # Tool job logs
│   │   │   ├── findings/       # Vulnerability list and detail
│   │   │   ├── verification/   # Human-in-the-loop review actions
│   │   │   ├── ai/             # AI-generated analysis panels
│   │   │   └── reports/        # Report export screen
│   │   ├── shared/             # API Axios client, base UI components, types
│   │   ├── main.tsx
│   │   └── index.css           # Tailwind entry
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── docker-compose.yml          # Postgres 16, Backend, Frontend, and optional target containers
├── Makefile                    # Standard orchestration commands
├── .env.example                # Sample environment configuration
└── README.md
```

---

## 3. Prerequisites

- **Docker & Docker Compose** (or local Python 3.12+, Node.js 20+, PostgreSQL 16+)
- **Make** (optional, recommended)

---

## 4. Quick Start

### Option A: Using Docker Compose & Makefile

```bash
# 1. Clone repository and copy sample environment
cp .env.example .env
# Set GEMINI_API_KEY and ZAP_API_KEY in .env before enabling AI/ZAP features.

# 2. Build and start core containers (Postgres, Backend, Frontend)
make up

# 3. Apply database migrations (creates all 12 tables)
make migrate

# 4. Seed initial accounts and sample target (OWASP Juice Shop)
make seed

# (Optional) Start lab target containers (OWASP Juice Shop & OWASP ZAP daemon)
make up-targets
```

The backend reaches ZAP at `http://zap:8080` on the Compose network. If running the
backend directly on the host instead, set `ZAP_API_URL=http://localhost:8080`.
Set `GEMINI_API_KEY` to enable interpretation and `AI_ENABLED=true` to allow AI calls.

### Option B: Local Development (Without Docker)

1. **Database Setup**:
   Ensure PostgreSQL is running locally on port 5432 with database `secassess` (as configured in `.env`).

2. **Backend**:
   ```bash
   cd backend
   python -m venv .venv
   source .venv/bin/activate  # Or on Windows: .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   alembic upgrade head
   python scripts/seed.py
   uvicorn app.main:app --reload --port 8000
   ```

3. **Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

---

## 5. Service URLs & Default Credentials

| Service | URL | Notes |
|---|---|---|
| **Frontend App** | `http://localhost:5173` | Dashboard, Recharts visualization, API health indicator |
| **API Docs (Swagger)** | `http://localhost:8000/docs` | Interactive OpenAPI documentation for all 12 modules |
| **API Health Check** | `http://localhost:8000/api/v1/health` | Validates app state & `SELECT 1` DB connection |
| **Juice Shop Target** | `http://localhost:3000` | (When started with `--profile targets`) |
| **ZAP Daemon API** | `http://localhost:8080` | Host-published URL; backend uses `http://zap:8080` in Docker |

### Synthetic Seed Credentials
- **Admin**: `admin@secassess.local` / `AdminSecurePassword123!`
- **Assessor**: `assessor@secassess.local` / `AssessorSecurePassword123!`

---

## 6. How to Add a New Backend Module

To maintain the modular monolith architecture:
1. Create a folder under `backend/app/modules/<new_module>/`.
2. Implement the standard module structure:
   - `models.py`: SQLAlchemy models inheriting from `app.core.database.Base`.
   - `repository.py`: Data-access methods encapsulating queries.
   - `schemas.py`: Pydantic models for request validation and response serialization.
   - `service.py`: Public business logic API.
   - `router.py`: `APIRouter` with prefix `/<new_module>` and tags `["<new_module>"]`.
   - `__init__.py`: Export **only** the `Service` class.
3. Register the model in `backend/app/core/db_models.py`.
4. Mount the router in `backend/app/main.py` under `/api/v1`.
5. Generate an Alembic migration: `alembic revision --autogenerate -m "add_<new_module>"` and run `alembic upgrade head`.
6. Run `pytest` to verify `test_module_boundaries.py` confirms no illegal cross-module imports.

---

## 7. Verification & Testing Commands

```bash
# Run backend unit tests and static module boundary checks
pytest

# Run Python linter
ruff check .

# Test frontend build
cd frontend && npm run build
```
