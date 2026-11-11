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
│   │       ├── recon/          # Nmap and DNS parsers, asset catalog
│   │       ├── scans/          # Safe Nmap/DNS adapters, execution, and scan lifecycle
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

- **Git** to clone the repository.
- **Docker Desktop** on Windows or macOS, or Docker Engine with the Compose plugin on Linux. Docker Compose v2 is used with the `docker compose` command.
- **PostgreSQL 16 is included in the Docker setup.** You do not need to install PostgreSQL separately unless you choose the native, non-Docker setup below.
- For native development without Docker: Python 3.12+, Node.js 20+, and PostgreSQL 16+.
- **Make** is optional; the commands below work without it.

---

## 4. Run on Your Computer (Recommended: Docker)

These steps work on Windows, macOS, and Linux. On Windows, run the commands in PowerShell. Install and start Docker Desktop first, then wait until it reports that Docker is running.

### Step 1: Install Git and Docker

- Install Git from [git-scm.com](https://git-scm.com/downloads).
- Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) on Windows or macOS. On Linux, install Docker Engine and the Compose plugin by following the [Docker Engine guide](https://docs.docker.com/engine/install/).
- Open a terminal and check that both tools are available:

```text
git --version
docker compose version
```

### Step 2: Clone the GitHub repository

```text
git clone https://github.com/naz-33/secassess-platform.git
cd secassess-platform
```

### Step 3: Create your local environment file

The sample configuration is copied once when setting up a fresh clone. Use the command for your terminal:

```powershell
Copy-Item .env.example .env
```

```bash
cp .env.example .env
```

The Docker setup uses development defaults and does not require an AI API key. To use optional AI or ZAP integrations, edit `.env` and configure the relevant keys (`GEMINI_API_KEY` and/or `ZAP_API_KEY`). Do not share or commit your `.env` file. The sample credentials and secrets are for local development only; replace them before any non-local deployment.

### Step 4: Build and start the application

From the repository root, run:

```text
docker compose up --build -d
```

This builds the frontend and backend containers and starts them with PostgreSQL 16. The backend applies database migrations during startup. You do not need a local PostgreSQL installation or a separate migration command for this setup.

Check that the containers are running:

```text
docker compose ps
```

Wait for the backend to finish its startup migrations. The API health URL below should report `"status": "ok"` and `"database": "ok"` before you continue.

### Step 5: Create the sample accounts and target

After the backend has started, run the idempotent seed script:

```text
docker compose exec backend python scripts/seed.py
```

This creates the sample admin and assessor accounts and registers the OWASP Juice Shop target. The target application itself is optional and is started in the next step.

### Step 6: Open the app and sign in

- Frontend: [http://localhost:5173](http://localhost:5173)
- API health: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) — should report `"status": "ok"` and `"database": "ok"`.
- API documentation: [http://localhost:8000/docs](http://localhost:8000/docs)

Use one of these local demo accounts:

| Role | Email | Password |
|---|---|---|
| Admin | `admin@secassess.local` | `AdminSecurePassword123!` |
| Assessor | `assessor@secassess.local` | `AssessorSecurePassword123!` |

Change these development credentials before using the application beyond your own local machine.

### Optional: Start the local security-testing lab

To also start OWASP Juice Shop and OWASP ZAP, run this from the repository root:

```text
docker compose --profile targets up --build -d
```

Juice Shop is available at [http://localhost:3000](http://localhost:3000). Within Docker, the backend reaches ZAP at `http://zap:8080`; from a host-run backend, use `http://localhost:8080`. Only test systems you own or are explicitly authorized to assess. The included Juice Shop is intentionally vulnerable and is meant for local practice.

### Stop or inspect the application

Follow the service logs:

```text
docker compose logs -f
```

Press `Ctrl+C` to stop viewing logs. To stop the containers:

```text
docker compose down
```

`docker compose down` stops and removes the containers but preserves the PostgreSQL data volume, so your data remains for the next start. Avoid `docker compose down -v` unless you intend to delete that data.

## 5. Native Development (Without Docker)

Use this option only if you do not want Docker. Install Python 3.12+, Node.js 20+, and PostgreSQL 16+. Start PostgreSQL, create a database named `secassess` (for example, in pgAdmin or with `createdb -U postgres secassess`), and create `.env` from `.env.example` as described above. Update the database settings in `.env` to match your local PostgreSQL username and password; `DATABASE_URL` should use this format:

```text
postgresql+psycopg://<user>:<password>@localhost:5432/secassess
```

In PowerShell, install backend dependencies, migrate the database, seed the sample data, and start the API:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
alembic upgrade head
python scripts/seed.py
uvicorn app.main:app --reload --port 8000
```

If PowerShell blocks virtual-environment activation, allow it for the current terminal only, then activate again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux, run these backend commands instead:

```bash
cd backend
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
alembic upgrade head
python scripts/seed.py
uvicorn app.main:app --reload --port 8000
```

Keep the backend running. Open a second terminal at the repository root and start the frontend:

```powershell
cd frontend
npm install
$env:VITE_BACKEND_URL = "http://localhost:8000"
npm run dev
```

On macOS or Linux, set the proxy variable for the frontend command like this:

```bash
cd frontend
npm install
VITE_BACKEND_URL=http://localhost:8000 npm run dev
```

---

## 6. Service URLs

| Service | URL | Notes |
|---|---|---|
| **Frontend App** | `http://localhost:5173` | Dashboard, Recharts visualization, API health indicator |
| **API Docs (Swagger)** | `http://localhost:8000/docs` | Interactive OpenAPI documentation for all 12 modules |
| **API Health Check** | `http://localhost:8000/api/v1/health` | Validates app state & `SELECT 1` DB connection |
| **Juice Shop Target** | `http://localhost:3000` | (When started with `--profile targets`) |
| **ZAP Daemon API** | `http://localhost:8080` | Host-published URL; backend uses `http://zap:8080` in Docker |

---

## 7. How to Add a New Backend Module

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

## 8. Verification & Testing Commands

```bash
# Run backend tests using the isolated secassess_test database
make test

# Opt-in bounded end-to-end checks against local Juice Shop and ZAP only
make test-local-lab

# Run Python linter
ruff check .

# Test frontend build
cd frontend && npm run build
```

Backend tests require `TEST_DATABASE_URL` and fail closed unless it identifies a
separate database whose name contains `test`. `make test` provisions and migrates
the isolated Compose test database; it does not point tests at the application's
database. All AI integrations are disabled or mocked in tests. The local-lab
target leaves ZAP active scanning disabled and never scans public targets.
