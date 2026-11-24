# AI-Assisted Security Assessment Platform (SecAssess)
# Complete Local Setup & Development Guide for Group Members

Welcome to the **SecAssess** project! This guide is written specifically for group members setting up and running this repository on their personal laptops (Windows, macOS, or Linux).

Whether you are working on the backend, frontend, security scanning modules, or report generation, this guide will walk you through every step in chronological order—from cloning the repository to verifying that all services and login accounts work properly.

---

## Table of Contents
1. [Overview & Project Architecture](#1-overview--project-architecture)
2. [A. Prerequisites](#a-prerequisites)
   - [Option 1: Docker-Based Setup (Recommended & Easiest)](#option-1-docker-based-setup-recommended--easiest)
   - [Option 2: Native Setup (Without Docker)](#option-2-native-setup-without-docker)
3. [B. Clone the Repository](#b-clone-the-repository)
4. [C. Environment Configuration](#c-environment-configuration)
   - [Root Environment File (.env)](#1-root-environment-file-env)
   - [Frontend Environment File (frontend/.env)](#2-frontend-environment-file-frontendedv)
   - [Understanding the Key Variables](#3-understanding-the-key-variables)
5. [D. Database Setup](#d-database-setup)
   - [Option 1: Using Docker PostgreSQL (Automatic)](#database-option-1-using-docker-postgresql-automatic)
   - [Option 2: Using Local Native PostgreSQL](#database-option-2-using-local-native-postgresql)
6. [E. Backend Setup](#e-backend-setup)
   - [Native Backend Setup (Step-by-Step)](#native-backend-setup-step-by-step)
   - [Applying Database Migrations](#applying-database-migrations)
   - [Seeding Initial Users and Targets](#seeding-initial-users-and-targets)
   - [Starting the FastAPI Backend Server](#starting-the-fastapi-backend-server)
7. [F. Frontend Setup](#f-frontend-setup)
   - [Installing Node Dependencies](#installing-node-dependencies)
   - [Configuring the API Proxy](#configuring-the-api-proxy)
   - [Starting the Vite Development Server](#starting-the-vite-development-server)
8. [G. Running the Entire Project](#g-running-the-entire-project)
   - [Method 1: The One-Command Docker Setup (Recommended)](#method-1-the-one-command-docker-setup-recommended)
   - [Method 2: Multi-Terminal Native Execution](#method-2-multi-terminal-native-execution)
   - [Service URLs & Default Credentials Quick Reference](#service-urls--default-credentials-quick-reference)
9. [H. Common Errors and Troubleshooting](#h-common-errors-and-troubleshooting)
   - [1. PowerShell Execution Policy Restriction](#1-powershell-execution-policy-restriction)
   - [2. PostgreSQL Database Connection Refused](#2-postgresql-database-connection-refused)
   - [3. Port Already in Use (5432, 8000, 5173, 8081)](#3-port-already-in-use-5432-8000-5173-8081)
   - [4. Frontend Cannot Connect to Backend / Network Error](#4-frontend-cannot-connect-to-backend--network-error)
   - [5. Gemini AI Errors or Scanning Failures](#5-gemini-ai-errors-or-scanning-failures)
   - [6. Test Database Failures When Running Pytest](#6-test-database-failures-when-running-pytest)
10. [I. Verification Checklist](#i-verification-checklist)

---

## 1. Overview & Project Architecture

Before installing anything, here is a quick bird's-eye view of how the project is built:

```
secassess-platform/
├── backend/                  # FastAPI (Python 3.12) Modular Monolith
│   ├── alembic/              # Database migration history (12 domain tables)
│   ├── app/                  # Application core, modules (auth, recon, findings, ai, etc.)
│   ├── scripts/seed.py       # Initial database seeder script
│   └── requirements.txt      # Python dependencies
├── frontend/                 # React 18 + TypeScript + Vite + Tailwind CSS
│   ├── src/                  # App components, layout, API client, feature views
│   └── package.json          # Node.js dependencies
├── targets/                  # Local target applications for safe security testing
│   └── SarangTV-backend/     # Vulnerable Laravel (PHP/MySQL) testing application
├── docker-compose.yml        # Orchestration for PostgreSQL 16, MySQL, Backend, Frontend, Targets
├── Makefile                  # Shortcut commands for Docker workflows
└── .env.example              # Sample environment configuration template
```

The system connects together as follows:
- **Frontend** runs on `http://localhost:5173` (React/Vite).
- **Backend API** runs on `http://localhost:8000` (FastAPI/Uvicorn).
- **Primary Database** runs on `localhost:5432` (PostgreSQL 16).
- **Target Applications**:
  - `http://localhost:8081` — SarangTV (Vulnerable K-drama Watchlist backend).
  - `http://localhost:3000` — OWASP Juice Shop (included in Docker profile `targets`).
  - `http://localhost:8080` — OWASP ZAP Proxy (included in Docker profile `targets`).

---

## A. Prerequisites

Choose the setup path that best fits your machine. **Docker Desktop is strongly recommended** because it packages Python, Node, PostgreSQL, and MySQL into containers with zero version conflicts.

### Option 1: Docker-Based Setup (Recommended & Easiest)

If you use Docker, you only need two tools installed on your host machine:

| Tool | Required Version | Official Download Link | Verification Command |
|---|---|---|---|
| **Git** | Any modern version (2.x+) | [git-scm.com/downloads](https://git-scm.com/downloads) | `git --version` |
| **Docker Desktop** | Docker Engine 24+ & Compose v2+ | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) | `docker compose version` |

> [!NOTE]
> **Windows Users**: When installing Docker Desktop on Windows 10/11, ensure **WSL 2 (Windows Subsystem for Linux)** is enabled when prompted by the installer. Start Docker Desktop and wait until the whale icon in the taskbar turns solid green ("Engine running") before executing docker commands.

---

### Option 2: Native Setup (Without Docker)

If you cannot run Docker Desktop or prefer running the code directly on your local system:

| Tool | Required Version | Official Download Link | Verification Command |
|---|---|---|---|
| **Git** | 2.x+ | [git-scm.com/downloads](https://git-scm.com/downloads) | `git --version` |
| **Python** | **3.12** or higher (3.12.x recommended) | [python.org/downloads](https://www.python.org/downloads/) | `py --version` (Windows) or `python3 --version` |
| **Node.js & npm** | **Node.js 20 LTS** or 22 LTS | [nodejs.org/en/download](https://nodejs.org/en/download/) | `node -v` and `npm -v` |
| **PostgreSQL** | **PostgreSQL 16.x** | [postgresql.org/download](https://www.postgresql.org/download/) | `psql --version` |
| **VS Code** (Optional) | Latest | [code.visualstudio.com](https://code.visualstudio.com/) | `code --version` |

> [!IMPORTANT]
> **Windows Python Installer Tip**: During Python installation on Windows, **check the box "Add python.exe to PATH"** on the first screen.

---

## B. Clone the Repository

Open your terminal (**PowerShell** on Windows, or **Terminal** on macOS/Linux) and navigate to the directory where you store university projects (for example `C:\Projects` or `~/projects`):

```powershell
# 1. Clone the repository via Git HTTPS
git clone https://github.com/naz-33/secassess-platform.git

# 2. Enter the cloned project folder
cd secassess-platform
```

### Open the Project in Your IDE

If you use **Visual Studio Code**, launch it directly from the project root:

```powershell
code .
```

Alternatively, open VS Code, click **File > Open Folder...**, and select the `secassess-platform` folder.

---

## C. Environment Configuration

The application uses environment variables (`.env` files) to configure database credentials, JWT security tokens, and external API keys.

> [!IMPORTANT]
> **One-Time Action**: `.env` files contain local secrets and are ignored by Git. You must create them from the provided `.env.example` templates.

### 1. Root Environment File (`.env`)

This file is used by Docker Compose and serves as the primary fallback for the backend.

In your terminal at the root directory (`secassess-platform/`):

#### On Windows (PowerShell):
```powershell
Copy-Item .env.example .env
```

#### On macOS / Linux (Bash/Zsh):
```bash
cp .env.example .env
```

---

### 2. Frontend Environment File (`frontend/.env`)

The frontend needs an environment file to communicate with the backend.

#### On Windows (PowerShell):
```powershell
Copy-Item frontend\.env.example frontend\.env
```

#### On macOS / Linux (Bash/Zsh):
```bash
cp frontend/.env.example frontend/.env
```

---

### 3. Understanding the Key Variables

Open the newly created `.env` file in VS Code or any text editor. Review the parameters:

```ini
# ===================================================================
# PostgreSQL Database Configuration
# ===================================================================
POSTGRES_DB=secassess
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/secassess

# ===================================================================
# Security & JWT Token Generation
# ===================================================================
JWT_SECRET=supersecretjwtkeyforuniversityprojecttestingonly12345
JWT_EXPIRE_MINUTES=1440

# ===================================================================
# CORS Settings (Allowed Frontend URLs)
# ===================================================================
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# ===================================================================
# Optional External Services & AI (Google Gemini)
# ===================================================================
GEMINI_API_KEY=your-google-gemini-api-key
GEMINI_MODEL=gemini-3-flash-preview
AI_ENABLED=true

# ===================================================================
# Pre-Configured Local Demo Accounts (Created by scripts/seed.py)
# ===================================================================
SEED_ADMIN_EMAIL=admin@secassess.local
SEED_ADMIN_PASSWORD=AdminSecurePassword123!
SEED_ASSESSOR_EMAIL=assessor@secassess.local
SEED_ASSESSOR_PASSWORD=AssessorSecurePassword123!
```

### What is safe to share vs what must stay private:
- **Safe to share with group members**: Default database names (`secassess`), local ports, development CORS origins, and local seed test logins (`admin@secassess.local`).
- **Must be kept personal / private**:
  - `GEMINI_API_KEY`: If you want to test AI vulnerability suggestions, generate your own free API key from [Google AI Studio](https://aistudio.google.com/) and paste it here. If left blank or disabled (`AI_ENABLED=false`), all other parts of the platform (recon, scanning, assessor review, reporting) work normally without crashing.
  - Never commit your `.env` file to GitHub!

---

## D. Database Setup

SecAssess uses **PostgreSQL 16** as its primary relational database.

### Database Option 1: Using Docker PostgreSQL (Automatic)
If you are using Docker, you do not need to configure anything in this section. The `secassess-db` container automatically initializes PostgreSQL 16 on port `5432`. Skip forward to **[G. Running the Entire Project](#g-running-the-entire-project)**.

---

### Database Option 2: Using Local Native PostgreSQL

If running natively without Docker:

1. **Start the PostgreSQL Service**:
   - On Windows: Open the **Services** app (`services.msc`), find **postgresql-x64-16**, and ensure its status is **Running**.
   - On macOS (Homebrew): `brew services start postgresql@16`
   - On Linux: `sudo systemctl start postgresql`

2. **Create the Database**:
   Open a terminal and run the PostgreSQL CLI tool `createdb`, or use pgAdmin / psql:
   ```powershell
   # Create the database named 'secassess' using the postgres superuser
   createdb -U postgres secassess
   ```
   *(Enter your PostgreSQL master password when prompted).*

   If using the `psql` shell:
   ```sql
   CREATE DATABASE secassess;
   ```

3. **Verify Connection**:
   In `.env`, confirm that `DATABASE_URL` matches your local PostgreSQL username and password:
   ```text
   DATABASE_URL=postgresql+psycopg://<your-username>:<your-password>@localhost:5432/secassess
   ```
   *(Default username is usually `postgres`, password was set during PostgreSQL installation).*

---

## E. Backend Setup

> [!NOTE]
> Follow these steps if you are running the backend **natively** on your machine. If you are using Docker, see **[Section G (Method 1)](#method-1-the-one-command-docker-setup-recommended)**.

All backend commands must be run from inside the `backend` directory.

### Native Backend Setup (Step-by-Step)

#### Step 1: Open a terminal and enter the `backend` folder
```powershell
cd backend
```

#### Step 2: Create a Python 3.12 Virtual Environment
Creating a virtual environment (`.venv`) isolates project packages from your system Python.

```powershell
# On Windows:
py -3.12 -m venv .venv

# On macOS/Linux:
python3.12 -m venv .venv
```

#### Step 3: Activate the Virtual Environment

```powershell
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# On macOS / Linux:
source .venv/bin/activate
```

> [!TIP]
> **Windows PowerShell Script Block?**  
> If PowerShell displays `File ... Activate.ps1 cannot be loaded because running scripts is disabled`, run this single command to allow scripts in your current session:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```
> When activated, your prompt will show `(.venv)` on the left.

#### Step 4: Upgrade pip and install backend dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

*What this installs:* FastAPI, Uvicorn, SQLAlchemy 2.0, Alembic (database migrations), Psycopg 3 (PostgreSQL binary driver), PyJWT, Bcrypt, Google GenAI SDK, and reporting libraries (python-docx, matplotlib).

---

### Applying Database Migrations

With the virtual environment active and PostgreSQL running, apply all 10 database migration revisions:

```powershell
# Run from within the backend directory:
alembic upgrade head
```

**Expected output:**
```text
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 785f3772620e, Initial schema
INFO  [alembic.runtime.migration] Running upgrade 785f3772620e -> ee459127cdd8, Phase 2 recon schema
INFO  [alembic.runtime.migration] Running upgrade ee459127cdd8 -> cc89e812d8a1, Phase 3 findings schema
...
INFO  [alembic.runtime.migration] Running upgrade 20261110_2030 -> 20261116_2200, AI API Call Quota
```
This builds all 12 database tables (`users`, `audit_logs`, `targets`, `scope_items`, `assessments`, `scans`, `assets`, `asset_discoveries`, `findings`, `evidence`, `severity_changes`, `ai_analyses`, `verifications`, `reports`).

---

### Seeding Initial Users and Targets

To seed the initial Admin account, Assessor account, and the default OWASP Juice Shop target, execute the idempotent seed script:

```powershell
# Run from within the backend directory:
python scripts/seed.py
```

**Expected output:**
```text
INFO: Starting database seeding...
INFO: Created admin user: admin@secassess.local
INFO: Created assessor user: assessor@secassess.local
INFO: Created target 'OWASP Juice Shop' with default scope item.
INFO: Database seeding completed successfully.
```

*(Note: Running this command multiple times is completely safe; it will skip existing records).*

---

### Starting the FastAPI Backend Server

Run the development server with auto-reload:

```powershell
# Run from within the backend directory:
uvicorn app.main:app --reload --port 8000
```

**Expected output:**
```text
INFO:     Will watch for changes in: ['.../backend']
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [...]
INFO:     Application startup complete.
```

Test that the backend is responding by opening your browser or running in another terminal:
- Health check URL: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)  
  Should return: `{"status":"ok","database":"ok","version":"0.1.0"}`
- Interactive Swagger Documentation: [http://localhost:8000/docs](http://localhost:8000/docs)

> [!IMPORTANT]
> **Keep this terminal window open!** The backend server must remain running while using the application.

---

## F. Frontend Setup

> [!NOTE]
> Run these commands in a **second terminal window** while the backend remains running in the first terminal.

### Installing Node Dependencies

#### Step 1: Open a new terminal and navigate to the `frontend` folder
```powershell
cd frontend
```

#### Step 2: Install dependencies via npm
```powershell
npm install
```
This installs React 18, Vite, TypeScript, Tailwind CSS, TanStack React Query, React Router, Recharts, and Lucide icons.

---

### Configuring the API Proxy

The frontend Vite server is pre-configured with a reverse proxy in `vite.config.ts`. It forwards all `/api` requests directly to `http://localhost:8000` so that your browser does not encounter CORS issues.

Make sure `frontend/.env` exists (created in Section C):
```ini
VITE_API_BASE_URL=
```
*(Leaving `VITE_API_BASE_URL` empty instructs the app to route requests through the Vite local proxy).*

---

### Starting the Vite Development Server

Start the frontend development server:

#### On Windows (PowerShell):
```powershell
$env:VITE_BACKEND_URL = "http://localhost:8000"
npm run dev
```

#### On macOS / Linux:
```bash
VITE_BACKEND_URL=http://localhost:8000 npm run dev
```

**Expected output:**
```text
  VITE v6.0.3  ready in 240 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.x.x:5173/
  ➜  press h + enter to show help
```

Open your browser and navigate to:
👉 **[http://localhost:5173](http://localhost:5173)**

You will see the SecAssess login screen!

---

## G. Running the Entire Project

You have two ways to run the project. Group members can choose either method:

### Method 1: The One-Command Docker Setup (Recommended)

This is the easiest method. It starts PostgreSQL, the FastAPI backend, the React frontend, and the vulnerable SarangTV target container all at once.

#### Step 1: Start the services
From the repository root (`secassess-platform/`):

```powershell
docker compose up --build -d
```
*(The first build takes 2–4 minutes to download images and compile dependencies).*

#### Step 2: Run the database seeder inside the container
Once the backend container is healthy (wait ~15 seconds after the first start):

```powershell
docker compose exec backend python scripts/seed.py
```

#### Step 3: (Optional) Start OWASP Juice Shop & ZAP testing targets
If your assignment task involves scanning OWASP Juice Shop or using the ZAP proxy:

```powershell
docker compose --profile targets up --build -d
```

#### Step 4: Stopping the containers
When you are done working:
```powershell
# Stops containers but PRESERVES your database records
docker compose down
```

> [!CAUTION]
> Do **NOT** run `docker compose down -v` unless you want to permanently erase the database volume and all saved assessments!

---

### Method 2: Multi-Terminal Native Execution

If running without Docker, you will maintain **two dedicated terminal windows**:

#### Terminal 1: Backend API
```powershell
cd secassess-platform\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --port 8000
```
*Leave running on port 8000.*

#### Terminal 2: Frontend Web App
```powershell
cd secassess-platform\frontend
$env:VITE_BACKEND_URL = "http://localhost:8000"
npm run dev
```
*Leave running on port 5173.*

---

### Service URLs & Default Credentials Quick Reference

| Service | Local URL | Description |
|---|---|---|
| **Frontend Web App** | `http://localhost:5173` | React Dashboard, Findings, Scans, Reports |
| **Backend API Docs** | `http://localhost:8000/docs` | Swagger OpenAPI UI for testing endpoints |
| **API Health Check** | `http://localhost:8000/api/v1/health` | Diagnostic status of app & database |
| **SarangTV Target** | `http://localhost:8081` | Vulnerable Laravel app (PHP/MySQL) |
| **OWASP Juice Shop** | `http://localhost:3000` | Optional web target (Docker profile `targets`) |
| **OWASP ZAP API** | `http://localhost:8080` | Security proxy daemon (Docker profile `targets`) |

#### Pre-Configured Local User Accounts:

| Role | Email | Password | Allowed Capabilities |
|---|---|---|---|
| **Administrator** | `admin@secassess.local` | `AdminSecurePassword123!` | User management, audit logs, target scoping, assessment creation |
| **Assessor** | `assessor@secassess.local` | `AssessorSecurePassword123!` | Running scans, reviewing findings, AI analysis, report generation |

---

## H. Common Errors and Troubleshooting

Here are the most common issues group members encounter when setting up this repository on their personal laptops, along with proven fixes:

---

### 1. PowerShell Execution Policy Restriction

#### Symptom:
When trying to activate the virtual environment (`.\.venv\Scripts\Activate.ps1`), PowerShell displays:
```text
File C:\...\Activate.ps1 cannot be loaded because running scripts is disabled on this system.
```

#### Cause:
Windows PowerShell disables script execution by default as a security precaution on new machines.

#### Solution:
Bypass the restriction for the current PowerShell window only:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```
*(This does not modify permanent system settings and is completely safe).*

---

### 2. PostgreSQL Database Connection Refused

#### Symptom:
Running `alembic upgrade head` or starting the backend throws:
```text
psycopg.OperationalError: connection to server at "localhost" (127.0.0.1), port 5432 failed: Connection refused
```

#### Cause:
Either:
1. The PostgreSQL service is not running on your computer.
2. The database named `secassess` has not been created yet.
3. The password in `DATABASE_URL` inside `.env` does not match your local PostgreSQL password.

#### Solution:
1. Check that PostgreSQL service is running:
   ```powershell
   Get-Service -Name postgresql*
   ```
   If stopped, start it:
   ```powershell
   Start-Service -Name postgresql*
   ```
2. Create the `secassess` database if missing:
   ```powershell
   createdb -U postgres secassess
   ```
3. Check `backend/.env` or root `.env`:
   Make sure the username and password match what you entered when installing PostgreSQL:
   ```ini
   DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/secassess
   ```
4. Verify by curling the health check after starting the backend:
   ```powershell
   curl http://localhost:8000/api/v1/health
   ```

---

### 3. Port Already in Use (5432, 8000, 5173, 8081)

#### Symptom:
```text
[Errno 10048] error while attempting to bind on address ('127.0.0.1', 8000): only one usage of each socket address is normally permitted
```
or Docker error:
```text
driver failed programming external connectivity on endpoint ...: Bind for 0.0.0.0:5432 failed: port is already allocated
```

#### Cause:
Another application (e.g. an earlier uvicorn instance, local PostgreSQL, or another web server) is already occupying that port.

#### Solution:
Find and terminate the process holding the port:
```powershell
# Check which process ID (PID) owns port 8000:
netstat -ano | findstr :8000

# Terminate the process (replace <PID> with the number from the last column):
taskkill /F /PID <PID>
```
*(If port 5432 is conflicting with Docker, your native PostgreSQL is running on host port 5432. Stop the local service using `Stop-Service postgresql*` so Docker can bind to 5432).*

---

### 4. Frontend Cannot Connect to Backend / Network Error

#### Symptom:
The frontend page loads at `http://localhost:5173`, but login attempts fail with `Network Error` or `Failed to fetch`.

#### Cause:
The frontend development server does not know where the backend is running, or the backend is not started.

#### Solution:
1. Confirm the backend is actually running: Open [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) in your browser. It must return `"status": "ok"`.
2. Stop the frontend terminal (`Ctrl + C`) and restart it with the explicit backend environment variable:
   ```powershell
   $env:VITE_BACKEND_URL = "http://localhost:8000"
   npm run dev
   ```
3. Ensure `frontend/.env` has `VITE_API_BASE_URL=` (empty string).

---

### 5. Gemini AI Errors or Scanning Failures

#### Symptom:
Vulnerability analysis displays `AI integration is currently disabled` or fails with an API key error.

#### Cause:
`GEMINI_API_KEY` is empty or `AI_ENABLED=false` in `.env`.

#### Solution:
1. AI analysis is an optional feature and is intentionally designed to fail gracefully without crashing the platform.
2. If you want to enable it:
   - Obtain a free API key at [Google AI Studio](https://aistudio.google.com/).
   - Edit `.env`:
     ```ini
     AI_ENABLED=true
     GEMINI_API_KEY=your_actual_gemini_api_key_here
     GEMINI_MODEL=gemini-3-flash-preview
     ```
   - Restart the backend.

---

### 6. Test Database Failures When Running Pytest

#### Symptom:
Running `pytest` directly in the backend fails immediately with:
```text
RuntimeError: TEST_DATABASE_URL must point to a dedicated test database before running backend tests.
```

#### Cause:
To prevent students or developers from accidentally deleting assessment data, the test suite strictly enforces that backend tests can **only** run against a dedicated database whose name contains `test`.

#### Solution:
Create a test database and provide `TEST_DATABASE_URL`:
```powershell
# 1. Create the test database once
createdb -U postgres secassess_test

# 2. In PowerShell, set the test database URL and run pytest:
$env:TEST_DATABASE_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/secassess_test"
pytest -v
```
*(If using Docker, simply run `make test` or `docker compose --profile test run --rm test-runner`).*

---

## I. Verification Checklist

Use this checklist to confirm your local setup is 100% operational before beginning your work:

- [ ] **Prerequisites Verified**:
  - `git --version` returns Git 2.x.
  - If Docker: `docker compose version` returns Compose v2.x.
  - If Native: `py --version` (3.12+) and `node -v` (v20+).
- [ ] **Environment Files Created**:
  - `.env` exists in root folder.
  - `frontend/.env` exists.
- [ ] **Database Running**:
  - PostgreSQL port `5432` is reachable.
- [ ] **Migrations & Seed Data Applied**:
  - `alembic upgrade head` completed with no errors.
  - `python scripts/seed.py` successfully created Admin & Assessor accounts.
- [ ] **Backend Health Check Passed**:
  - Navigating to [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) returns:
    ```json
    {
      "status": "ok",
      "database": "ok",
      "version": "0.1.0"
    }
    ```
- [ ] **API Documentation Accessible**:
  - [http://localhost:8000/docs](http://localhost:8000/docs) opens interactive Swagger UI.
- [ ] **Frontend Running & Reachable**:
  - [http://localhost:5173](http://localhost:5173) displays the SecAssess login screen.
- [ ] **Successful Authentication**:
  - Log in with `admin@secassess.local` / `AdminSecurePassword123!`.
  - Dashboard appears showing target and assessment widgets.
- [ ] **Target Scope Verification**:
  - Navigate to **Targets** in the top navigation bar.
  - Verify that **OWASP Juice Shop** is visible in the list as in-scope.

---

### Need Help?
If you run into an issue not covered in this guide, check with the team lead or post the error message in the group chat along with:
1. Your Operating System (e.g. Windows 11, macOS Sequoia, Ubuntu 24.04).
2. Whether you are using Docker or the Native setup.
3. The exact error output from the terminal.
