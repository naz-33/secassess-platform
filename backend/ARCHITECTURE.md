# Backend Architecture & Modular Monolith Guide

This document describes the architectural principles, boundaries, and dependency patterns governing the "AI-Assisted Security Assessment and Vulnerability Analysis Platform".

---

## 1. Core Architectural Principles

1. **Modular Monolith**:
   The backend is packaged and deployed as a single FastAPI service, but is internally partitioned into self-contained, domain-aligned modules located under `backend/app/modules/`.

2. **Strict Module Encapsulation**:
   Each module owns its internal data layer (`models.py`, `repository.py`), HTTP endpoints (`router.py`), and validation schemas (`schemas.py`).
   - A module exposes **only** its public API through `service.py` and `__init__.py`.
   - Direct imports of another module's `models.py`, `repository.py`, or `router.py` are **strictly forbidden** and caught automatically by static AST analysis in `tests/test_module_boundaries.py`.

3. **Database Independence with Plain Foreign Keys**:
   - Cross-module data references in the database use plain PostgreSQL foreign key constraints (`ForeignKey("targets.id")`).
   - Modules do **not** configure cross-module SQLAlchemy ORM `relationship()` objects that import other modules' model classes.
   - Cross-module runtime coordination is handled strictly via public service calls.

4. **Domain-Agnostic Core**:
   Shared, domain-agnostic infrastructure lives in `backend/app/core/` (configuration, database engine session, authentication security utilities, structured logging, exception handlers, and generic FastAPI dependencies).
   - Domain logic must never be placed into `core/`.

5. **Mandatory Scope Verification**:
   The `targets` module provides `ScopeManager.assert_in_scope(target_id, asset)` exported via `TargetService`. Every active scanner or reconnaissance tool runner (`recon`, `web_assessment`) must invoke this verification before initiating network interaction.

---

## 2. Module Directory Structure

Each module adheres to the standard layout:

```text
modules/<module_name>/
├── __init__.py       # Re-exports the public API (Service class / functions)
├── router.py         # APIRouter with prefix and tags; mounted under /api/v1
├── schemas.py        # Pydantic v2 validation models
├── models.py         # SQLAlchemy 2.0 declarative models (if module owns tables)
├── service.py        # Business logic entry points
└── repository.py     # Database queries and persistence (if module owns tables)
```

Specialized extensions:
- `scans/`: allow-listed Nmap/DNS adapters and the shared scope-enforcing process runner.
- `recon/`: Nmap/DNS output parsers and deduplicated asset cataloging with per-scan discovery history.
- `web_assessment/`: curl/TLS runners, ZAP API integration, output parsers, and custom checks.
- `ai_analysis/`: `prompts/`, `redaction.py`, `llm_client.py`.
- `targets/`: `scope_manager.py` (authoritative scope boundary enforcement).
- `reporting/`: `templates/` and `generators/` (DOCX & PDF document compilation).

---

## 3. Module Dependency Diagram (ASCII)

```text
                               +-------------------+
                               |   FastAPI Main    |
                               | (app/main.py: /api)
                               +---------+---------+
                                         |
     +---------------+-------------------+---------------+-------------------+
     |               |                   |               |                   |
     v               v                   v               v                   v
+---------+     +---------+         +---------+     +---------+         +---------+
|  auth   |     |  audit  |         | targets |     |dashboard|         |reporting|
+----+----+     +----+----+         +----+----+     +----+----+         +----+----+
     |               ^                   ^               |                   |
     |               | (audit calls)     | (scope check) | (aggregates)      | (reads)
     |               +-----------+       |               v                   v
     |                           |   +---+-------------+-----------------------+
     |                           |   |                                         |
     |                           +---|       assessments / scans               |
     |                               |                                         |
     |                               +---+-------------+-----------------------+
     |                                   |             |
     |             +---------------------+             +--------------------+
     |             | (invokes / produces)                                   |
     v             v                                                        v
+-----------------------+                                         +-------------------+
|         recon         |                                         |  web_assessment   |
| (Nmap, DNS -> assets) |                                         | (ZAP, curl, TLS)  |
+-----------+-----------+                                         +---------+---------+
            |                                                               |
            +----------------------------+----------------------------------+
                                         | (candidate findings)
                                         v
                              +--------------------+
                              |      findings      |<-------------------+
                              | (findings+evidence)|                    |
                              +----+----------+----+                    |
                                   |          |                         |
               (triggers reasoning)|          | (assessor verification) |
                                   v          v                         |
                             +-----------+  +--------------+            |
                             |ai_analysis|  | verification +------------+
                             +-----------+  +--------------+ (updates status)
```

---

## 4. Module Responsibilities & Table Ownership

| Module | Owned Tables | Description |
|---|---|---|
| `auth` | `users` | User credentials, roles (`admin`, `assessor`), JWT token creation |
| `audit` | `audit_log` | System-wide audit trail for security events and assessor actions |
| `targets` | `targets`, `scope_items` | Assessment target boundaries and scope enforcement (`ScopeManager`) |
| `assessments` | `assessments` | High-level security evaluation project cycles |
| `scans` | `scans` | Background scanner task records, command history, and raw outputs |
| `recon` | `assets` | Discovered network assets, open ports, and DNS infrastructure |
| `web_assessment` | *(none)* | Web vulnerability assessment runners (ZAP, curl, TLS) |
| `findings` | `findings`, `evidence` | Vulnerability records with severity, lifecycle status, and evidence artifacts |
| `ai_analysis` | `ai_analyses` | Redacted LLM prompting, vulnerability interpretation, and remediation suggestions |
| `verification` | `verifications` | Human-in-the-loop review decisions confirming or rejecting findings |
| `reporting` | `reports` | PDF / Word report document compilation and archival |
| `dashboard` | *(none)* | Read-only metric aggregations for frontend charts |
