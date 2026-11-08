.PHONY: up down logs migrate revision seed test lint psql reset-db

# Start core services (db, backend, frontend)
up:
	docker compose up --build -d

# Start all services including juice-shop and zap target profile
up-targets:
	docker compose --profile targets up --build -d

# Stop and remove running containers
down:
	docker compose --profile targets down

# Stream container logs
logs:
	docker compose logs -f

# Run Alembic migrations in backend
migrate:
	docker compose exec backend alembic upgrade head

# Generate a new Alembic migration revision
revision:
	docker compose exec backend alembic revision --autogenerate -m "$(m)"

# Run database seed script idempotently
seed:
	docker compose exec backend python scripts/seed.py

# Run test suite
test:
	docker compose exec backend pytest -v

# Run backend linter
lint:
	docker compose exec backend ruff check .

# Open interactive PostgreSQL shell
psql:
	docker compose exec db psql -U postgres -d secassess

# Reset database: drop volume, recreate container, migrate and seed
reset-db:
	docker compose down -v
	docker compose up -d db
	docker compose exec db sh -c 'until pg_isready -U postgres -d secassess; do sleep 1; done'
	docker compose run --rm backend alembic upgrade head
	docker compose run --rm backend python scripts/seed.py
