.PHONY: up down logs migrate revision seed test test-local-lab lint psql reset-db

# Start core services (db, backend, frontend)
up:
	docker compose up --build -d

# Start all services including juice-shop and zap target profile
up-targets:
	docker compose --profile targets up --build -d

# Stop and remove running containers
down:
	docker compose --profile test --profile targets down

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

# Run backend tests against an isolated test database
test:
	docker compose --profile test run --rm test-runner

# Run bounded scanner checks against the local Juice Shop and ZAP services
test-local-lab:
	docker compose --profile test --profile targets up -d test-db juice-shop zap
	docker compose --profile test --profile targets run --rm -e RUN_LOCAL_LAB_TESTS=1 test-runner sh -c "alembic upgrade head && pytest -v tests/test_local_lab_assessment.py"

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
