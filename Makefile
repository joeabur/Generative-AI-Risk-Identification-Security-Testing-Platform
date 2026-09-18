.PHONY: up down build logs migrate test test-backend test-frontend lint typecheck fmt clean

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

migrate:
	docker compose exec backend alembic upgrade head

# `make seed` (a synthetic demo account + demo data) lands with the demo lab
# in a later phase — see docs/roadmap.md. There is deliberately no target
# for it yet rather than one that points at a module that doesn't exist.

test: test-backend test-frontend

test-backend:
	cd backend && . .venv/bin/activate && python -m pytest -q

test-frontend:
	cd frontend && npm test

lint:
	cd backend && . .venv/bin/activate && ruff check .
	cd frontend && npm run lint

typecheck:
	cd backend && . .venv/bin/activate && mypy app
	cd frontend && npm run typecheck

fmt:
	cd backend && . .venv/bin/activate && ruff format .

clean:
	docker compose down -v
