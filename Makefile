# HoneyForge - convenience commands (role 5: Makefile).
# Use --env-file .env because compose runs from deploy/.

SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON := $(if $(wildcard .venv/bin/python),$(wildcard .venv/bin/python),python3)
DEMO_PY := docker run --rm --network host --user "$$(id -u):$$(id -g)" -v "$$(pwd)":/workspace -w /workspace python:3.12-slim python
TEST_DB := honeyforge-test-db
TEST_DB_PORT ?= 55432
TEST_DATABASE_URL ?= postgresql+asyncpg://honeyforge:test@127.0.0.1:$(TEST_DB_PORT)/honeyforge_test

COMPOSE      := docker compose --env-file .env
CENTER_FILE  := -f deploy/docker-compose.yml
HONEY_FILE   := -f deploy/docker-compose.honeypots.yml
DEMO_FILE    := -f deploy/docker-compose.demo.yml

CENTER := $(COMPOSE) $(CENTER_FILE)
HONEY  := $(COMPOSE) $(HONEY_FILE) $(DEMO_FILE)
HONEY_DISTRIBUTED := $(COMPOSE) $(HONEY_FILE)

.PHONY: help env up down restart logs ps build config test test-db certs \
        demo demo-env demo-seed demo-attack demo-smoke demo-reset \
        demo-status demo-export demo-lifecycle demo-rbac demo-masking demo-payload demo-tour \
        demo-trap-host demo-logs \
        honeypots-up honeypots-down honeypots-build honeypots-config \
        honeypots-distributed-config clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || { cp .env.example .env; echo "[env] created .env from .env.example"; }

certs: ## Generate the local CA and server certificate (task 6.5)
	@bash deploy/scripts/gen_certs.sh

# --- center stack ---------------------------------------------------------

up: env certs ## Start the center stack (task 6.1)
	$(CENTER) up -d --build

down: env ## Stop the center stack
	$(CENTER) down

restart: down up ## Restart the center stack

build: env ## Build center images
	$(CENTER) build

logs: env ## Follow center logs
	$(CENTER) logs -f --tail=100

ps: env ## Show center container statuses
	$(CENTER) ps

config: env ## Validate deploy/docker-compose.yml
	$(CENTER) config -q

clean: env ## Stop the center and remove volumes (deletes the database)
	$(CENTER) down -v

# --- tests ----------------------------------------------------------------

test: ## Run the test suite (PostgreSQL tests are skipped, see test-db)
	@if [ -d tests ]; then $(PYTHON) -m pytest -q; \
	else echo "[test] tests/ is empty - add tests (tests block)"; fi

test-db: ## Run the whole suite against a throwaway PostgreSQL (no DB skips)
	@docker rm -f $(TEST_DB) >/dev/null 2>&1 || true
	@if docker ps --format '{{.Ports}}' | grep -q ":$(TEST_DB_PORT)->"; then \
		echo "[test-db] порт $(TEST_DB_PORT) уже занят:"; \
		docker ps --format '  {{.Names}}' --filter publish=$(TEST_DB_PORT); \
		echo "  освободите его или запустите с TEST_DB_PORT=<другой порт>"; exit 1; \
	fi
	@docker run -d --rm --name $(TEST_DB) -p $(TEST_DB_PORT):5432 \
		-e POSTGRES_USER=honeyforge -e POSTGRES_PASSWORD=test \
		-e POSTGRES_DB=honeyforge_test postgres:16 >/dev/null
	@echo "[test-db] waiting for PostgreSQL on port $(TEST_DB_PORT)"
	@for attempt in $$(seq 1 60); do \
		docker exec $(TEST_DB) pg_isready -U honeyforge -d honeyforge_test >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(PYTHON) -m pytest -q -p no:cacheprovider; status=$$?; \
	docker rm -f $(TEST_DB) >/dev/null 2>&1 || true; \
	exit $$status

# --- demo stand -----------------------------------------------------------

demo-env: ## Create secure local demo configuration without overwriting it
	@$(DEMO_PY) deploy/scripts/demo.py env

demo: demo-env certs ## Start the complete idempotent local MVP demo
	$(CENTER) up -d --build --force-recreate
	@$(DEMO_PY) deploy/scripts/demo.py seed
	$(HONEY) up -d --build --force-recreate
	@echo "[demo] Control Center: https://localhost:$${CENTER_HTTPS_PORT:-8443}"

demo-reset: ## Remove the demo stack, volumes and Trap credentials
	-$(HONEY) down -v --remove-orphans
	-$(CENTER) down -v --remove-orphans
	-rm -f secrets/low_trap_secret secrets/medium_trap_secret
	@echo "[demo-reset] removed demo volumes and Trap credentials; run 'make demo' for a clean stand"

demo-seed: env certs ## Seed demo Trap Profiles, Traps and persistent credentials
	@$(DEMO_PY) deploy/scripts/demo.py seed

# --- feature demonstrations ----------------------------------------------

demo-tour: ## Walk through every feature against the running stand
	@$(DEMO_PY) deploy/scripts/demo.py tour

demo-status: ## Show the Trap fleet, profiles and the newest Security Event
	@$(DEMO_PY) deploy/scripts/demo.py status

demo-attack: ## Generate deterministic SSH, HTTP, MySQL and UDP interactions
	@$(DEMO_PY) deploy/scripts/demo.py attack

demo-payload: ## Push a payload into a Trap and show the captured event
	@$(DEMO_PY) deploy/scripts/demo.py payload

demo-export: ## Export the filtered Security Events as an IoC CSV
	@$(DEMO_PY) deploy/scripts/demo.py export \
		--trap-id "$(TRAP_ID)" --event-type "$(EVENT_TYPE)" \
		--source-ip "$(SOURCE_IP)" --limit "$(EXPORT_LIMIT)" \
		--output "$(or $(OUTPUT),artifacts/ioc-export.csv)"

demo-lifecycle: ## Stop, start, revoke and restore a Trap, then heal it
	@$(DEMO_PY) deploy/scripts/demo.py lifecycle --trap-name "$(or $(TRAP_NAME),Demo Low)"

demo-rbac: ## Show authentication and the read-only role boundary
	@$(DEMO_PY) deploy/scripts/demo.py rbac

demo-masking: ## Prove the shipped Agent artifact exposes nothing
	@$(DEMO_PY) deploy/scripts/demo.py masking
	@echo "[demo-masking] what an attacker with root on the Trap host would find:"
	@for container in $$(docker ps --format '{{.Names}}' | grep -E '^(syslog-relay|hf-agent)' || true); do \
		echo "  $$container: $$(docker exec $$container ls -1 /usr/lib/syslog-relay 2>/dev/null | tr '\n' ' ')"; \
	done

demo-smoke: ## Prove delivery survives a lost connection (buffer + catch-up)
	@bash deploy/scripts/buffer_smoke.sh

demo-trap-host: ## Inspect the trap container as an attacker with root would
	@for container in $$(docker ps --format '{{.Names}}' | grep -E '^(syslog-relay|hf-agent)' || true); do \
		echo "== $$container =="; \
		docker exec $$container sh -c 'ls -1 /usr/lib/syslog-relay; grep -c "python\|relay" /proc/1/cmdline 2>/dev/null || true'; \
	done

demo-logs: ## Follow center and trap logs side by side
	@echo "[logs] center:"; $(CENTER) logs -f --tail=40 & \
	$(HONEY) logs -f --tail=40; \
	kill $$! 2>/dev/null || true

# --- distributed honeypot fleet -------------------------------------------

honeypots-up: env ## Start the honeypot fleet with the demo overlay
	$(HONEY) up -d --build

honeypots-down: env ## Stop the honeypot fleet
	$(HONEY) down

honeypots-build: env ## Build honeypot images
	$(HONEY) build

honeypots-config: env ## Validate deploy/docker-compose.honeypots.yml
	$(HONEY) config -q

honeypots-distributed-config: env ## Validate the separated DMZ topology
	$(HONEY_DISTRIBUTED) config -q