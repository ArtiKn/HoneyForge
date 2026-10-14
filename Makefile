# HoneyForge - convenience commands (role 5: Makefile).
# Use --env-file .env because compose runs from deploy/.

SHELL := /bin/bash
.DEFAULT_GOAL := help
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
DEMO_PY := docker run --rm --network host --user "$$(id -u):$$(id -g)" -v "$$(pwd)":/workspace -w /workspace python:3.12-slim python

COMPOSE      := docker compose --env-file .env
CENTER_FILE  := -f deploy/docker-compose.yml
HONEY_FILE   := -f deploy/docker-compose.honeypots.yml
DEMO_FILE    := -f deploy/docker-compose.demo.yml

CENTER := $(COMPOSE) $(CENTER_FILE)
HONEY  := $(COMPOSE) $(HONEY_FILE) $(DEMO_FILE)
HONEY_DISTRIBUTED := $(COMPOSE) $(HONEY_FILE)

.PHONY: help env up down restart logs ps build config test certs demo demo-env demo-seed demo-attack demo-smoke \
        honeypots-up honeypots-down honeypots-build honeypots-config \
        honeypots-distributed-config clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || { cp .env.example .env; echo "[env] created .env from .env.example"; }

certs: ## Generate self-signed certificates (task 6.5)
	@bash deploy/scripts/gen_certs.sh

demo-env: ## Create secure local demo configuration without overwriting it
	@$(DEMO_PY) deploy/scripts/demo.py env

demo: demo-env certs ## Start the complete idempotent local MVP demo
	$(CENTER) up -d --build --force-recreate
	@$(DEMO_PY) deploy/scripts/demo.py seed
	$(HONEY) up -d --build
	@echo "[demo] Control Center: https://localhost:$${CENTER_HTTPS_PORT:-8443}"

demo-seed: env certs ## Seed demo Trap Profiles, Traps and persistent credentials
	@$(DEMO_PY) deploy/scripts/demo.py seed

demo-attack: ## Generate deterministic SSH, HTTP and MySQL interactions locally
	@$(DEMO_PY) deploy/scripts/demo.py attack

demo-smoke: ## Probe Security Event delivery, REST persistence and UI visibility
	@bash deploy/scripts/buffer_smoke.sh

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

test: ## Run tests
	@if [ -d tests ]; then $(PYTHON) -m pytest -q; \
	else echo "[test] tests/ is empty - add tests (tests block)"; fi

honeypots-up: env ## Start the honeypot fleet skeleton (task 6.2)
	$(HONEY) up -d --build

honeypots-down: env ## Stop the honeypot fleet
	$(HONEY) down

honeypots-build: env ## Build honeypot images
	$(HONEY) build

honeypots-config: env ## Validate deploy/docker-compose.honeypots.yml
	$(HONEY) config -q

honeypots-distributed-config: env ## Validate the separated DMZ topology
	$(HONEY_DISTRIBUTED) config -q

clean: env ## Stop the center and remove volumes (deletes the database)
	$(CENTER) down -v
