# HoneyForge - convenience commands (role 5: Makefile).
# Use --env-file .env because compose runs from deploy/.

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE      := docker compose --env-file .env
CENTER_FILE  := -f deploy/docker-compose.yml
HONEY_FILE   := -f deploy/docker-compose.honeypots.yml

CENTER := $(COMPOSE) $(CENTER_FILE)
HONEY  := $(COMPOSE) $(HONEY_FILE)

.PHONY: help env up down restart logs ps build config test certs \
        honeypots-up honeypots-down honeypots-build honeypots-config clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from .env.example if missing
	@test -f .env || { cp .env.example .env; echo "[env] created .env from .env.example"; }

certs: ## Generate self-signed certificates (task 6.5)
	@bash deploy/scripts/gen_certs.sh

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
	@if [ -d tests ]; then python3 -m pytest -q; \
	else echo "[test] tests/ is empty - add tests (tests block)"; fi

honeypots-up: env ## Start the honeypot fleet skeleton (task 6.2)
	$(HONEY) up -d --build

honeypots-down: env ## Stop the honeypot fleet
	$(HONEY) down

honeypots-build: env ## Build honeypot images
	$(HONEY) build

honeypots-config: env ## Validate deploy/docker-compose.honeypots.yml
	$(HONEY) config -q

clean: env ## Stop the center and remove volumes (deletes the database)
	$(CENTER) down -v
