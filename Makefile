# Makefile for Argus Threat Intelligence Service
include .env
export

.PHONY: help dev-build dev-up dev-down dev-restart dev-logs prod-build prod-up prod-down prod-restart prod-logs clean

# Default target
help:
	@echo "Available commands:"
	@echo "  dev-build      - Build development containers"
	@echo "  dev-up         - Start development environment"
	@echo "  dev-down       - Stop development environment"
	@echo "  dev-restart    - Restart development environment"
	@echo "  dev-logs       - Follow development logs"
	@echo "  dev-shell      - Access PHP container shell"
	@echo ""
	@echo "  prod-build     - Build production containers"
	@echo "  prod-up        - Start production environment"
	@echo "  prod-down      - Stop production environment"
	@echo "  prod-restart   - Restart production environment"
	@echo "  prod-logs      - Follow production logs"
	@echo ""
	@echo "  clean          - Clean up containers and volumes"
	@echo "  composer-install - Install/update composer dependencies"
	@echo "  db-backup      - Create database backup"

# Development environment
dev-build:
	docker compose -f docker-compose.dev.yml build

dev-up:
	docker compose -f docker-compose.dev.yml up -d

dev-up-with-tools:
	docker compose -f docker-compose.dev.yml --profile tools up -d

dev-down:
	docker compose -f docker-compose.dev.yml down

dev-restart:
	docker compose -f docker-compose.dev.yml restart

dev-logs:
	docker compose -f docker-compose.dev.yml logs -f

dev-shell:
	docker compose -f docker-compose.dev.yml exec php-fpm bash

# Production environment
prod-build:
	docker compose -f docker-compose.prod.yml build

prod-up:
	docker compose -f docker-compose.prod.yml up -d

prod-down:
	docker compose -f docker-compose.prod.yml down

prod-restart:
	docker compose -f docker-compose.prod.yml restart

prod-logs:
	docker compose -f docker-compose.prod.yml logs -f

# Utility commands
composer-install:
	docker compose -f docker-compose.dev.yml exec php-fpm composer install

composer-update:
	docker compose -f docker-compose.dev.yml exec php-fpm composer update

db-backup:
    docker compose -f docker-compose.dev.yml exec mariadb sh -c \
        "mariadb-dump -u root -p$$MYSQL_ROOT_PASSWORD $$MYSQL_DATABASE" \
        > ./database/backups/backup_$(shell date +%Y%m%d_%H%M%S).sql


clean:
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.prod.yml down -v
	docker system prune -f

# Monitor threat intelligence service
monitor:
	@echo "=== Container Status ==="
	docker compose -f docker-compose.dev.yml ps
	@echo ""
	@echo "=== Recent Logs ==="
	docker compose -f docker-compose.dev.yml logs --tail=50
	@echo ""
	@echo "=== Threat Analysis Logs ==="
	docker compose -f docker-compose.dev.yml exec php-fpm tail -f /var/log/ip-blocklist.log