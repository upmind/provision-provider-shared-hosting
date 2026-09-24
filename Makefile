.PHONY: help

# List all available Makefile commands.
help:
	@echo "Available commands:"
	@echo "   make help                  : List all available Makefile commands"
	@echo "   make setup-php74           : Start the dev environment with PHP 7.4"
	@echo "   make shell                 : Get an interactive shell on the PHP container"
	@echo "   make static-analysis       : Run Static Analysis (PHPStan)"
	@echo "   make coding-standards      : Run Coding Standards (PHP-CS-Fixer)"
	@echo "   make start-containers      : Start the dev environment"
	@echo "   make stop-containers       : Stop the dev environment"
	@echo "   make kill-containers       : Stop and remove all containers"
	@echo "   make composer-install      : Install composer dependencies"

# Typing 'make setup-php74' will start the dev environment with PHP 7.4
setup-php74: --prep-docker-compose-file stop-containers --prep-dockerfile-php74 start-containers --remove-packages composer-install

# Get a shell on the PHP container
shell:
	docker compose exec -it provision-provider-shared-hosting /bin/bash

# Run Static Analysis (PHPStan)
static-analysis:
	docker compose exec provision-provider-shared-hosting ./vendor/bin/phpstan analyse --memory-limit=1G

coding-standards:
	docker compose exec provision-provider-shared-hosting php ./bin/php-cs-fixer-v3.phar fix --config=./.php-cs-fixer.dist.php

# Start the dev environment
start-containers:
	docker compose up -d --build

# Stop the dev environment
stop-containers:
	docker compose down

# Stop and remove all containers
kill-containers:
	docker compose kill
	docker compose rm --force

# Install composer dependencies
composer-install:
	docker compose exec provision-provider-shared-hosting composer install --no-interaction

# Copy Dockerfile for PHP 7.4
--prep-dockerfile-php74: --remove-dockerfile
	cp "./.docker/Dockerfile.php74" "./.docker/Dockerfile"

# Copy docker-compose.yml file
--prep-docker-compose-file:
	[ -f "./docker-compose.yml" ] || cp "./docker-compose.yml.example" "./docker-compose.yml"

# Remove Dockerfile
--remove-dockerfile:
	rm -f ./docker/Dockerfile

# Remove composer related files
--remove-packages: --remove-lockfile --remove-vendor

# Remove composer.lock file
--remove-lockfile:
	docker compose exec provision-provider-shared-hosting rm -f ./composer.lock

# Remove vendor directory
--remove-vendor:
	docker compose exec provision-provider-shared-hosting rm -rf ./vendor
