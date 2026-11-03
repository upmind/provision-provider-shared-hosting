.PHONY: help

# List all available Makefile commands.
help:
	@echo "Available commands:"
	@echo "   make help                  : List all available Makefile commands"
	@echo "   make setup-php83           : Start the dev environment with PHP 8.3"
	@echo "   make setup-php84           : Start the dev environment with PHP 8.4"
	@echo "   make setup-php85           : Start the dev environment with PHP 8.5"
	@echo "   make shell                 : Get an interactive shell on the PHP container"
	@echo "   make test                  : Run Tests (PHPUnit)"
	@echo "   make static-analysis       : Run Static Analysis (PHPStan)"
	@echo "   make coding-standards      : Run Coding Standards (PHP-CS-Fixer)"
	@echo "   make start-containers      : Start the dev environment"
	@echo "   make stop-containers       : Stop the dev environment"
	@echo "   make kill-containers       : Stop and remove all containers"
	@echo "   make composer-install      : Install composer dependencies"

# Typing 'make setup-php83' will start the dev environment with PHP 8.3
setup-php83: --prep-docker-compose-file stop-containers --prep-dockerfile-php83 start-containers --remove-packages composer-install

# Typing 'make setup-php84' will start the dev environment with PHP 8.4
setup-php84: --prep-docker-compose-file stop-containers --prep-dockerfile-php84 start-containers --remove-packages composer-install

# Typing 'make setup-php85' will start the dev environment with PHP 8.5
setup-php85: --prep-docker-compose-file stop-containers --prep-dockerfile-php85 start-containers --remove-packages composer-install

# Get a shell on the PHP container
shell:
	docker compose exec -it provision-provider-shared-hosting /bin/bash

# Run Tests (PHPUnit)
test:
	docker compose exec provision-provider-shared-hosting ./vendor/bin/phpunit

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

# Copy Dockerfile for PHP 8.3
--prep-dockerfile-php83: --remove-dockerfile
	cp "./.docker/Dockerfile.php83" "./.docker/Dockerfile"

# Copy Dockerfile for PHP 8.4
--prep-dockerfile-php84: --remove-dockerfile
	cp "./.docker/Dockerfile.php84" "./.docker/Dockerfile"

# Copy Dockerfile for PHP 8.5
--prep-dockerfile-php85: --remove-dockerfile
	cp "./.docker/Dockerfile.php85" "./.docker/Dockerfile"

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
