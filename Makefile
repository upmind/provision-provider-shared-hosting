.PHONY: help

# List all available Makefile commands.
help:
	@echo "Available commands:"
	@echo "   make help                  : List all available Makefile commands"
	@echo "   make setup-php81           : Start the dev environment with PHP 8.1"
	@echo "   make setup-php82           : Start the dev environment with PHP 8.2"
	@echo "   make setup-php83           : Start the dev environment with PHP 8.3"
	@echo "   make shell                 : Get an interactive shell on the PHP container"
	@echo "   make static-analysis       : Run Static Analysis (PHPStan)"
	@echo "   make coding-standards      : Run Coding Standards (PHP-CS-Fixer)"
	@echo "   make start-containers      : Start the dev environment"
	@echo "   make stop-containers       : Stop the dev environment"
	@echo "   make kill-containers       : Stop and remove all containers"
	@echo "   make composer-install      : Install composer dependencies"

# Typing 'make setup-php81' will start the dev environment with PHP 8.1
setup-php81: --prep-docker-compose-file stop-containers --prep-dockerfile-php81 start-containers --remove-packages composer-install

# Typing 'make setup-php82' will start the dev environment with PHP 8.2
setup-php82: --prep-docker-compose-file stop-containers --prep-dockerfile-php82 start-containers --remove-packages composer-install

# Typing 'make setup-php83' will start the dev environment with PHP 8.3
setup-php83: --prep-docker-compose-file stop-containers --prep-dockerfile-php83 start-containers --remove-packages composer-install

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

# Copy Dockerfile for PHP 8.1
--prep-dockerfile-php81: --remove-dockerfile
	cp "./.docker/Dockerfile.php81" "./.docker/Dockerfile"

# Copy Dockerfile for PHP 8.2
--prep-dockerfile-php82: --remove-dockerfile
	cp "./.docker/Dockerfile.php82" "./.docker/Dockerfile"

# Copy Dockerfile for PHP 8.3
--prep-dockerfile-php83: --remove-dockerfile
	cp "./.docker/Dockerfile.php83" "./.docker/Dockerfile"

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
