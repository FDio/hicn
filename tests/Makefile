# Use when building for the first time,
# then `make test` forces a rebuild if local changes
build:
	DOCKERFILE=Dockerfile.dev BUILD_SOFTWARE=1 \
		docker-compose -f build.yml up --force-recreate --remove-orphans

# Rebuild from scratch (to avoid cmake cache)
rebuild:
	DOCKERFILE=Dockerfile.dev BUILD_SOFTWARE=1 \
		REBUILD=1 \
		docker-compose -f build.yml up --force-recreate --remove-orphans

# Force base image creation from scratch
rebase:
	DOCKERFILE=Dockerfile.dev \
		docker-compose -f build.yml build --pull --no-cache

# If local changes, hicn is re-built
test:
	docker-compose -f 1-node.yml up --force-recreate --remove-orphans -d

log:
	docker exec forwarder tail -f -n +1 /tmp/lite_client.log

shell:
	docker exec -it forwarder bash

down:
	docker-compose -f 1-node.yml down

functional-ctrl:
	sleep 1  # Wait for the forwarder to be ready
	bash -x config.sh ctrl listeners
	bash -x config.sh ctrl connections
	bash -x config.sh ctrl routes

functional-ping-manifest:
	bash config.sh ping manifest
functional-ping-signature:
	bash config.sh ping signature
functional-ping-timeout:
	bash config.sh ping timeout