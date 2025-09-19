# Makefile for building and running the Osrovnet project with nerdctl (containerd)
# Assumes containerd+nerdctl is installed and configured on the host.

.PHONY: help nerdctl-version build-backend build-frontend build-all up down logs ps prune

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  nerdctl-version   - show nerdctl and containerd versions"
	@echo "  build-backend     - build the backend Docker image"
	@echo "  build-frontend    - build the frontend Docker image"
	@echo "  build-all         - build both backend and frontend images"
	@echo "  up                - start services via nerdctl compose (dev)"
	@echo "  down              - stop and remove compose services"
	@echo "  logs              - tail service logs (pass SERVICE=name)"
	@echo "  ps                - show running containers (nerdctl ps)"
 	@echo "  prune             - remove dangling images and stopped containers"
 	@echo "  build-backend-pqc - build backend image with liboqs/python-oqs included (may take long)"

# Use the project's docker-compose files by default
COMPOSE_FILE ?= docker-compose.dev.yml

# Image names — change these if you use a registry
BACKEND_IMAGE = osrovnet-backend:local
FRONTEND_IMAGE = osrovnet-frontend:local

# Build backend image (uses dockerfile in ./docker/Dockerfile.backend)
build-backend:
	@echo "Building backend image: $(BACKEND_IMAGE)"
	# Use the backend directory as the build context so Dockerfile can COPY requirements.txt and project files
	nerdctl build -f docker/Dockerfile.backend -t $(BACKEND_IMAGE) ./backend

# Build backend image with PQC libs included (liboqs + python-oqs)
build-backend-pqc:
	@echo "Building backend image with PQC: $(BACKEND_IMAGE)-pqc"
	# set build-arg PQC=true so Dockerfile.backend installs liboqs and python-oqs
	nerdctl build --build-arg PQC=true -f docker/Dockerfile.backend -t $(BACKEND_IMAGE)-pqc ./backend

# Build frontend image (uses dockerfile in ./docker/Dockerfile.frontend)
build-frontend:
	@echo "Building frontend image: $(FRONTEND_IMAGE)"
	cd frontend && nerdctl build -f ../docker/Dockerfile.frontend -t $(FRONTEND_IMAGE) .

build-all: build-backend build-frontend

# Build a single root image that bundles frontend + backend (convenience)
build-root:
	@echo "Building root image: osrovnet-root:local"
	nerdctl build -f Dockerfile.root -t osrovnet-root:local .

# Terminal web shell image (Debian + ttyd) - useful for iOS/Debian web terminal access
build-terminal:
	@echo "Building terminal image: osrovnet-terminal:local"
	nerdctl build -f docker/terminal/Dockerfile -t osrovnet-terminal:local .

run-terminal:
	@echo "Running terminal (mapped to host port 7681)"
	nerdctl run --rm -p 7681:7681 --name osrovnet-terminal osrovnet-terminal:local

clean-terminal:
	@echo "Removing terminal image if exists"
	-nerdctl rmi osrovnet-terminal:local || true

# Compose up (detached)
up:
	nerdctl compose -f $(COMPOSE_FILE) up -d --remove-orphans

# Compose down
down:
	nerdctl compose -f $(COMPOSE_FILE) down --rmi local

logs:
	ifndef SERVICE
		$(error SERVICE variable is required, e.g. make logs SERVICE=backend)
	endif
	nerdctl compose -f $(COMPOSE_FILE) logs -f $(SERVICE)

ps:
	nerdctl ps -a

prune:
	nerdctl image prune -f || true
	nerdctl container prune -f || true

nerdctl-version:
	nerdctl --version || true
	containerd --version || true
