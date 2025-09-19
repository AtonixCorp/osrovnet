#!/bin/bash

# Osrovnet Production Deployment Script
# AtonixCorp Network Security Platform

set -e

echo "🔒 Osrovnet Production Deployment"
echo "=================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is required but not installed"
        exit 1
    fi
    
    print_success "Docker environment verified"
}

# Build and deploy
deploy() {
    print_status "Building frontend application..."
    pushd frontend > /dev/null
    npm ci --silent
    npm run build --silent
    popd > /dev/null

    print_status "Building Osrovnet containers..."
    docker-compose -f docker-compose.yml build
    
    print_status "Starting Osrovnet services..."
    docker-compose -f docker-compose.yml up -d
    
    print_status "Running database migrations..."
    docker-compose -f docker-compose.yml exec backend python manage.py migrate
    
    print_status "Collecting static files..."
    docker-compose -f docker-compose.yml exec backend python manage.py collectstatic --noinput
    
    print_success "🚀 Osrovnet deployed successfully!"
    print_status "Frontend: http://localhost:3000"
    print_status "Backend API: http://localhost:8000"
    print_status "Admin Panel: http://localhost:8000/admin"
}

# Stop deployment
stop() {
    print_status "Stopping Osrovnet services..."
    docker-compose -f docker-compose.yml down
    print_success "Osrovnet services stopped"
}

# Show logs
logs() {
    docker-compose -f docker-compose.yml logs -f
}

# Show status
status() {
    docker-compose -f docker-compose.yml ps
}

# Main function
main() {
    case "${1:-deploy}" in
        "deploy")
            check_docker
            deploy
            ;;
        "stop")
            stop
            ;;
        "logs")
            logs
            ;;
        "status")
            status
            ;;
        *)
            echo "Usage: $0 {deploy|stop|logs|status}"
            echo "  deploy  - Build and deploy Osrovnet (default)"
            echo "  stop    - Stop all services"
            echo "  logs    - Show service logs"
            echo "  status  - Show service status"
            exit 1
            ;;
    esac
}

main "$@"