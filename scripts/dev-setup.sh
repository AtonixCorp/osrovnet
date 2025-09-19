#!/bin/bash

# Osrovnet Development Environment Setup Script
# AtonixCorp Network Security Platform

set -e

echo "🔒 Osrovnet Development Environment Setup"
echo "=========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if Python virtual environment exists
check_python_env() {
    if [ ! -d ".venv" ]; then
        print_status "Creating Python virtual environment..."
        python3 -m venv .venv
    fi
    
    print_status "Activating Python virtual environment..."
    source .venv/bin/activate
    
    print_status "Installing Python dependencies..."
    cd backend && pip install -r requirements.txt && cd ..
    
    print_success "Python environment ready"
}

# Check if Node.js dependencies are installed
check_node_env() {
    if [ ! -d "frontend/node_modules" ]; then
        print_status "Installing Node.js dependencies..."
        cd frontend && npm install && cd ..
    fi
    
    print_success "Node.js environment ready"
}

# Set up database
setup_database() {
    print_status "Setting up database..."
    source .venv/bin/activate
    cd backend
    python manage.py makemigrations
    python manage.py migrate
    cd ..
    print_success "Database setup complete"
}

# Create superuser
create_superuser() {
    print_status "Creating Django superuser..."
    source .venv/bin/activate
    cd backend
    echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_superuser('admin', 'admin@osrovnet.com', 'admin123') if not User.objects.filter(username='admin').exists() else None" | python manage.py shell
    cd ..
    print_success "Superuser created (username: admin, password: admin123)"
}

# Start development servers
start_dev_servers() {
    print_status "Starting development servers..."
    
    # Start backend in background
    print_status "Starting Django backend on http://localhost:8000"
    source .venv/bin/activate
    cd backend && python manage.py runserver 8000 &
    BACKEND_PID=$!
    cd ..
    
    # Wait a moment for backend to start
    sleep 3
    
    # Start frontend in background
    print_status "Starting React frontend on http://localhost:3000"
    cd frontend && npm start &
    FRONTEND_PID=$!
    cd ..
    
    print_success "Development servers started!"
    print_status "Backend: http://localhost:8000"
    print_status "Frontend: http://localhost:3000"
    print_status "Admin Panel: http://localhost:8000/admin"
    
    # Handle cleanup on script exit
    trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
    
    print_warning "Press Ctrl+C to stop all servers"
    wait
}

# Main setup process
main() {
    print_status "Starting Osrovnet development setup..."
    
    # Check dependencies
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi
    
    if ! command -v node &> /dev/null; then
        print_error "Node.js is required but not installed"
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        print_error "npm is required but not installed"
        exit 1
    fi
    
    # Setup environments
    check_python_env
    check_node_env
    setup_database
    create_superuser
    
    print_success "🚀 Osrovnet development environment is ready!"
    
    # Ask if user wants to start dev servers
    echo ""
    read -p "Do you want to start the development servers now? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        start_dev_servers
    else
        print_status "To start servers later, run:"
        print_status "Backend: cd backend && source ../.venv/bin/activate && python manage.py runserver"
        print_status "Frontend: cd frontend && npm start"
    fi
}

# Run main function
main "$@"