#!/bin/bash

# Neo4j Dashboard VM Deployment Script
# This script automates the deployment process on a VM

set -e

echo "🚀 Neo4j Dashboard VM Deployment Script"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VM_IP="${VM_IP:-87.247.174.71}"
VM_USER="${VM_USER:-miladomidvar}"
SSH_KEY="${SSH_KEY:-./deployment_ssh_key}"
PROJECT_DIR="${PROJECT_DIR:-~/neo4j-dashboard}"

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${GREEN}ℹ️  $1${NC}"
}

# Check if SSH key exists
if [ ! -f "$SSH_KEY" ]; then
    print_error "SSH key not found: $SSH_KEY"
    exit 1
fi

# Set correct permissions for SSH key
chmod 600 "$SSH_KEY"

echo "📋 Configuration:"
echo "   VM IP: $VM_IP"
echo "   VM User: $VM_USER"
echo "   SSH Key: $SSH_KEY"
echo "   Project Directory: $PROJECT_DIR"
echo ""

# Function to run command on VM
run_on_vm() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$VM_USER@$VM_IP" "$1"
}

# Function to copy file to VM
copy_to_vm() {
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$1" "$VM_USER@$VM_IP:$2"
}

print_info "Step 1: Testing SSH connection..."
if run_on_vm "echo 'Connection successful'"; then
    print_success "SSH connection successful"
else
    print_error "Failed to connect to VM. Please check your SSH key and VM IP."
    exit 1
fi

print_info "Step 2: Checking prerequisites on VM..."
run_on_vm "
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo 'Docker not found. Please install Docker first.'
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo 'Docker Compose not found. Please install Docker Compose first.'
        exit 1
    fi
    
    # Check Git
    if ! command -v git &> /dev/null; then
        echo 'Git not found. Installing Git...'
        sudo apt-get update && sudo apt-get install -y git
    fi
    
    echo 'All prerequisites are installed.'
"

if [ $? -eq 0 ]; then
    print_success "Prerequisites check passed"
else
    print_error "Prerequisites check failed"
    exit 1
fi

print_info "Step 3: Setting up project directory on VM..."
run_on_vm "
    mkdir -p ~/neo4j-dashboard
    cd ~/neo4j-dashboard
    
    # Check if it's a git repository
    if [ -d .git ]; then
        echo 'Repository exists. Pulling latest changes...'
        git pull
    else
        echo 'Not a git repository. Please clone your repository manually:'
        echo '  git clone YOUR_REPO_URL ~/neo4j-dashboard'
        exit 1
    fi
"

print_info "Step 4: Creating required directories..."
run_on_vm "
    cd ~/neo4j-dashboard
    mkdir -p logs staticfiles wiremock_mappings
    chmod -R 755 logs staticfiles wiremock_mappings
"
print_success "Directories created"

print_info "Step 5: Starting Docker services..."
run_on_vm "
    cd ~/neo4j-dashboard
    
    # Stop existing containers if any
    docker-compose down 2>/dev/null || true
    
    # Start services
    docker-compose up -d
    
    # Wait a bit for services to start
    sleep 10
    
    # Show container status
    docker-compose ps
"

print_info "Step 6: Waiting for services to be ready..."
run_on_vm "
    cd ~/neo4j-dashboard
    
    # Wait for PostgreSQL
    echo 'Waiting for PostgreSQL...'
    timeout=60
    counter=0
    while ! docker-compose exec -T postgres pg_isready -U neo4j_dashboard_user > /dev/null 2>&1; do
        sleep 2
        counter=\$((counter + 2))
        if [ \$counter -ge \$timeout ]; then
            echo 'PostgreSQL did not start in time'
            exit 1
        fi
    done
    echo 'PostgreSQL is ready'
    
    # Wait for Neo4j
    echo 'Waiting for Neo4j...'
    counter=0
    while ! nc -z localhost 7687 2>/dev/null; do
        sleep 2
        counter=\$((counter + 2))
        if [ \$counter -ge \$timeout ]; then
            echo 'Neo4j did not start in time'
            exit 1
        fi
    done
    echo 'Neo4j is ready'
"

print_info "Step 7: Running database migrations..."
run_on_vm "
    cd ~/neo4j-dashboard
    docker-compose exec -T web python manage.py migrate --noinput
"
print_success "Migrations completed"

print_info "Step 8: Collecting static files..."
run_on_vm "
    cd ~/neo4j-dashboard
    docker-compose exec -T web python manage.py collectstatic --noinput
"
print_success "Static files collected"

print_info "Step 9: Checking service status..."
run_on_vm "
    cd ~/neo4j-dashboard
    docker-compose ps
    echo ''
    echo 'Service URLs:'
    echo '  Web App: http://$VM_IP:8000'
    echo '  Neo4j Browser: http://$VM_IP:7474'
    echo '  WireMock: http://$VM_IP:8081'
"

echo ""
print_success "Deployment completed!"
echo ""
echo "📝 Next steps:"
echo "   1. Access your application at: http://$VM_IP:8000"
echo "   2. Check logs: ssh -i $SSH_KEY $VM_USER@$VM_IP 'cd ~/neo4j-dashboard && docker-compose logs -f'"
echo "   3. Create superuser: ssh -i $SSH_KEY $VM_USER@$VM_IP 'cd ~/neo4j-dashboard && docker-compose exec web python manage.py createsuperuser'"
echo ""
print_warning "Remember to:"
echo "   - Update ALLOWED_HOSTS in docker-compose.yml with your VM IP"
echo "   - Change default passwords"
echo "   - Configure firewall rules if needed"
echo "   - Set up SSL/HTTPS for production"
