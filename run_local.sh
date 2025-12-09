#!/bin/bash

echo "⚡ Starting Neo4j Dashboard (quick mode)..."
echo "   This assumes you've already run ./setup_all.sh at least once."
echo ""

# Environment variables (same as setup script)
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5433
export POSTGRES_NAME=neo_dashboard
export POSTGRES_USER=neo4j_dashboard_user
export POSTGRES_PASSWORD=Milad1986

export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=Milad1986

export MONGODB_HOST=localhost
export MONGODB_PORT=27017
export MONGODB_USER=mongodb_user
export MONGODB_PASSWORD=Milad1986
export MONGODB_DB=testcases_db

export DEBUG=True
export KEYCLOAK_ENABLED=True
export SECRET_KEY='django-insecure-sx42i2cydw$405*%s0e_*rwr@t&ixl_6h53*dr0c9+#itt^z6y'

# Keycloak Configuration for automatic setup
export KEYCLOAK_SERVER_URL=http://localhost:8080
export KEYCLOAK_REALM=neo4j_dashboard
export KEYCLOAK_CLIENT_ID=neo4j_dashboard_client
export KEYCLOAK_CLIENT_SECRET=neo4j_dashboard_secret

echo "✅ Environment variables set."
echo ""

# Lightweight container check (start if missing)
ensure_container() {
    local name=$1
    local service=$2
    if ! docker ps | grep -q "$name"; then
        echo "📦 Starting $service container..."
        docker-compose up -d "$service"
        sleep 2
    fi
}

ensure_container "neo4j_dashboard_postgres" "postgres"
ensure_container "neo4j_dashboard_neo4j" "neo4j"
ensure_container "neo4j_dashboard_mongodb" "mongodb"
ensure_container "neo4j_dashboard_wiremock" "wiremock"

# Start Keycloak if enabled
if [ "$KEYCLOAK_ENABLED" = "True" ]; then
    echo "🔐 Keycloak is enabled. Checking containers..."
    if ! docker ps | grep -q "neo4j_dashboard_keycloak"; then
        echo "📦 Starting Keycloak containers..."
        docker-compose --profile keycloak up -d keycloak keycloak-db
        echo "   Waiting for Keycloak to start..."
        # We don't wait indefinitely here, just give it a kick
    fi
fi

echo "✅ Required containers are running."
echo ""

# Ensure virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found."
    echo "   Please run ./setup_all.sh first to install dependencies."
    exit 1
fi

echo "🔧 Activating virtual environment..."
source venv/bin/activate

echo ""
echo "🎯 Starting Django development server..."
echo "   Access: http://localhost:8000"
echo "   Press Ctrl+C to stop."
echo ""

python manage.py runserver
