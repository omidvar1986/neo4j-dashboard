#!/bin/bash

echo "⚡ Starting Neo4j Dashboard (quick mode)..."
echo "   This assumes you've already run ./run_local_setup.sh at least once."
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
export SECRET_KEY='django-insecure-sx42i2cydw$405*%s0e_*rwr@t&ixl_6h53*dr0c9+#itt^z6y'

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

echo "✅ Required containers are running."
echo ""

# Ensure virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found."
    echo "   Please run ./run_local_setup.sh first to install dependencies."
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
