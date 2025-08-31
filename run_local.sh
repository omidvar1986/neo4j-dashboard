#!/bin/bash

echo "🚀 Starting Neo4j Dashboard locally (with Docker databases)..."

# Set environment variables to point to Docker containers
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_NAME=neo_dashboard
export POSTGRES_USER=neo4j_dashboard_user
export POSTGRES_PASSWORD=Milad1986

export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=Milad1986

export DEBUG=True
export SECRET_KEY=django-insecure-sx42i2cydw$405*%s0e_*rwr@t&ixl_6h53*dr0c9+#itt^z6y

echo "✅ Environment variables set:"
echo "   PostgreSQL: localhost:5432"
echo "   Neo4j: localhost:7687"
echo ""

# Check if Docker containers are running
if ! docker ps | grep -q "neo4j_dashboard_postgres"; then
    echo "❌ PostgreSQL container is not running!"
    echo "   Please start Docker services first: docker-compose up -d"
    exit 1
fi

if ! docker ps | grep -q "neo4j_dashboard_neo4j"; then
    echo "❌ Neo4j container is not running!"
    echo "   Please start Docker services first: docker-compose up -d"
    exit 1
fi

echo "✅ Docker containers are running"
echo ""

# Install dependencies if needed
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

echo "🔧 Activating virtual environment..."
source venv/bin/activate

echo "📥 Installing dependencies..."
pip install -r requirements.txt

echo "🗄️ Running migrations..."
python manage.py migrate

echo "🎯 Starting Django development server..."
echo "   Access your application at: http://localhost:8000"
echo "   Default credentials: admin/admin123"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python manage.py runserver
