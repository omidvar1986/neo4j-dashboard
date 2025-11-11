#!/bin/bash

echo "🚀 Starting Neo4j Dashboard locally (with Docker databases)..."

# Set environment variables to point to Docker containers
# Using port 5433 to avoid conflict with local PostgreSQL on 5432
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

echo "✅ Environment variables set:"
echo "   PostgreSQL: localhost:5433 (Docker container)"
echo "   Neo4j: localhost:7687"
echo "   MongoDB: localhost:27017"
echo ""

# Check if Docker containers are running
if ! docker ps | grep -q "neo4j_dashboard_postgres"; then
    echo "📦 Starting Docker containers..."
    docker-compose up -d postgres neo4j mongodb
    sleep 3
fi

if ! docker ps | grep -q "neo4j_dashboard_neo4j"; then
    echo "📦 Starting Neo4j container..."
    docker-compose up -d neo4j
    sleep 2
fi

if ! docker ps | grep -q "neo4j_dashboard_mongodb"; then
    echo "📦 Starting MongoDB container..."
    docker-compose up -d mongodb
    sleep 2
fi

# Check if PostgreSQL is on the correct port (5433)
POSTGRES_PORT_CHECK=$(docker port neo4j_dashboard_postgres 2>/dev/null | grep -o "5433" || echo "")
if [ -z "$POSTGRES_PORT_CHECK" ]; then
    echo "⚠️  PostgreSQL container is on wrong port. Restarting with correct port..."
    docker-compose up -d --force-recreate postgres
    sleep 5
fi

echo "✅ Docker containers are running"
echo ""

# Verify and set up PostgreSQL database
echo "🔍 Verifying PostgreSQL setup..."
# Wait a moment for PostgreSQL to be ready
sleep 3

# Check if we can connect as the configured user inside the container
# Since POSTGRES_USER=neo4j_dashboard_user in docker-compose.yml, that user should exist
if docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -c "SELECT 1;" &>/dev/null 2>&1; then
    # User exists, check if database exists
    DB_EXISTS=$(docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -tc "SELECT 1 FROM pg_database WHERE datname='neo_dashboard'" 2>/dev/null | tr -d ' ' || echo "")
    if [ "$DB_EXISTS" != "1" ]; then
        echo "⚠️  Database 'neo_dashboard' not found. Creating..."
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d postgres -c "CREATE DATABASE neo_dashboard;" 2>/dev/null
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d neo_dashboard -c "GRANT ALL PRIVILEGES ON DATABASE neo_dashboard TO neo4j_dashboard_user;" 2>/dev/null
        docker exec neo4j_dashboard_postgres psql -U neo4j_dashboard_user -d neo_dashboard -c "GRANT ALL PRIVILEGES ON SCHEMA public TO neo4j_dashboard_user;" 2>/dev/null
        echo "✅ Database created"
    else
        echo "✅ PostgreSQL is ready"
    fi
    
    # Test connection from host (as Django will connect)
    echo "🔍 Testing connection from host..."
    if python3 -c "import sys; sys.path.insert(0, 'venv/lib/python3.13/site-packages'); import psycopg2; conn = psycopg2.connect(host='${POSTGRES_HOST}', port=${POSTGRES_PORT}, database='neo_dashboard', user='neo4j_dashboard_user', password='Milad1986'); conn.close(); print('✅ Connection test successful')" 2>&1 | grep -q "successful"; then
        echo "✅ Connection from host successful"
    else
        echo "⚠️  Connection test failed. Make sure Docker container is running on port 5433."
    fi
else
    echo "❌ Cannot connect to PostgreSQL as 'neo4j_dashboard_user'"
    echo "   This usually means the container was created with different settings."
    echo ""
    echo "💡 Solution: Recreate the PostgreSQL container:"
    echo "   docker-compose down postgres"
    echo "   docker volume rm neo4j-dashboard_postgres_data  # Remove old data"
    echo "   docker-compose up -d postgres"
    echo ""
    echo "   Or run: docker-compose up -d --force-recreate postgres"
    exit 1
fi
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

# Create or update admin user
echo "👤 Setting up admin user..."
python manage.py shell << 'PYEOF'
from django.contrib.auth import get_user_model
User = get_user_model()
try:
    admin, created = User.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@example.com',
            'role': 3,  # Admin User role
            'is_approved': True,
            'is_staff': True,
            'is_superuser': True,
            'is_active': True
        }
    )
    if created:
        admin.set_password('admin123')
        admin.save()
        print("   ✅ Admin user created (admin/admin123)")
    else:
        # Update existing admin user to ensure correct settings
        admin.set_password('admin123')
        admin.email = 'admin@example.com'
        admin.role = 3
        admin.is_approved = True
        admin.is_staff = True
        admin.is_superuser = True
        admin.is_active = True
        admin.save()
        print("   ✅ Admin user updated (admin/admin123)")
except Exception as e:
    print(f"   ⚠️  Error setting up admin user: {e}")
    print("   You can create one manually with: python manage.py createsuperuser")
PYEOF

echo ""
echo "🎯 Starting Django development server..."
echo "   Access your application at: http://localhost:8000"
echo "   Default credentials: admin/admin123"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python manage.py runserver
