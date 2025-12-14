#!/bin/bash
set -e

echo "🚀 Starting Neo4j Dashboard..."

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
while ! nc -z postgres 5432; do
  echo "PostgreSQL is unavailable - sleeping"
  sleep 1
done
echo "✅ PostgreSQL is up - continuing"

# Wait for Neo4j to be ready
echo "⏳ Waiting for Neo4j to be ready..."
while ! nc -z neo4j 7687; do
  echo "Neo4j is unavailable - sleeping"
  sleep 1
done
echo "✅ Neo4j is up - continuing"

# Apply database migrations
echo "🔄 Applying database migrations..."
python manage.py migrate

# Collect static files
echo "📁 Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser if it doesn't exist
echo "👤 Checking for superuser..."
python manage.py shell -c "
from dashboard.models import user
if not user.objects.filter(username='admin').exists():
    admin_user = user.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    admin_user.role = 3  # Admin role
    admin_user.is_approved = True
    admin_user.save()
    print('✅ Superuser created: admin/admin123')
else:
    print('✅ Superuser already exists')
"

# Start Gunicorn
echo "🌐 Starting Django application..."
exec gunicorn \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --log-level INFO \
    --access-logfile - \
    --error-logfile - \
    neo4j_dashboard.wsgi:application