#!/bin/bash
set -e

# Apply database migrations
echo "Applying database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Start Gunicorn
echo "Starting Gunicorn..."
exec gunicorn neo4j_dashboard.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --log-level DEBUG \
    --access-logfile - \
    --error-logfile -