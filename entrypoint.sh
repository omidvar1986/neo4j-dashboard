#!/bin/bash

# Collect static files
python manage.py collectstatic --noinput

# Apply migrations
python manage.py migrate

# Start Gunicorn
exec gunicorn --bind 0.0.0.0:8000 --workers 3 --log-file /app/logs/gunicorn.log neo4j_dashboard.wsgi:application