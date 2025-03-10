#!/bin/bash

# Collect static files
python manage.py collectstatic --noinput

# Apply migrations
python manage.py migrate

# Start Gunicorn with logs to stdout
exec gunicorn --bind 0.0.0.0:8000 --workers 3 --log-level DEBUG --access-logfile - --error-logfile - neo4j_dashboard.wsgi:application