#!/bin/sh

echo "اجرای migrate..."
python manage.py migrate

echo "جمع‌آوری staticfiles..."
python manage.py collectstatic --noinput

echo "اجرای سرور Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 neo4j_dashboard.wsgi:application