# neo4j_dashboard/wsgi.py
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'neo4j_dashboard.settings')
application = get_wsgi_application()