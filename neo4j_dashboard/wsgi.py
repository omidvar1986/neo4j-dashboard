import os
import logging
from django.core.wsgi import get_wsgi_application

logger = logging.getLogger('dashboard')

# Neo4j driver setup
from neo4j import GraphDatabase

def check_neo4j_connection():
    uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
    user = os.getenv('NEO4J_USER', 'neo4j')
    password = os.getenv('NEO4J_PASSWORD', 'Milad1986')
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        logger.info("Successfully connected to Neo4j at %s", uri)
        driver.close()
    except Exception as e:
        logger.warning("Failed to connect to Neo4j at %s: %s", uri, str(e))
        logger.warning("Neo4j connection failed, but continuing startup...")
        # Don't raise the exception, just log it as a warning

# Check connection on startup
check_neo4j_connection()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'neo4j_dashboard.settings')

application = get_wsgi_application()