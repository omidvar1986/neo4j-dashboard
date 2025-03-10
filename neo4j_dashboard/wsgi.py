import os
import logging
from django.core.wsgi import get_wsgi_application

logger = logging.getLogger('dashboard')

# Neo4j driver setup
from neo4j import GraphDatabase

def check_neo4j_connection():
    uri = os.getenv('NEO4J_URI', 'bolt://neo4j:7687')
    user = os.getenv('NEO4J_USER', 'neo4j')
    password = os.getenv('NEO4J_PASSWORD', 'password')
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        logger.info("Successfully connected to Neo4j at %s", uri)
        driver.close()
    except Exception as e:
        logger.error("Failed to connect to Neo4j at %s: %s", uri, str(e))
        raise

# Check connection on startup
check_neo4j_connection()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'neo4j_dashboard.settings')

application = get_wsgi_application()